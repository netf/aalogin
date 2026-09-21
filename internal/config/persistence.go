package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Update serializes cooperating writers using a sidecar lock, rereads under
// that lock, then atomically replaces only the destination's selected values.
// Existing destination symlinks remain symlinks: the resolved target is updated.
func Update(ctx context.Context, path, sectionName string, values map[string]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSection(sectionName); err != nil {
		return err
	}
	for key, value := range values {
		if key == "" || strings.TrimSpace(key) != key || strings.ContainsAny(key, "=[]\r\n\x00") || strings.HasPrefix(key, "#") || strings.HasPrefix(key, ";") {
			return fmt.Errorf("invalid INI key in section [%s]", sectionName)
		}
		if err := validateValue(value); err != nil {
			return fmt.Errorf("%s: section [%s]: key %s: %w", path, sectionName, key, err)
		}
	}
	if len(values) == 0 {
		return nil
	}
	target, err := resolveDestination(path)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", path, err)
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create parent of %s: %w", path, err)
	}
	lockPath := target + ".aalogin.lock"
	fd, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("open lock for %s: %w", path, err)
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	defer lock.Close()
	if err := lock.Chmod(0600); err != nil {
		return fmt.Errorf("secure lock for %s: %w", path, err)
	}
	if err := acquireLock(ctx, fd); err != nil {
		return fmt.Errorf("lock %s: %w", path, err)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	if err := ctx.Err(); err != nil {
		return err
	}

	doc, err := Load(target)
	if err != nil {
		return err
	}
	updated, err := doc.patch(sectionName, values)
	if err != nil {
		return err
	}
	return atomicReplace(ctx, target, updated)
}

func acquireLock(ctx context.Context, fd int) error {
	var ticker *time.Ticker
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		if ticker == nil {
			ticker = time.NewTicker(50 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// resolveDestination also follows dangling final symlinks and symlinked
// parents. Treating EvalSymlinks' ENOENT as an ordinary missing file would
// otherwise replace a dangling symlink instead of creating its target.
func resolveDestination(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty file path")
	}
	current := string(filepath.Separator)
	if !filepath.IsAbs(path) {
		var err error
		current, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	pending := strings.Split(path, string(filepath.Separator))
	links := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(current)
			continue
		}
		candidate := filepath.Join(current, part)
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			current = candidate
			continue
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			current = candidate
			continue
		}
		links++
		if links > 40 {
			return "", fmt.Errorf("too many symbolic links")
		}
		target, err := os.Readlink(candidate)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			current = string(filepath.Separator)
		}
		pending = append(strings.Split(target, string(filepath.Separator)), pending...)
	}
	return current, nil
}

type replacement struct {
	start int
	end   int
	value string
}

func (d *Document) patch(sectionName string, values map[string]string) ([]byte, error) {
	sec, err := d.findSection(sectionName)
	if err != nil {
		return nil, err
	}
	var replacements []replacement
	found := make(map[string]bool, len(values))
	if sec != nil {
		entries, err := d.entries(*sec, values)
		if err != nil {
			return nil, err
		}
		for _, item := range entries {
			value, replace := values[item.key]
			if !replace {
				continue
			}
			if item.nested {
				return nil, fmt.Errorf("%s: section [%s]: key %s is a nested block, not a scalar", d.path, sectionName, item.key)
			}
			found[item.key] = true
			if item.value == value {
				continue
			}
			replacements = append(replacements, replacement{start: item.valueStart, end: item.valueEnd, value: encodeValue(value)})
		}
	}
	var missing []string
	for key := range values {
		if !found[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		ending := "\n"
		if newline := bytes.IndexByte(d.data, '\n'); newline > 0 && d.data[newline-1] == '\r' {
			ending = "\r\n"
		}
		position := len(d.data)
		if sec != nil {
			position = sec.end
		}
		var addition strings.Builder
		if position > 0 && d.data[position-1] != '\n' {
			addition.WriteString(ending)
		}
		if sec == nil {
			addition.WriteString("[" + sectionName + "]" + ending)
		}
		for _, key := range missing {
			addition.WriteString(key + " = " + encodeValue(values[key]) + ending)
		}
		replacements = append(replacements, replacement{start: position, end: position, value: addition.String()})
	}
	sort.SliceStable(replacements, func(i, j int) bool { return replacements[i].start < replacements[j].start })
	var output bytes.Buffer
	output.Grow(len(d.data))
	cursor := 0
	for _, change := range replacements {
		output.Write(d.data[cursor:change.start])
		output.WriteString(change.value)
		cursor = change.end
	}
	output.Write(d.data[cursor:])
	return output.Bytes(), nil
}

func encodeValue(value string) string {
	// Quotes are only delimiters, not an escape language in shared INI files.
	// An outer pair retains literal whitespace or an existing quote pair.
	if strings.TrimSpace(value) != value || (len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\''))) {
		return "\"" + value + "\""
	}
	return value
}

func atomicReplace(ctx context.Context, path string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open parent of %s: %w", path, err)
	}
	defer dir.Close()
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".aalogin-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("secure temporary file for %s: %w", path, err)
	}
	if n, err := file.Write(data); err != nil {
		return fmt.Errorf("write temporary file for %s: %w", path, err)
	} else if n != len(data) {
		return fmt.Errorf("write temporary file for %s: %w", path, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary file for %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary file for %s: %w", path, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync parent after replacing %s: %w", path, err)
	}
	return nil
}
