package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

var ErrInteractionRequired = errors.New("interaction required; rerun without --no-prompt")

type Prompt struct {
	In       *os.File
	Out      io.Writer
	NoPrompt bool
}

// Read accepts terminal input only. A blank answer retains defaultValue; secret
// defaults are never printed. NoPrompt rejects even a prompt with a default.
func (p *Prompt) Read(ctx context.Context, label, defaultValue string, secret bool) (answer string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if p.NoPrompt {
		return "", ErrInteractionRequired
	}
	in, out := p.In, p.Out
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stderr
	}
	if !term.IsTerminal(int(in.Fd())) {
		return "", errors.New("interaction required; stdin must be a terminal (or supply values and use --no-prompt)")
	}
	// Reopen the terminal to obtain independent nonblocking file status flags.
	// Dup would change the caller's stdin flags as well. ReadPassword's blocking
	// syscall cannot be cancelled safely; canonical polling gives the same line
	// editing and hidden-input behavior with no abandoned reader goroutine.
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", in.Fd()), unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("open terminal input: %w", err)
	}
	defer unix.Close(fd)
	state, err := term.GetState(fd)
	if err != nil {
		return "", fmt.Errorf("read terminal state: %w", err)
	}
	settings, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", fmt.Errorf("read terminal settings: %w", err)
	}
	settings.Lflag |= unix.ICANON | unix.ISIG
	settings.Iflag |= unix.ICRNL
	if secret {
		settings.Lflag &^= unix.ECHO | unix.ECHONL
	} else {
		settings.Lflag |= unix.ECHO
	}
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, settings); err != nil {
		return "", fmt.Errorf("set terminal input mode: %w", err)
	}
	defer func() {
		if err != nil {
			// Discard partially typed secrets on EOF, cancellation, or failure.
			_ = unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
		}
		if restoreErr := term.Restore(fd, state); restoreErr != nil {
			answer = ""
			err = errors.Join(err, fmt.Errorf("restore terminal state: %w", restoreErr))
		}
		if secret {
			_, printErr := fmt.Fprintln(out)
			if printErr != nil {
				answer = ""
				err = errors.Join(err, printErr)
			}
		}
	}()
	text := safePromptText(label)
	if !secret && defaultValue != "" {
		text += " [" + safePromptText(defaultValue) + "]"
	}
	if _, err := fmt.Fprint(out, text+": "); err != nil {
		return "", err
	}
	line, err := readTerminalLine(ctx, fd)
	if err != nil {
		return "", err
	}
	defer clear(line)
	answer = strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	if !secret {
		answer = strings.TrimSpace(answer)
	}
	if answer == "" {
		answer = defaultValue
	}
	return answer, nil
}

func readTerminalLine(ctx context.Context, fd int) ([]byte, error) {
	var line []byte
	var buffer [4096]byte
	defer clear(buffer[:])
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if err := ctx.Err(); err != nil {
			clear(line)
			return nil, err
		}
		_, err := unix.Poll(poll, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			clear(line)
			return nil, fmt.Errorf("poll terminal input: %w", err)
		}
		if poll[0].Revents == 0 {
			continue
		}
		n, err := unix.Read(fd, buffer[:])
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			clear(line)
			return nil, fmt.Errorf("read terminal input: %w", err)
		}
		if n == 0 {
			clear(line)
			return nil, io.EOF
		}
		line = append(line, buffer[:n]...)
		if err := ctx.Err(); err != nil {
			clear(line)
			return nil, err
		}
		if len(line) > 64*1024 {
			clear(line)
			return nil, errors.New("terminal input is too long")
		}
		if line[len(line)-1] == '\n' {
			return line, nil
		}
	}
}

func safePromptText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			continue
		}
		if b.Len() >= 512 {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
