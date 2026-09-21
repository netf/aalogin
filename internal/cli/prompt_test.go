package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPromptNeverConsumesNoninteractiveInput(t *testing.T) {
	for _, noPrompt := range []bool{false, true} {
		t.Run(fmt.Sprint(noPrompt), func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := io.WriteString(w, "not-consumed\n"); err != nil {
				t.Fatal(err)
			}
			w.Close()
			var out bytes.Buffer
			p := Prompt{In: r, Out: &out, NoPrompt: noPrompt}
			_, err = p.Read(context.Background(), "Password", "secret-default", true)
			if err == nil || (noPrompt && !errors.Is(err, ErrInteractionRequired)) {
				t.Fatalf("unexpected prompt error: %v", err)
			}
			remaining, err := io.ReadAll(r)
			if err != nil || string(remaining) != "not-consumed\n" || out.Len() != 0 {
				t.Fatalf("prompt consumed input or produced output: %q, %q, %v", remaining, out.String(), err)
			}
		})
	}
}

func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "ptmx")
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

type promptOutput struct {
	bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (w *promptOutput) Write(b []byte) (int, error) {
	n, err := w.Buffer.Write(b)
	w.once.Do(func() { close(w.ready) })
	return n, err
}

type promptResult struct {
	value string
	err   error
}

func startPrompt(ctx context.Context, in *os.File, secret bool, defaultValue string) (*promptOutput, <-chan promptResult) {
	out := &promptOutput{ready: make(chan struct{})}
	result := make(chan promptResult, 1)
	go func() {
		p := Prompt{In: in, Out: out}
		value, err := p.Read(ctx, "Answer", defaultValue, secret)
		result <- promptResult{value, err}
	}()
	return out, result
}

func awaitPrompt(t *testing.T, out *promptOutput, result <-chan promptResult) {
	t.Helper()
	select {
	case <-out.ready:
	case r := <-result:
		t.Fatalf("prompt ended before input: %v", r.err)
	case <-time.After(3 * time.Second):
		t.Fatal("prompt failed to start")
	}
}

func awaitResult(t *testing.T, result <-chan promptResult) promptResult {
	t.Helper()
	select {
	case r := <-result:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("prompt did not finish")
		return promptResult{}
	}
}

func TestHiddenPromptCancellationRestoresTerminal(t *testing.T) {
	master, slave := openPTY(t)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, result := startPrompt(ctx, slave, true, "never-display-default")
	awaitPrompt(t, out, result)
	during, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || during.Lflag&(unix.ECHO|unix.ECHONL) != 0 {
		t.Fatalf("secret input is not hidden: %v", err)
	}
	if _, err := io.WriteString(master, "discard-partial-secret"); err != nil {
		t.Fatal(err)
	}
	cancel()
	r := awaitResult(t, result)
	if !errors.Is(r.err, context.Canceled) || r.value != "" {
		t.Fatalf("cancelled prompt = %#v", r)
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal state not restored: before=%+v after=%+v err=%v", before, after, err)
	}
	if strings.Contains(out.String(), "never-display-default") || strings.Contains(out.String(), "discard-partial-secret") {
		t.Fatal("secret appeared in prompt output")
	}
	// A subsequent reader must not compete with an abandoned cancellation
	// goroutine, and the partial secret must not become the next answer.
	nextCtx, nextCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer nextCancel()
	nextOut, nextResult := startPrompt(nextCtx, slave, true, "")
	awaitPrompt(t, nextOut, nextResult)
	if _, err := io.WriteString(master, "next-answer\n"); err != nil {
		t.Fatal(err)
	}
	next := awaitResult(t, nextResult)
	if next.err != nil || next.value != "next-answer" {
		t.Fatalf("next prompt = %#v", next)
	}
}

func TestTerminalEOFIsNotDefaultAcceptance(t *testing.T) {
	master, slave := openPTY(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, result := startPrompt(ctx, slave, true, "must-not-accept")
	awaitPrompt(t, out, result)
	if _, err := master.Write([]byte{4}); err != nil {
		t.Fatal(err)
	}
	r := awaitResult(t, result)
	if !errors.Is(r.err, io.EOF) || r.value != "" {
		t.Fatalf("EOF prompt = %#v", r)
	}
}

func TestTerminalAnswers(t *testing.T) {
	for _, tc := range []struct {
		name, input, defaultValue, want string
		secret                          bool
	}{
		{"visible", "  value  \n", "", "value", false},
		{"secret", "  secret  \n", "", "  secret  ", true},
		{"default", "\n", "default-value", "default-value", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			master, slave := openPTY(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			out, result := startPrompt(ctx, slave, tc.secret, tc.defaultValue)
			awaitPrompt(t, out, result)
			if _, err := io.WriteString(master, tc.input); err != nil {
				t.Fatal(err)
			}
			r := awaitResult(t, result)
			if r.err != nil || r.value != tc.want {
				t.Fatalf("prompt = %#v, want %q", r, tc.want)
			}
		})
	}
}
