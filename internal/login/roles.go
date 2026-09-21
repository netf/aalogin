package login

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"aalogin/internal/cli"
	"aalogin/internal/saml"

	"golang.org/x/term"
)

func roleLabel(role saml.Role) string {
	parts := strings.SplitN(role.RoleARN, ":", 6)
	if len(parts) != 6 {
		return role.RoleARN
	}
	return fmt.Sprintf("%s (%s, %s)", strings.TrimPrefix(parts[5], "role/"), parts[4], parts[1])
}

func selectRole(ctx context.Context, roles []saml.Role, def string, prompt *cli.Prompt) (saml.Role, error) {
	if err := ctx.Err(); err != nil {
		return saml.Role{}, err
	}
	return saml.SelectRole(roles, def, prompt.NoPrompt, func(roles []saml.Role) (int, error) {
		in, out := prompt.In, prompt.Out
		if in == nil {
			in = os.Stdin
		}
		if out == nil {
			out = os.Stderr
		}
		if terminal, ok := out.(*os.File); ok && term.IsTerminal(int(in.Fd())) && term.IsTerminal(int(terminal.Fd())) {
			if path, err := exec.LookPath("fzf"); err == nil {
				return fuzzyRole(ctx, path, roles, terminal)
			}
		}
		for i, role := range roles {
			fmt.Fprintf(out, "%d: %s\n", i+1, roleLabel(role))
		}
		text, err := prompt.Read(ctx, "Role number", "", false)
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(text)
		if err != nil {
			return 0, errors.New("invalid role number")
		}
		return n - 1, nil
	})
}

func fuzzyRole(ctx context.Context, path string, roles []saml.Role, terminal *os.File) (choice int, err error) {
	state, err := term.GetState(int(terminal.Fd()))
	if err != nil {
		return 0, fmt.Errorf("read terminal state: %w", err)
	}
	// CommandContext may kill fzf before it can restore canonical input and echo.
	defer func() {
		if restoreErr := term.Restore(int(terminal.Fd()), state); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore terminal state: %w", restoreErr))
		}
	}()
	rows := make([]string, len(roles))
	for i, role := range roles {
		rows[i] = strconv.Itoa(i) + "\t" + roleLabel(role)
	}
	cmd := exec.CommandContext(ctx, path, "--height=~12", "--layout=reverse", "--border=rounded",
		"--no-multi", "--delimiter=\t", "--with-nth=2..", "--prompt=Role > ",
		"--header=Type to search · Up/Down navigate · Enter select · Esc cancel")
	// User fzf defaults can enable multi-select, auto-selection, or shell bindings.
	// Keep this authentication decision explicitly interactive and single-select.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "FZF_DEFAULT_OPTS" && key != "FZF_DEFAULT_OPTS_FILE" && key != "FZF_DEFAULT_COMMAND" {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Stdin = strings.NewReader(strings.Join(rows, "\n") + "\n")
	var selected bytes.Buffer
	cmd.Stdout = &selected
	cmd.Stderr = terminal
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && (exit.ExitCode() == 130 || exit.ExitCode() == 1) {
			return 0, errors.New("role selection canceled")
		}
		return 0, fmt.Errorf("fzf role selection failed: %w", err)
	}
	line := strings.TrimSuffix(selected.String(), "\n")
	index, _, _ := strings.Cut(line, "\t")
	n, err := strconv.Atoi(index)
	if err != nil || n < 0 || n >= len(rows) || line != rows[n] {
		return 0, errors.New("fzf returned an invalid role selection")
	}
	return n, nil
}
