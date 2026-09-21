package cli

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestProfilePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, env string
		args      []string
		want      string
	}{
		{"default", "", nil, "default"},
		{"environment", "from-env", nil, "from-env"},
		{"explicit", "from-env", []string{"-p", "selected"}, "selected"},
		{"empty-explicit", "from-env", []string{"--profile="}, "from-env"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AWS_PROFILE", tc.env)
			o, err := Parse(tc.args, io.Discard)
			if err != nil || o.Profile != tc.want {
				t.Fatalf("profile = %q, err = %v; want %q", o.Profile, err, tc.want)
			}
		})
	}
}

func TestRejectInvalidInvocations(t *testing.T) {
	t.Setenv("AWS_PROFILE", "")
	for _, args := range [][]string{
		{"--unknown"}, {"positional"}, {"--", "positional"},
		{"--mode", "browser"}, {"--mode", ""}, {"--timeout", "0"}, {"--timeout=-1s"}, {"--timeout", "tomorrow"},
		{"-c", "-a"}, {"-c", "-f"}, {"-c", "--credential-process"},
		{"--configure", "--duration", "4h"},
		{"--duration", "0"}, {"--duration=-1s"}, {"--duration", "14m59s"},
		{"--duration", "12h1s"}, {"--duration", "15m1ns"}, {"--duration", "tomorrow"},
		{"-p", "selected", "-a"}, {"--profile=", "--all-profiles"},
		{"--credential-process", "-a"}, {"--credential-process", "-m", "gui"}, {"--credential-process", "-m", "debug"},
		{"-p", "bad\n[section]"},
		{"--trusted-login-host", "https://example.com"}, {"--trusted-login-host", "*.example.com"},
		{"--trusted-login-host", "example.com:443"}, {"--trusted-login-host", "example.com/path"},
		{"--trusted-login-host", "example.com,other.example"}, {"--trusted-login-host", "-example.com"},
		{"--trusted-login-host", ""}, {"--trusted-login-host", "example.com\n"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, err := Parse(args, io.Discard); err == nil {
				t.Fatalf("accepted %q", args)
			}
		})
	}
}

func TestDurationOverrideBoundaries(t *testing.T) {
	t.Setenv("AWS_PROFILE", "")
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"", 0},
		{"15m", 15 * time.Minute},
		{"4h", 4 * time.Hour},
		{"90m", 90 * time.Minute},
		{"12h", 12 * time.Hour},
	} {
		t.Run(tc.value, func(t *testing.T) {
			var args []string
			if tc.value != "" {
				args = []string{"--duration", tc.value}
			}
			o, err := Parse(args, io.Discard)
			if err != nil || o.Duration != tc.want {
				t.Fatalf("duration = %v, err = %v; want %v", o.Duration, err, tc.want)
			}
		})
	}
}

func TestCredentialProcessCannotEnablePrompts(t *testing.T) {
	for _, args := range [][]string{
		{"--credential-process"},
		{"--credential-process", "--no-prompt=false", "--force-refresh"},
		{"--no-prompt=false", "--credential-process", "--mode=cli"},
	} {
		o, err := Parse(args, io.Discard)
		if err != nil || !o.NoPrompt || o.Mode != "cli" || !o.CredentialProcess {
			t.Fatalf("unsafe process invocation: options=%+v err=%v", o, err)
		}
	}
}

func TestCompatibilityFlagsAndAliases(t *testing.T) {
	o, err := Parse([]string{
		"-a", "-f", "-m", "debug", "--no-prompt", "--no-sandbox",
		"--enable-chrome-network-service", "--no-verify-ssl", "--enable-chrome-seamless-sso",
		"--no-disable-extensions", "--disable-gpu", "--browser", "/custom/chromium", "--timeout", "90s",
		"--trusted-login-host", "ADFS.Example.com", "--trusted-login-host", "other.example.com",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !o.AllProfiles || !o.ForceRefresh || !o.NoPrompt || !o.NoSandbox || !o.EnableChromeNetworkService ||
		!o.NoVerifySSL || !o.EnableChromeSeamlessSSO || !o.NoDisableExtensions || !o.DisableGPU ||
		o.Mode != "debug" || o.Browser != "/custom/chromium" || o.Timeout != 90*time.Second {
		t.Fatalf("compatibility switches were not retained: %+v", o)
	}
	if strings.Join(o.TrustedLoginHosts, ",") != "adfs.example.com,other.example.com" {
		t.Fatalf("trusted hosts = %q", o.TrustedLoginHosts)
	}
	for _, args := range [][]string{{"-c", "--no-prompt"}, {"-h"}, {"--help"}, {"--version"}, {"-p", "selected", "-f"}} {
		if _, err := Parse(args, io.Discard); err != nil {
			t.Fatalf("rejected supported invocation %q: %v", args, err)
		}
	}
}
