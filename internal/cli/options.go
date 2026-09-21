// Package cli defines aalogin's command-line and terminal interaction contracts.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

type Options struct {
	Profile, Mode, Browser                                   string
	AllProfiles, ForceRefresh, Configure, NoPrompt           bool
	NoSandbox, EnableChromeNetworkService, NoVerifySSL       bool
	EnableChromeSeamlessSSO, NoDisableExtensions, DisableGPU bool
	CredentialProcess, Help, Version                         bool
	Timeout, Duration                                        time.Duration
	TrustedLoginHosts                                        []string
}

func flags(o *Options) *pflag.FlagSet {
	f := pflag.NewFlagSet("aalogin", pflag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVarP(&o.Profile, "profile", "p", "", "AWS profile (otherwise AWS_PROFILE, then default)")
	f.BoolVarP(&o.AllProfiles, "all-profiles", "a", false, "Refresh all Azure profiles expiring within 11 minutes")
	f.BoolVarP(&o.ForceRefresh, "force-refresh", "f", false, "Refresh even unexpired all-profile credentials")
	f.BoolVarP(&o.Configure, "configure", "c", false, "Configure an Azure AWS profile without storing passwords")
	f.StringVarP(&o.Mode, "mode", "m", "cli", "Authentication mode: cli, gui, or debug")
	f.BoolVar(&o.NoPrompt, "no-prompt", false, "Never read terminal input")
	f.BoolVar(&o.NoSandbox, "no-sandbox", false, "Explicitly disable the Chromium sandbox (unsafe)")
	f.BoolVar(&o.EnableChromeNetworkService, "enable-chrome-network-service", false, "Enable Chromium's NetworkService feature")
	f.BoolVar(&o.NoVerifySSL, "no-verify-ssl", false, "Disable STS TLS verification only (unsafe)")
	f.BoolVar(&o.EnableChromeSeamlessSSO, "enable-chrome-seamless-sso", false, "Enable Chromium integrated authentication for Microsoft seamless SSO")
	f.BoolVar(&o.NoDisableExtensions, "no-disable-extensions", false, "Allow Chromium extensions")
	f.BoolVar(&o.DisableGPU, "disable-gpu", false, "Disable Chromium GPU acceleration")
	f.BoolVar(&o.CredentialProcess, "credential-process", false, "Emit AWS process credentials JSON; implies --no-prompt and requires cli mode")
	f.StringVar(&o.Browser, "browser", "", "Chromium executable (otherwise CHROME_BIN, then PATH)")
	f.DurationVar(&o.Timeout, "timeout", 5*time.Minute, "Overall authentication timeout (Go duration)")
	f.DurationVar(&o.Duration, "duration", 0, "Override profile session duration (Go duration, whole seconds from 15m to 12h)")
	f.StringArrayVar(&o.TrustedLoginHosts, "trusted-login-host", nil, "Additional exact HTTPS credential-filling hostname (repeatable)")
	f.BoolVarP(&o.Help, "help", "h", false, "Show help")
	f.BoolVar(&o.Version, "version", false, "Show version")
	return f
}

// Parse validates options without opening a browser or reading configuration.
// The caller renders help and errors on stderr, and handles Help and Version.
func Parse(args []string, stderr io.Writer) (Options, error) {
	var o Options
	f := flags(&o)
	if stderr != nil {
		f.SetOutput(stderr)
	}
	if err := f.Parse(args); err != nil {
		return Options{}, err
	}
	if f.NArg() != 0 {
		return Options{}, fmt.Errorf("positional arguments are not supported")
	}
	if o.Mode != "cli" && o.Mode != "gui" && o.Mode != "debug" {
		return Options{}, fmt.Errorf("--mode must be cli, gui, or debug")
	}
	if o.Timeout <= 0 {
		return Options{}, fmt.Errorf("--timeout must be positive")
	}
	if f.Changed("duration") && (o.Duration < 15*time.Minute || o.Duration > 12*time.Hour || o.Duration%time.Second != 0) {
		return Options{}, fmt.Errorf("--duration must be whole seconds between 15m and 12h")
	}
	if o.Configure && f.Changed("duration") {
		return Options{}, fmt.Errorf("--configure cannot be combined with --duration")
	}
	if o.Configure && (o.AllProfiles || o.CredentialProcess || o.ForceRefresh) {
		return Options{}, fmt.Errorf("--configure cannot be combined with --all-profiles, --credential-process, or --force-refresh")
	}
	if f.Changed("profile") && o.AllProfiles {
		return Options{}, fmt.Errorf("--profile cannot be combined with --all-profiles")
	}
	if o.CredentialProcess && (o.AllProfiles || o.Mode != "cli") {
		return Options{}, fmt.Errorf("--credential-process requires cli mode and cannot be combined with --all-profiles")
	}
	if o.Profile == "" {
		o.Profile = os.Getenv("AWS_PROFILE")
	}
	if o.Profile == "" {
		o.Profile = "default"
	}
	if strings.ContainsAny(o.Profile, "\r\n[]") {
		return Options{}, fmt.Errorf("profile name must not contain newlines or brackets")
	}
	for i, host := range o.TrustedLoginHosts {
		if !validHostname(host) {
			return Options{}, fmt.Errorf("--trusted-login-host requires an exact hostname without a scheme, wildcard, port, or path")
		}
		o.TrustedLoginHosts[i] = strings.ToLower(host)
	}
	if o.CredentialProcess {
		o.NoPrompt = true
	}
	return o, nil
}

func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func Help(out io.Writer) {
	var o Options
	f := flags(&o)
	fmt.Fprintln(out, "Usage: aalogin [options]\n\nAuthenticate Microsoft Entra ID to AWS SAML and write temporary AWS credentials.\nAll prompts and progress use stderr. Normal login never prints credentials.")
	fmt.Fprintln(out, "\nOptions:")
	fmt.Fprint(out, f.FlagUsages())
	fmt.Fprintln(out, `
Modes:
  cli    Headless Chromium with terminal username/password/MFA prompts (default).
  gui    Visible Chromium; complete authentication in the browser.
  debug  Visible Chromium with terminal-driven authentication; never logs secrets.

Use --mode gui for passkeys, CAPTCHA, or unsupported authentication pages.
No browser is downloaded; install Chromium or specify --browser.
--no-prompt never reads stdin; typed MFA requires an interactive invocation.

Profiles and storage:
  Reuses azure_* settings in ~/.aws/config; writes ~/.aws/credentials.
  AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE override these paths.
  Configure with: aalogin --configure --profile NAME
  Configuration never writes passwords. Existing legacy password keys are kept.
  All-profile renewal includes only profiles with tenant/app values in the file.
  Only complete credentials expiring more than 11 minutes away are skipped.

Browser privacy:
  Every login owns an isolated Chromium process; the normal browser is untouched.
  Remember-me stores sensitive session cookies under
  $XDG_STATE_HOME/aalogin/browser (default ~/.local/state/aalogin/browser).
  These private directories are not an encryption guarantee. Existing
  aws-azure-login browser state is not imported; first login authenticates again.
  Otherwise browser state is temporary and removed when the process finishes.
  Debug mode produces no screenshot, page HTML, or assertion diagnostic dumps.
  Password saving and the browser response cache are disabled.
  Browser TLS verification stays enabled, including with --no-verify-ssl.
  HTTPS proxies use https_proxy, then HTTPS_PROXY; bypass uses no_proxy, then
  NO_PROXY. AWS_CA_BUNDLE applies to STS. Proxy failure never falls back to direct.
  Shared-file locks coordinate aalogin writers, not unrelated programs.

AWS credential_process configuration:
  [profile NAME]
  credential_process = /absolute/path/to/aalogin --profile NAME --credential-process

Process mode emits exactly one AWS credentials JSON object on stdout, obtains
fresh credentials without writing the AWS credentials file, and never opens a
visible browser. Existing static credentials for the consumer profile take
precedence: deliberately remove them yourself if using credential_process.
aalogin never removes those credentials automatically.

Exit status: 0 success/help/version; 2 usage/configuration error;
1 authentication/network/persistence failure; 130 SIGINT; 143 SIGTERM.`)
}
