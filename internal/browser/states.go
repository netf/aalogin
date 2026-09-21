// Copyright (c) 2022 aws-azure-login devs
// SPDX-License-Identifier: MIT
// Microsoft selectors and authentication flow adapted from aws-azure-login.
package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"aalogin/internal/cli"
	"github.com/chromedp/cdproto"
	"github.com/chromedp/chromedp"
)

// Test policy is private: neither origin exceptions nor shortened deadlines are
// reachable from command-line arguments or environment variables.
type statePolicy struct {
	allowOrigin    func(string) bool
	pollInterval   time.Duration
	unknownTimeout time.Duration
}

type observedState struct {
	Kind     string `json:"kind"`
	Origin   string `json:"origin"`
	Error    string `json:"error"`
	Text     string `json:"text"`
	Number   string `json:"number"`
	Work     bool   `json:"work"`
	Personal bool   `json:"personal"`
	Ready    bool   `json:"ready"`
}

// Observe and act use the same visibility and state ordering. Actions reobserve
// in the same JavaScript task as the write, closing the navigation race between
// an origin check (or a terminal prompt) and supplying a credential.
const stateObserverJS = `
const visible = e => !!e && e.getClientRects().length > 0 &&
  (typeof e.checkVisibility === 'function' ? e.checkVisibility({checkOpacity:true,checkVisibilityCSS:true}) :
    getComputedStyle(e).visibility !== 'hidden' && getComputedStyle(e).display !== 'none');
const find = selector => Array.from(document.querySelectorAll(selector)).find(visible);
const text = selector => { const e = find(selector); const value=e ? (e.innerText || e.textContent || '') : ''; return value.length>4096 ? '[message omitted]' : value; };
const observe = () => {
  const s = {kind:'unknown',origin:location.origin,error:'',text:'',number:'',work:false,personal:false,ready:true};
  if (find('#service_exception_message')) { s.kind='service_error'; s.error=text('#service_exception_message'); }
  else if (find('#idDiv_SAASDS_Description,#idDiv_SAASTO_Description')) { s.kind='mfa_error'; s.error=text('#idDiv_SAASDS_Description,#idDiv_SAASTO_Description'); }
  else if (find('input[name="loginfmt"]:not(.moveOffScreen)')) { s.kind='username'; }
  else if (find('#aadTileTitle,#msaTileTitle')) { s.kind='account'; s.work=!!find('#aadTileTitle'); s.personal=!!find('#msaTileTitle'); }
  else if (find("input[value='Send notification']")) { s.kind='passwordless'; s.text=text('#idDiv_RemoteNGC_PollingDescription'); s.number=text('#idRemoteNGC_DisplaySign'); }
  else if (find('input[name="Password"]:not(.moveOffScreen),input[name="passwd"]:not(.moveOffScreen)')) { s.kind='password'; }
  else if (find('#idDiv_SAOTCAS_Description')) { s.kind='push'; s.text=text('#idDiv_SAOTCAS_Description'); s.number=text('#idRichContext_DisplaySign'); }
  else if (find('input[name="otc"]:not(.moveOffScreen)')) { s.kind='otp'; s.text=text('#idDiv_SAOTCC_Description'); }
  else if (find('#KmsiDescription')) { s.kind='stay'; }
  else if (find('#idDiv_RemoteNGC_PollingDescription,#idRemoteNGC_DisplaySign')) { s.kind='passwordless_wait'; s.text=text('#idDiv_RemoteNGC_PollingDescription'); s.number=text('#idRemoteNGC_DisplaySign'); }
  if (s.kind==='username' || s.kind==='password' || s.kind==='otp') s.error=text('.alert-error');
  const ready = (field, button) => { const input=find(field), submit=find(button); return !!input && !input.disabled && !input.readOnly && !!submit && !submit.disabled; };
  if (s.kind==='username') s.ready=ready('input[name="loginfmt"]:not(.moveOffScreen)','input[type="submit"]');
  if (s.kind==='password') s.ready=ready('input[name="Password"]:not(.moveOffScreen),input[name="passwd"]:not(.moveOffScreen)','span[class="submit"],input[type="submit"]');
  if (s.kind==='otp') s.ready=ready('input[name="otc"]:not(.moveOffScreen)','input[type="submit"]');
  return s;
};
`

func driveStates(ctx context.Context, opts Options, policy statePolicy) error {
	if opts.Mode == "gui" {
		<-ctx.Done()
		return ctx.Err()
	}
	if policy.pollInterval <= 0 {
		policy.pollInterval = 250 * time.Millisecond
	}
	if policy.unknownTimeout <= 0 {
		policy.unknownTimeout = 30 * time.Second
	}
	for _, host := range opts.TrustedLoginHosts {
		if !validLoginHost(host) {
			return errors.New("trusted login host must be an exact hostname without a scheme, port, wildcard, or path")
		}
	}
	allowOrigin := policy.allowOrigin
	if allowOrigin == nil {
		allowOrigin = func(origin string) bool { return trustedLoginOrigin(origin, opts.TrustedLoginHosts) }
	}
	out := opts.Out
	if out == nil {
		out = os.Stderr
	}
	noPrompt := opts.NoPrompt || opts.CredentialProcess
	prompt := cli.Prompt{In: os.Stdin, Out: out, NoPrompt: noPrompt}
	if opts.Prompt != nil {
		prompt = *opts.Prompt
		prompt.NoPrompt = prompt.NoPrompt || noPrompt
		if prompt.Out == nil {
			prompt.Out = out
		}
	}
	noPrompt = prompt.NoPrompt
	secrets := []string{opts.Password}
	usernameUsed, passwordUsed := false, false
	last := ""
	lastApproval := ""
	submittedKey := ""
	var submittedAt time.Time
	unknownSince := time.Now()
	ticker := time.NewTicker(policy.pollInterval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var s observedState
		err := chromedp.Run(ctx, chromedp.Evaluate("(() => {"+stateObserverJS+"return observe();})()", &s))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !transientStateError(err) {
				return errors.New("cannot observe the sign-in page; rerun with --mode gui or --mode debug")
			}
		} else if s.Kind == "unknown" || !s.Ready {
			last = ""
		} else {
			unknownSince = time.Now()
			keyBytes, _ := json.Marshal(s)
			key := string(keyBytes)
			if key == submittedKey && !submittedAt.IsZero() && time.Since(submittedAt) >= policy.unknownTimeout {
				return errors.New("sign-in form did not advance after submission; rerun with --mode gui or --mode debug")
			}
			if key != submittedKey {
				submittedAt = time.Time{}
			}
			if key != last {
				last = key
				safe := func(value string) string { return sanitizeStateText(value, secrets) }
				if s.Kind == "service_error" {
					return statePageError("sign-in service error", safe(s.Error))
				}
				if s.Kind == "mfa_error" {
					return statePageError("MFA approval was denied or timed out", safe(s.Error))
				}
				if s.Kind == "username" || s.Kind == "password" || s.Kind == "otp" {
					if !allowOrigin(s.Origin) {
						return untrustedStateOrigin(s.Origin)
					}
					if s.Error != "" {
						if noPrompt {
							return statePageError("sign-in credential was rejected; rerun without --no-prompt", safe(s.Error))
						}
						if err := writeStateMessage(out, "Sign-in rejected: "+safe(s.Error)); err != nil {
							return err
						}
					}
				}
				button, field, value := "", "", ""
				switch s.Kind {
				case "username":
					field, button = `input[name="loginfmt"]:not(.moveOffScreen)`, `input[type="submit"]`
					if !usernameUsed && s.Error == "" {
						value = opts.Username
					}
					if value == "" {
						if noPrompt {
							return interactionRequired("username is required")
						}
						value, err = prompt.Read(ctx, "Username", "", false)
					}
					if err == nil && strings.TrimSpace(value) == "" {
						err = errors.New("username cannot be empty")
					}
				case "password":
					field, button = `input[name="Password"]:not(.moveOffScreen),input[name="passwd"]:not(.moveOffScreen)`, `span[class="submit"],input[type="submit"]`
					if !passwordUsed && s.Error == "" {
						value = opts.Password
					}
					if value == "" {
						if noPrompt {
							return interactionRequired("password is required or a previous password was rejected")
						}
						value, err = prompt.Read(ctx, "Password", "", true)
					}
					if err == nil && value == "" {
						err = errors.New("password cannot be empty")
					}
					secrets = append(secrets, value)
				case "otp":
					if noPrompt {
						return interactionRequired("a one-time code is required")
					}
					if err = writeStateMessage(out, safe(s.Text)); err == nil {
						value, err = prompt.Read(ctx, "Verification code", "", true)
					}
					if err == nil && value == "" {
						err = errors.New("verification code cannot be empty")
					}
					secrets = append(secrets, value)
					field, button = `input[name="otc"]:not(.moveOffScreen)`, `input[type="submit"]`
				case "account":
					button = "#aadTileTitle"
					if !s.Work {
						button = "#msaTileTitle"
					} else if s.Personal && !noPrompt {
						var choice string
						choice, err = prompt.Read(ctx, "Account type (1 = work or school, 2 = personal)", "1", false)
						if err == nil {
							switch strings.ToLower(strings.TrimSpace(choice)) {
							case "1", "work", "school":
							case "2", "personal":
								button = "#msaTileTitle"
							default:
								err = errors.New("account type must be 1 (work or school) or 2 (personal)")
							}
						}
					}
				case "passwordless", "passwordless_wait", "push":
					if opts.CredentialProcess {
						return interactionRequired("authentication approval is required")
					}
					message := safe(s.Text)
					if message == "" {
						message = "Approve the sign-in request on your authentication device."
					}
					if s.Number != "" {
						message += "\nNumber to match: " + safe(s.Number)
					}
					if message != lastApproval {
						err = writeStateMessage(out, message)
						lastApproval = message
					}
					if s.Kind == "passwordless" {
						button = `input[value='Send notification']`
					}
				case "stay":
					button = "#idBtn_Back"
					if opts.RememberMe {
						button = "#idSIButton9"
					}
				}
				if err != nil {
					return err
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				acted := true
				if button != "" {
					acted, err = actOnState(ctx, s, field, button, value)
				}
				// A navigation may destroy the evaluation context after submission.
				// Never resend an automatic secret after an ambiguous attempt.
				if acted || err != nil {
					if s.Kind == "username" {
						usernameUsed = true
					}
					if s.Kind == "password" {
						passwordUsed = true
					}
					if field != "" {
						submittedKey, submittedAt = key, time.Now()
					}
				}
				if err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if !transientStateError(err) {
						return errors.New("cannot operate the sign-in page; rerun with --mode gui or --mode debug")
					}
				} else if !acted {
					// A definite no-op is safe to retry after fresh observation.
					last = ""
				}
			}
		}
		if time.Since(unknownSince) >= policy.unknownTimeout {
			return errors.New("unrecognized sign-in page; use --mode gui for CAPTCHA, passkeys, or changed pages, or --mode debug to inspect the browser")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func actOnState(ctx context.Context, expected observedState, field, button, value string) (bool, error) {
	payload, _ := json.Marshal(struct {
		Expected observedState `json:"expected"`
		Field    string        `json:"field"`
		Button   string        `json:"button"`
		Value    string        `json:"value"`
	}{expected, field, button, value})
	var acted bool
	err := chromedp.Run(ctx, chromedp.Evaluate("(() => {"+stateObserverJS+`
const action = `+string(payload)+`;
if (JSON.stringify(observe()) !== JSON.stringify(action.expected)) return false;
const button = find(action.button);
if (!button || button.disabled) return false;
if (action.field) {
  const input = find(action.field);
  if (!input || input.disabled || input.readOnly) return false;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
  input.focus();
  setter.call(input,'');
  input.dispatchEvent(new Event('input',{bubbles:true}));
  setter.call(input,action.value);
  input.dispatchEvent(new Event('input',{bubbles:true}));
  input.dispatchEvent(new Event('change',{bubbles:true}));
}
button.click();
return true;
})()`, &acted))
	return acted, err
}

func validLoginHost(host string) bool {
	if host == "" || host != strings.TrimSpace(host) || strings.ContainsAny(host, ":/?#@*\\[]") {
		return false
	}
	for _, ch := range host {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.') {
			return false
		}
	}
	return !strings.HasPrefix(host, ".") && !strings.HasSuffix(host, ".") && !strings.Contains(host, "..")
}

func trustedLoginOrigin(origin string, hosts []string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || (u.Port() != "" && u.Port() != "443") || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "login.microsoftonline.com") || strings.EqualFold(host, "login.live.com") {
		return true
	}
	for _, trusted := range hosts {
		if validLoginHost(trusted) && strings.EqualFold(host, trusted) {
			return true
		}
	}
	return false
}

func untrustedStateOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err == nil && u.Scheme == "https" && validLoginHost(u.Hostname()) && (u.Port() == "" || u.Port() == "443") {
		return fmt.Errorf("refusing credentials on untrusted login host %s; use --mode gui or rerun with --trusted-login-host %s", u.Hostname(), u.Hostname())
	}
	return errors.New("refusing credentials on a non-HTTPS or invalid login origin; use --mode gui with a trusted HTTPS sign-in page")
}

func interactionRequired(reason string) error {
	return fmt.Errorf("interaction required; rerun without --no-prompt: %s", reason)
}

func statePageError(prefix, message string) error {
	if message == "" {
		return errors.New(prefix)
	}
	return fmt.Errorf("%s: %s", prefix, message)
}

var stateURLPattern = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s]+`)
var stateTokenPattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{100,}`)

func sanitizeStateText(value string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	value = stateURLPattern.ReplaceAllString(value, "[URL]")
	value = stateTokenPattern.ReplaceAllString(value, "[redacted]")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) > 512 {
		value = string(runes[:512]) + "..."
	}
	return value
}

func writeStateMessage(out io.Writer, message string) error {
	if message == "" {
		return nil
	}
	if _, err := fmt.Fprintln(out, message); err != nil {
		return errors.New("cannot write authentication instructions")
	}
	return nil
}

func transientStateError(err error) bool {
	var protocolError *cdproto.Error
	if !errors.As(err, &protocolError) {
		return false
	}
	for _, message := range []string{"Execution context was destroyed", "Cannot find context with specified id", "Cannot find default execution context", "Could not find node with given id", "No node with given id", "Node is detached from document"} {
		if strings.Contains(protocolError.Message, message) {
			return true
		}
	}
	return false
}
