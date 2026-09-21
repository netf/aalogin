//go:build integration && linux

package browser

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aalogin/internal/cli"
	"golang.org/x/sys/unix"
)

const stateFixtureAssertion = "c3RhdGUtZml4dHVyZQ=="

type stateFixtureOutput struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	onWrite func(string)
}

func (o *stateFixtureOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	_, _ = o.buffer.Write(p)
	o.mu.Unlock()
	if o.onWrite != nil {
		o.onWrite(string(p))
	}
	return len(p), nil
}

func (o *stateFixtureOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buffer.String()
}

func stateFixtureTerminal(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

func stateFixtureBrowser(t *testing.T, handler http.HandlerFunc) (Browser, Options, *stateFixtureOutput) {
	t.Helper()
	for _, key := range []string{"https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY"} {
		t.Setenv(key, "")
	}
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	out := &stateFixtureOutput{}
	b := Browser{deps: &browserDependencies{
		allowEndpoint: func(u *url.URL) bool { return u.Scheme == "http" && u.Hostname() == "127.0.0.1" },
		statePolicy: statePolicy{
			allowOrigin:    func(origin string) bool { return origin == server.URL },
			pollInterval:   20 * time.Millisecond,
			unknownTimeout: 500 * time.Millisecond,
		},
	}}
	opts := Options{
		Executable: os.Getenv("CHROME_BIN"), Mode: "cli", Tenant: "fixture.example", Username: "fixture@example.invalid", Password: "fixture-password",
		LoginURL: server.URL + "/start", ACS: server.URL + "/saml", NoSandbox: true, Out: out,
	}
	return b, opts, out
}

func stateFixtureContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func stateFixtureCapturePage(delayMilliseconds int) string {
	return fmt.Sprintf(`<form id="capture" action="/saml" method="post"><input type="hidden" name="SAMLResponse" value="%s"></form><script>setTimeout(()=>document.getElementById('capture').submit(),%d)</script>`, stateFixtureAssertion, delayMilliseconds)
}

func TestBrowserFlowStatesUsernamePasswordOTP(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	var forwarded atomic.Int32
	b, opts, out := stateFixtureBrowser(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		switch r.URL.Path {
		case "/username":
			seen["username"] = r.PostForm.Get("loginfmt")
		case "/password":
			seen["password"] = r.PostForm.Get("passwd")
		case "/otp":
			seen["otp"] = r.PostForm.Get("otc")
		case "/stay":
			seen["stay"] = r.PostForm.Get("choice")
		}
		mu.Unlock()
		switch r.URL.Path {
		case "/start":
			fmt.Fprint(w, `<div id="service_exception_message" style="display:none">hidden failure</div><input name="loginfmt" style="display:none"><form action="/username" method="post"><input name="loginfmt" value="replace-me"><input type="submit"></form>`)
		case "/username":
			fmt.Fprint(w, `<input name="passwd" class="moveOffScreen"><form action="/password" method="post"><input name="passwd" type="password" value="replace-me"><input type="submit"></form>`)
		case "/password":
			fmt.Fprint(w, `<div id="idDiv_SAOTCC_Description">Enter the fixture verification code.</div><form action="/otp" method="post"><input name="otc"><input type="submit"></form>`)
		case "/otp":
			fmt.Fprint(w, `<div id="KmsiDescription">Stay signed in?</div><form action="/stay" method="post"><button id="idSIButton9" name="choice" value="yes">Yes</button><button id="idBtn_Back" name="choice" value="no">No</button></form>`)
		case "/stay":
			fmt.Fprint(w, stateFixtureCapturePage(0))
		case "/saml":
			forwarded.Add(1)
		}
	})
	master, slave := stateFixtureTerminal(t)
	var prompted atomic.Int32
	out.onWrite = func(message string) {
		if strings.Contains(message, "Verification code:") {
			prompted.Add(1)
			if _, err := master.WriteString("729481\n"); err != nil {
				t.Error(err)
			}
		}
	}
	opts.Prompt = &cli.Prompt{In: slave, Out: out}
	assertion, err := b.Acquire(stateFixtureContext(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	if assertion != stateFixtureAssertion {
		t.Fatal("did not intercept the fixture assertion")
	}
	mu.Lock()
	defer mu.Unlock()
	for key, want := range map[string]string{"username": opts.Username, "password": opts.Password, "otp": "729481", "stay": "no"} {
		if seen[key] != want {
			t.Errorf("%s form received %q, want %q", key, seen[key], want)
		}
	}
	if prompted.Load() != 1 {
		t.Errorf("verification prompted %d times", prompted.Load())
	}
	if forwarded.Load() != 0 {
		t.Fatal("assertion was forwarded to ACS")
	}
	if strings.Contains(out.String(), opts.Password) || strings.Contains(out.String(), "729481") || strings.Contains(out.String(), assertion) {
		t.Fatal("diagnostics contain a secret")
	}
}

func TestBrowserFlowStatesApproval(t *testing.T) {
	for _, passwordless := range []bool{false, true} {
		t.Run(fmt.Sprintf("passwordless=%t", passwordless), func(t *testing.T) {
			var clicks atomic.Int32
			b, opts, out := stateFixtureBrowser(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/notification" {
					clicks.Add(1)
					return
				}
				if r.URL.Path != "/start" {
					return
				}
				if passwordless {
					fmt.Fprint(w, `<div id="idDiv_RemoteNGC_PollingDescription">Approve this fixture request.</div><div id="idRemoteNGC_DisplaySign">84</div><input type="button" value="Send notification" onclick="fetch('/notification');this.remove();setTimeout(()=>document.getElementById('capture').submit(),350)"><form id="capture" action="/saml" method="post"><input type="hidden" name="SAMLResponse" value="`+stateFixtureAssertion+`"></form>`)
				} else {
					fmt.Fprint(w, `<div id="idDiv_SAOTCAS_Description">Approve this fixture request.</div><div id="idRichContext_DisplaySign">84</div>`+stateFixtureCapturePage(350))
				}
			})
			opts.NoPrompt = true
			assertion, err := b.Acquire(stateFixtureContext(t), opts)
			if err != nil || assertion != stateFixtureAssertion {
				t.Fatalf("assertion capture: %v", err)
			}
			if strings.Count(out.String(), "Approve this fixture request.") != 1 || strings.Count(out.String(), "Number to match: 84") != 1 {
				t.Fatalf("approval instructions repeated or missing: %q", out.String())
			}
			if passwordless && clicks.Load() != 1 {
				t.Errorf("notification sent %d times", clicks.Load())
			}
		})
	}
}

func TestBrowserFlowStatesErrors(t *testing.T) {
	for _, tc := range []struct{ name, page, want string }{
		{"denied", `<div id="idDiv_SAASDS_Description">Fixture approval denied</div><form><input name="passwd"><input type="submit"></form>`, "MFA approval was denied"},
		{"timedout", `<div id="idDiv_SAASTO_Description">Fixture approval expired</div>`, "MFA approval was denied or timed out"},
		{"service", `<div id="service_exception_message">Fixture service failure</div><form><input name="loginfmt"><input type="submit"></form>`, "sign-in service error"},
		{"unknown", `<div>Fixture passkey or CAPTCHA</div>`, "unrecognized sign-in page"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, opts, _ := stateFixtureBrowser(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.page) })
			opts.NoPrompt = true
			assertion, err := b.Acquire(stateFixtureContext(t), opts)
			if assertion != "" || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %s error, got assertion %q, error %v", tc.name, assertion, err)
			}
		})
	}
}

func TestBrowserFlowStatesPromptSuppression(t *testing.T) {
	for _, tc := range []struct {
		name, page string
		process    bool
	}{
		{"username", `<form><input name="loginfmt"><input type="submit"></form>`, false},
		{"password", `<form><input name="passwd"><input type="submit"></form>`, false},
		{"otp", `<div id="idDiv_SAOTCC_Description">SECRET-OTP-INSTRUCTIONS</div><form><input name="otc"><input type="submit"></form>`, false},
		{"process-push", `<div id="idDiv_SAOTCAS_Description">SECRET-APPROVAL-INSTRUCTIONS</div><div id="idRichContext_DisplaySign">8317</div>`, true},
		{"process-passwordless", `<input type="button" value="Send notification"><div id="idRemoteNGC_DisplaySign">8317</div>`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, opts, out := stateFixtureBrowser(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.page) })
			in, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = in.Close(); _ = writer.Close() })
			if _, err := writer.WriteString("unconsumed\n"); err != nil {
				t.Fatal(err)
			}
			_ = writer.Close()
			opts.Username, opts.Password = "", ""
			opts.NoPrompt, opts.CredentialProcess = !tc.process, tc.process
			opts.Prompt = &cli.Prompt{In: in, Out: out}
			assertion, authErr := b.Acquire(stateFixtureContext(t), opts)
			if assertion != "" || authErr == nil || !strings.Contains(authErr.Error(), "interaction required") {
				t.Fatalf("expected interaction-required, got %q, %v", assertion, authErr)
			}
			remaining, err := io.ReadAll(in)
			if err != nil || string(remaining) != "unconsumed\n" {
				t.Fatalf("no-prompt consumed input: %q, %v", remaining, err)
			}
			for _, forbidden := range []string{"Username:", "Password:", "Verification code:", "SECRET-", "8317"} {
				if strings.Contains(out.String()+authErr.Error(), forbidden) {
					t.Fatalf("suppressed challenge leaked %q", forbidden)
				}
			}
		})
	}
}

func TestBrowserFlowStatesRejectedPassword(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		t.Run(fmt.Sprintf("interactive=%t", interactive), func(t *testing.T) {
			var mu sync.Mutex
			var passwords []string
			b, opts, out := stateFixtureBrowser(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/submit" {
					_ = r.ParseForm()
					password := r.PostForm.Get("Password")
					mu.Lock()
					passwords = append(passwords, password)
					mu.Unlock()
					if password == "replacement-fixture-password" {
						fmt.Fprint(w, stateFixtureCapturePage(0))
						return
					}
					fmt.Fprint(w, `<div class="alert-error">Rejected `+html.EscapeString(password)+` https://fixture.invalid/?token=PRIVATE-QUERY</div>`)
				}
				fmt.Fprint(w, `<form action="/submit" method="post"><input name="Password" type="password"><input type="submit"></form>`)
			})
			opts.NoPrompt = !interactive
			if interactive {
				master, slave := stateFixtureTerminal(t)
				out.onWrite = func(message string) {
					if strings.Contains(message, "Password:") {
						if _, err := master.WriteString("replacement-fixture-password\n"); err != nil {
							t.Error(err)
						}
					}
				}
				opts.Prompt = &cli.Prompt{In: slave, Out: out}
			}
			assertion, err := b.Acquire(stateFixtureContext(t), opts)
			if interactive {
				if err != nil || assertion != stateFixtureAssertion {
					t.Fatalf("correction failed: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "rejected") || assertion != "" {
				t.Fatalf("expected rejection, got %q, %v", assertion, err)
			}
			mu.Lock()
			defer mu.Unlock()
			want := []string{opts.Password}
			if interactive {
				want = append(want, "replacement-fixture-password")
			}
			if fmt.Sprint(passwords) != fmt.Sprint(want) {
				t.Fatalf("password was replayed or correction lost: %q", passwords)
			}
			diagnostic := out.String()
			if err != nil {
				diagnostic += err.Error()
			}
			for _, secret := range []string{opts.Password, "replacement-fixture-password", "PRIVATE-QUERY"} {
				if strings.Contains(diagnostic, secret) {
					t.Fatalf("diagnostic leaked %q", secret)
				}
			}
		})
	}
}

func TestBrowserFlowStatesAccountChoice(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		personalOnly, interactive bool
		want                      string
	}{
		{"work-default", false, false, "work"}, {"personal-only", true, false, "personal"}, {"personal-choice", false, true, "personal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			choice := make(chan string, 1)
			b, opts, out := stateFixtureBrowser(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/choice" {
					choice <- r.URL.Query().Get("type")
					fmt.Fprint(w, stateFixtureCapturePage(0))
					return
				}
				if !tc.personalOnly {
					fmt.Fprint(w, `<button id="aadTileTitle" onclick="location.href='/choice?type=work'">Work</button>`)
				}
				fmt.Fprint(w, `<button id="msaTileTitle" onclick="location.href='/choice?type=personal'">Personal</button>`)
			})
			opts.NoPrompt = !tc.interactive
			if tc.interactive {
				master, slave := stateFixtureTerminal(t)
				out.onWrite = func(message string) {
					if strings.Contains(message, "Account type") {
						if _, err := master.WriteString("2\n"); err != nil {
							t.Error(err)
						}
					}
				}
				opts.Prompt = &cli.Prompt{In: slave, Out: out}
			}
			assertion, err := b.Acquire(stateFixtureContext(t), opts)
			if err != nil || assertion != stateFixtureAssertion {
				t.Fatalf("account selection: %v", err)
			}
			select {
			case got := <-choice:
				if got != tc.want {
					t.Fatalf("selected %s, want %s", got, tc.want)
				}
			default:
				t.Fatal("no account selected")
			}
		})
	}
}

func TestBrowserFlowStatesUntrustedOrigin(t *testing.T) {
	var posts atomic.Int32
	b, opts, _ := stateFixtureBrowser(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		fmt.Fprint(w, `<form method="post"><input name="passwd" type="password"><input type="submit"></form>`)
	})
	b.deps.statePolicy.allowOrigin = nil
	opts.NoPrompt = true
	assertion, err := b.Acquire(stateFixtureContext(t), opts)
	if err == nil || assertion != "" || !strings.Contains(err.Error(), "refusing credentials") {
		t.Fatalf("untrusted-origin result: %q, %v", assertion, err)
	}
	if posts.Load() != 0 {
		t.Fatal("credential submitted to untrusted origin")
	}
}

func TestBrowserFlowStatesPromptCancellation(t *testing.T) {
	for _, capture := range []bool{false, true} {
		t.Run(fmt.Sprintf("capture=%t", capture), func(t *testing.T) {
			b, opts, out := stateFixtureBrowser(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<form><input name="otc"><input type="submit"></form>`)
				if capture {
					fmt.Fprint(w, stateFixtureCapturePage(300))
				}
			})
			_, slave := stateFixtureTerminal(t)
			before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(stateFixtureContext(t))
			defer cancel()
			var prompted atomic.Bool
			out.onWrite = func(message string) {
				if strings.Contains(message, "Verification code:") {
					prompted.Store(true)
					if !capture {
						cancel()
					}
				}
			}
			opts.Prompt = &cli.Prompt{In: slave, Out: out}
			assertion, err := b.Acquire(ctx, opts)
			if capture {
				if err != nil || assertion != stateFixtureAssertion {
					t.Fatalf("capture did not cancel terminal work: %v", err)
				}
			} else if !errors.Is(err, context.Canceled) || assertion != "" {
				t.Fatalf("cancellation result: %q, %v", assertion, err)
			}
			if !prompted.Load() {
				t.Fatal("fixture did not reach terminal input")
			}
			after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			if before.Lflag != after.Lflag {
				t.Fatal("terminal mode not restored before acquisition returned")
			}
		})
	}
}

func TestBrowserFlowStatesRepeatedRejectionIsBounded(t *testing.T) {
	var submissions atomic.Int32
	b, opts, out := stateFixtureBrowser(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/attempt" {
			submissions.Add(1)
			return
		}
		fmt.Fprint(w, `<div class="alert-error" style="display:none">Incorrect fixture password</div><form onsubmit="event.preventDefault();fetch('/attempt',{method:'POST'});document.querySelector('.alert-error').style.display='block'"><input name="passwd" type="password"><input type="submit"></form>`)
	})
	master, slave := stateFixtureTerminal(t)
	var prompts atomic.Int32
	out.onWrite = func(message string) {
		if strings.Contains(message, "Password:") {
			prompts.Add(1)
			if _, err := master.WriteString("still-wrong-fixture-password\n"); err != nil {
				t.Error(err)
			}
		}
	}
	opts.Prompt = &cli.Prompt{In: slave, Out: out}
	assertion, err := b.Acquire(stateFixtureContext(t), opts)
	if assertion != "" || err == nil || !strings.Contains(err.Error(), "form did not advance") {
		t.Fatalf("repeated identical rejection was not bounded: %q, %v", assertion, err)
	}
	if submissions.Load() != 2 || prompts.Load() != 1 {
		t.Fatalf("unexpected replay: submissions=%d, prompts=%d", submissions.Load(), prompts.Load())
	}
}
