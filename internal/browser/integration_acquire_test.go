//go:build integration

package browser

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

func acquireEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"} {
		t.Setenv(key, "")
	}
	t.Setenv("XDG_STATE_HOME", t.TempDir())
}

func acquireLoopback(u *url.URL) bool {
	return (u.Scheme == "http" || u.Scheme == "https") && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "fixture.test")
}

func acquireBrowser() Browser {
	return Browser{deps: &browserDependencies{
		allowEndpoint: acquireLoopback,
		statePolicy:   statePolicy{pollInterval: 20 * time.Millisecond, unknownTimeout: 5 * time.Second},
	}}
}

func acquireOptions(loginURL string) Options {
	u, _ := url.Parse(loginURL)
	return Options{
		Mode: "cli", Tenant: "synthetic-tenant", Username: "fixture@example.test",
		LoginURL: loginURL, ACS: u.Scheme + "://" + u.Host + "/saml", NoPrompt: true,
		// An explicit test choice, not a production fallback for root.
		NoSandbox: true, Out: io.Discard,
	}
}

func acquireForm(assertion string) string {
	return `<html><body><form method="post" action="/saml?opaque=not-for-diagnostics"><input name="SAMLResponse" value="` + html.EscapeString(assertion) + `"></form><script>document.forms[0].submit()</script></body></html>`
}

type acquireProcess struct {
	process *os.Process
	profile string
}

func acquireObserveProcess(ctx context.Context) (acquireProcess, error) {
	process := chromedp.FromContext(ctx).Browser.Process()
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", process.Pid))
	if err != nil {
		return acquireProcess{}, err
	}
	// Chromium may rewrite argv into one space-separated process title.
	// Fixture directories contain no whitespace, so both forms are unambiguous.
	for _, arg := range strings.Fields(strings.ReplaceAll(string(cmdline), "\x00", " ")) {
		if strings.HasPrefix(arg, "--user-data-dir=") {
			return acquireProcess{process, strings.TrimPrefix(arg, "--user-data-dir=")}, nil
		}
	}
	return acquireProcess{}, errors.New("owned Chromium has no private user-data directory")
}

func acquireAssertStopped(t *testing.T, process acquireProcess, temporary bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := syscall.Kill(process.process.Pid, 0); errors.Is(err, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("owned Chromium PID %d still exists after Acquire returned", process.process.Pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if temporary {
		if _, err := os.Stat(process.profile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary browser profile remains after shutdown: %v", err)
		}
	}
}

func TestBrowserFlowEncodedCallbackExactlyOnce(t *testing.T) {
	acquireEnvironment(t)
	secrets := map[string]string{
		"AZURE_DEFAULT_PASSWORD": "synthetic-secret-not-for-chromium-env",
		"azure_default_password": "synthetic-lowercase-secret",
		"AWS_SECRET_ACCESS_KEY":  "synthetic-aws-secret",
		"AWS_SESSION_TOKEN":      "synthetic-aws-token",
	}
	for name, value := range secrets {
		t.Setenv(name, value)
	}
	assertion := "fixture+/encoded==&percent% value"
	var forwarded atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/saml" {
			forwarded.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		// Two actual simultaneous form submissions race for a single acquisition.
		_, _ = fmt.Fprintf(w, `<iframe name="first"></iframe><iframe name="second"></iframe><form target="first" method="post" action="/saml?q=secret"><input name="SAMLResponse" value="%s"></form><form target="second" method="post" action="/saml"><input name="SAMLResponse" value="%s"></form><script>document.forms[0].submit();document.forms[1].submit()</script>`, html.EscapeString(assertion), html.EscapeString(assertion))
	}))
	defer server.Close()
	browser := acquireBrowser()
	var owned acquireProcess
	var observationErr error
	browser.deps.onStarted = func(ctx context.Context) {
		owned, observationErr = acquireObserveProcess(ctx)
		if observationErr != nil {
			return
		}
		environment, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", owned.process.Pid))
		if err != nil {
			observationErr = err
			return
		}
		for _, secret := range secrets {
			if strings.Contains(string(environment), secret) {
				observationErr = errors.New("a parent credential leaked into the Chromium environment")
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	got, err := browser.Acquire(ctx, acquireOptions(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if observationErr != nil {
		t.Fatal(observationErr)
	}
	if got != assertion {
		t.Fatalf("form encoding changed assertion: got %q", got)
	}
	if forwarded.Load() != 0 {
		t.Fatal("an intercepted assertion was forwarded to the ACS server")
	}
	acquireAssertStopped(t, owned, true)
}

func TestBrowserFlowMalformedCallbacksNeverForward(t *testing.T) {
	for _, test := range []struct {
		name, page, want string
	}{
		{"duplicate", `<form method="post" action="/saml"><input name="SAMLResponse" value="one"><input name="SAMLResponse" value="two"></form><script>document.forms[0].submit()</script>`, "exactly one"},
		{"empty", acquireForm(""), "nonempty"},
		{"get", `<script>location.href='/saml?SAMLResponse=fake'</script>`, "POST"},
		{"content-type", `<script>fetch('/saml',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"SAMLResponse":"fake"}'})</script>`, "URL-encoded"},
		{"bad-encoding", `<script>fetch('/saml',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'SAMLResponse=%ZZ'})</script>`, "malformed form"},
		{"assertion-size", acquireForm(strings.Repeat("A", maxAssertion+1)), "100000"},
		{"form-size", `<script>fetch('/saml',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'SAMLResponse=fake&padding='+('x'.repeat(1048576))})</script>`, "1 MiB"},
	} {
		t.Run(test.name, func(t *testing.T) {
			acquireEnvironment(t)
			var forwarded atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/saml" {
					forwarded.Add(1)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, test.page)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			value, err := acquireBrowser().Acquire(ctx, acquireOptions(server.URL))
			if err == nil || !strings.Contains(err.Error(), test.want) || value != "" {
				t.Fatalf("expected rejected %s callback, got assertion %q, error %v", test.name, value, err)
			}
			if forwarded.Load() != 0 {
				t.Fatal("malformed callback escaped local interception")
			}
		})
	}
}

func TestBrowserFlowRememberedCookies(t *testing.T) {
	acquireEnvironment(t)
	var seen atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		value := "initial-session"
		if cookie, err := r.Cookie("remembered"); err == nil && cookie.Value == "synthetic-cookie" {
			value = "remembered-session"
			seen.Add(1)
		}
		http.SetCookie(w, &http.Cookie{Name: "remembered", Value: "synthetic-cookie", Path: "/", MaxAge: 3600, HttpOnly: true})
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = io.WriteString(w, acquireForm(value))
	}))
	defer server.Close()
	browser := acquireBrowser()
	options := acquireOptions(server.URL)
	options.RememberMe = true
	var processes []acquireProcess
	browser.deps.onStarted = func(ctx context.Context) {
		process, err := acquireObserveProcess(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		processes = append(processes, process)
	}
	for _, want := range []string{"initial-session", "remembered-session"} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		got, err := browser.Acquire(ctx, options)
		cancel()
		if err != nil || got != want {
			t.Fatalf("remember-me acquisition = %q, %v; want %q", got, err, want)
		}
	}
	if seen.Load() != 1 || len(processes) != 2 || processes[0].profile != processes[1].profile {
		t.Fatal("remember-me did not reuse the private session across two owned launches")
	}
	for _, process := range processes {
		acquireAssertStopped(t, process, false)
		info, err := os.Stat(process.profile)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("remembered state is not private: %v", err)
		}
	}
	options.RememberMe = false
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	got, err := browser.Acquire(ctx, options)
	if err != nil || got != "initial-session" {
		t.Fatalf("temporary session reused remembered cookies: %q, %v", got, err)
	}
}

func TestBrowserFlowCancellationAndBrowserExitCleanup(t *testing.T) {
	for _, exit := range []bool{false, true} {
		name := "cancellation"
		if exit {
			name = "browser-exit"
		}
		t.Run(name, func(t *testing.T) {
			acquireEnvironment(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "<html>Waiting for fixture cancellation</html>")
			}))
			defer server.Close()
			browser := acquireBrowser()
			started := make(chan acquireProcess, 1)
			observed := make(chan error, 1)
			browser.deps.onStarted = func(ctx context.Context) {
				process, err := acquireObserveProcess(ctx)
				if err != nil {
					observed <- err
					return
				}
				started <- process
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			finished := make(chan acquisitionResult, 1)
			go func() {
				value, err := browser.Acquire(ctx, acquireOptions(server.URL))
				finished <- acquisitionResult{value, err}
			}()
			var process acquireProcess
			select {
			case process = <-started:
			case err := <-observed:
				t.Fatal(err)
			case result := <-finished:
				t.Fatalf("acquisition ended before process observation: %v", result.err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if exit {
				if err := process.process.Kill(); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			select {
			case result := <-finished:
				if result.err == nil || result.assertion != "" {
					t.Fatalf("interrupted acquisition unexpectedly succeeded: %#v", result)
				}
				if !exit && !errors.Is(result.err, context.Canceled) {
					t.Fatalf("cancellation was not preserved: %v", result.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("interrupted acquisition failed to settle promptly")
			}
			acquireAssertStopped(t, process, true)
		})
	}
}

func TestBrowserFlowPersistentLockCancellation(t *testing.T) {
	acquireEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html>Holding a private session</html>")
	}))
	defer server.Close()
	browser := acquireBrowser()
	started := make(chan struct{}, 1)
	browser.deps.onStarted = func(context.Context) { started <- struct{}{} }
	opts := acquireOptions(server.URL)
	opts.RememberMe = true
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := browser.Acquire(ctx, opts); finished <- err }()
	select {
	case <-started:
	case err := <-finished:
		t.Fatalf("first browser did not acquire its lock: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitingCtx, stopWaiting := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer stopWaiting()
	_, err := acquireBrowser().Acquire(waitingCtx, opts)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("profile lock waiter did not respect cancellation: %v", err)
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("profile owner did not terminate")
	}
	lockCtx, stopLock := context.WithTimeout(context.Background(), time.Second)
	defer stopLock()
	_, release, err := browserProfile(lockCtx, opts)
	if err != nil {
		t.Fatalf("profile lock was not released: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

type acquireProxy struct {
	server        *httptest.Server
	challenges    atomic.Int32
	authenticated atomic.Int32
	mu            sync.Mutex
	connections   map[net.Conn]bool
	workers       sync.WaitGroup
	closed        bool
}

func acquireCONNECTProxy(t *testing.T, allowedHost, upstream, username, password string) *acquireProxy {
	t.Helper()
	proxy := &acquireProxy{connections: make(map[net.Conn]bool)}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	proxy.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != allowedHost {
			http.Error(w, "fixture forbids unexpected proxy destination", http.StatusBadGateway)
			return
		}
		if r.Header.Get("Proxy-Authorization") != wantAuth {
			proxy.challenges.Add(1)
			w.Header().Set("Proxy-Authenticate", `Basic realm="synthetic proxy"`)
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		proxy.authenticated.Add(1)
		upstreamConn, err := net.DialTimeout("tcp", upstream, 3*time.Second)
		if err != nil {
			http.Error(w, "fixture upstream unavailable", http.StatusBadGateway)
			return
		}
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstreamConn.Close()
			return
		}
		proxy.mu.Lock()
		if proxy.closed {
			proxy.mu.Unlock()
			client.Close()
			upstreamConn.Close()
			return
		}
		proxy.connections[client], proxy.connections[upstreamConn] = true, true
		proxy.workers.Add(1)
		proxy.mu.Unlock()
		defer proxy.workers.Done()
		defer func() {
			client.Close()
			upstreamConn.Close()
			proxy.mu.Lock()
			delete(proxy.connections, client)
			delete(proxy.connections, upstreamConn)
			proxy.mu.Unlock()
		}()
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := buffered.Flush(); err != nil {
			return
		}
		copied := make(chan struct{})
		go func() { _, _ = io.Copy(upstreamConn, buffered); upstreamConn.Close(); close(copied) }()
		_, _ = io.Copy(client, upstreamConn)
		client.Close()
		<-copied
	}))
	t.Cleanup(func() {
		proxy.server.Close()
		proxy.mu.Lock()
		proxy.closed = true
		for connection := range proxy.connections {
			connection.Close()
		}
		proxy.mu.Unlock()
		proxy.workers.Wait()
	})
	return proxy
}

func TestBrowserFlowProxyCONNECTBasicAuthAndBypass(t *testing.T) {
	for _, bypass := range []bool{false, true} {
		name := "proxy"
		if bypass {
			name = "bypass"
		}
		t.Run(name, func(t *testing.T) {
			acquireEnvironment(t)
			var pages, forwarded atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/saml" {
					forwarded.Add(1)
					return
				}
				pages.Add(1)
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, acquireForm("proxy-fixture-assertion"))
			}))
			defer server.Close()
			_, port, err := net.SplitHostPort(server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			target := net.JoinHostPort("fixture.test", port)
			proxy := acquireCONNECTProxy(t, target, server.Listener.Addr().String(), "synthetic-user", "synthetic-proxy-password")
			proxyURL, _ := url.Parse(proxy.server.URL)
			proxyURL.User = url.UserPassword("synthetic-user", "synthetic-proxy-password")
			t.Setenv("https_proxy", proxyURL.String())
			if bypass {
				t.Setenv("no_proxy", "fixture.test")
			}
			browser := acquireBrowser()
			pin := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
			// Only this private fixture constructor can pin a throwaway certificate.
			browser.deps.allocatorOptions = []chromedp.ExecAllocatorOption{
				chromedp.Flag("ignore-certificate-errors-spki-list", base64.StdEncoding.EncodeToString(pin[:])),
				chromedp.Flag("host-resolver-rules", "MAP fixture.test 127.0.0.1"),
			}
			var process acquireProcess
			var observationErr error
			browser.deps.onStarted = func(ctx context.Context) {
				process, observationErr = acquireObserveProcess(ctx)
				if observationErr != nil {
					return
				}
				for _, name := range []string{"cmdline", "environ"} {
					data, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", process.process.Pid, name))
					if err != nil {
						observationErr = err
						return
					}
					if strings.Contains(string(data), "synthetic-proxy-password") {
						observationErr = errors.New("proxy password exposed in Chromium arguments or environment")
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			got, err := browser.Acquire(ctx, acquireOptions("https://"+target))
			if err != nil || got != "proxy-fixture-assertion" {
				t.Fatalf("proxy flow = %q, %v", got, err)
			}
			if observationErr != nil {
				t.Fatal(observationErr)
			}
			if pages.Load() == 0 || forwarded.Load() != 0 {
				t.Fatal("proxy fixture did not load the real page or leaked the assertion")
			}
			if bypass && (proxy.authenticated.Load() != 0 || proxy.challenges.Load() != 0) {
				t.Fatal("no_proxy did not bypass the actual CONNECT proxy")
			}
			if !bypass && (proxy.authenticated.Load() == 0 || proxy.challenges.Load() == 0) {
				t.Fatal("browser did not route through and authenticate to the CONNECT proxy")
			}
			acquireAssertStopped(t, process, true)
		})
	}
}

func TestBrowserFlowProxyCredentialsNeverAnswerOriginChallenge(t *testing.T) {
	acquireEnvironment(t)
	var originCredentials atomic.Bool
	var originRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originRequests.Add(1)
		if r.Header.Get("Authorization") != "" {
			originCredentials.Store(true)
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="not the proxy"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	target := net.JoinHostPort("fixture.test", port)
	proxy := acquireCONNECTProxy(t, target, server.Listener.Addr().String(), "synthetic-user", "synthetic-proxy-password")
	proxyURL, _ := url.Parse(proxy.server.URL)
	proxyURL.User = url.UserPassword("synthetic-user", "synthetic-proxy-password")
	t.Setenv("https_proxy", proxyURL.String())
	browser := acquireBrowser()
	browser.deps.statePolicy.unknownTimeout = 250 * time.Millisecond
	pin := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	browser.deps.allocatorOptions = []chromedp.ExecAllocatorOption{
		chromedp.Flag("ignore-certificate-errors-spki-list", base64.StdEncoding.EncodeToString(pin[:])),
		chromedp.Flag("host-resolver-rules", "MAP fixture.test 127.0.0.1"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := browser.Acquire(ctx, acquireOptions("https://"+target))
	if err == nil || got != "" {
		t.Fatal("origin authentication fixture unexpectedly acquired an assertion")
	}
	if proxy.authenticated.Load() == 0 || originRequests.Load() == 0 {
		t.Fatal("origin challenge was not reached through the authenticated proxy")
	}
	if originCredentials.Load() {
		t.Fatal("proxy credentials were disclosed to an origin server")
	}
}

func TestBrowserFlowProductionRejectsLoopbackEndpoint(t *testing.T) {
	acquireEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := (Browser{}).Acquire(ctx, acquireOptions(server.URL))
	if err == nil || got != "" || requests.Load() != 0 {
		t.Fatal("production browser accepted an insecure loopback authentication endpoint")
	}
}

func TestBrowserFlowTLSVerificationRemainsEnabled(t *testing.T) {
	acquireEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, acquireForm("must-not-be-acquired"))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Allow the endpoint through the loopback-only fixture seam, but do not pin
	// its certificate: Chromium must still reject this untrusted TLS connection.
	got, err := acquireBrowser().Acquire(ctx, acquireOptions(server.URL))
	if err == nil || got != "" || requests.Load() != 0 {
		t.Fatal("Chromium accepted an untrusted TLS certificate")
	}
}
