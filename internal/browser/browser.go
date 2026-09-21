// Package browser acquires SAML assertions in a private, owned Chromium process.
package browser

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aalogin/internal/cli"
	"aalogin/internal/transport"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"golang.org/x/sys/unix"
)

const maxFormBody = 1 << 20
const maxAssertion = 100000

// Options contains only browser authentication settings; browser TLS is never optional.
type Options struct {
	Executable, Mode, Tenant, Username, Password, LoginURL, ACS string
	RememberMe, NoPrompt, CredentialProcess, NoSandbox          bool
	EnableChromeNetworkService, EnableChromeSeamlessSSO         bool
	NoDisableExtensions, DisableGPU                             bool
	TrustedLoginHosts                                           []string
	Prompt                                                      *cli.Prompt
	Out                                                         io.Writer
}

// Browser never attaches to an existing browser. Its zero value is ready to use.
type Browser struct {
	deps *browserDependencies
}

// These dependencies are deliberately private: only package integration fixtures
// can allow loopback endpoints, alter state timing or observe the owned process.
type browserDependencies struct {
	statePolicy      statePolicy
	allowEndpoint    func(*url.URL) bool
	allocatorOptions []chromedp.ExecAllocatorOption
	onStarted        func(context.Context)
}

type acquisitionResult struct {
	assertion string
	err       error
}

// Acquire intercepts a single SAML POST without sending it to the AWS console.
// The caller's deadline bounds startup, authentication and persistent-profile locking.
func (b Browser) Acquire(ctx context.Context, opts Options) (assertion string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if opts.Mode == "" {
		opts.Mode = "cli"
	}
	if opts.Mode != "cli" && opts.Mode != "gui" && opts.Mode != "debug" {
		return "", errors.New("invalid browser mode; use cli, gui or debug")
	}
	if opts.CredentialProcess {
		opts.NoPrompt = true
		if opts.Mode != "cli" {
			return "", errors.New("credential process requires cli browser mode")
		}
	}
	if opts.Mode != "cli" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return "", errors.New("visible browser requires DISPLAY or WAYLAND_DISPLAY; use --mode cli")
	}
	executable, err := browserExecutable(opts.Executable)
	if err != nil {
		return "", err
	}
	_, err = b.endpoint(opts.LoginURL, false, opts.TrustedLoginHosts)
	if err != nil {
		return "", err
	}
	acs, err := b.endpoint(opts.ACS, true, nil)
	if err != nil {
		return "", err
	}
	proxy, err := transport.ResolveProxy()
	if err != nil {
		return "", err
	}
	profile, release, err := browserProfile(ctx, opts)
	if err != nil {
		return "", err
	}
	defer func() {
		if cleanupErr := release(); err == nil && cleanupErr != nil {
			assertion = ""
			err = cleanupErr
		}
	}()
	if err := disablePasswordSaving(profile); err != nil {
		return "", err
	}

	allocatorOpts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(executable), chromedp.UserDataDir(profile),
		chromedp.NoFirstRun, chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", opts.Mode == "cli"),
		// Always specify false too: chromedp otherwise disables the sandbox as root.
		chromedp.Flag("no-sandbox", opts.NoSandbox),
		chromedp.Flag("disable-extensions", !opts.NoDisableExtensions),
		chromedp.Flag("disable-gpu", opts.DisableGPU),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-save-password-bubble", true),
		chromedp.Flag("lang", "en"),
		chromedp.Flag("no-proxy-server", proxy.Server() == ""),
		// Discard Chromium diagnostics: they may contain credential-bearing URLs.
		chromedp.CombinedOutput(io.Discard),
		chromedp.Env(scrubbedBrowserEnvironment()...),
	}
	if proxy.Server() != "" {
		allocatorOpts = append(allocatorOpts,
			chromedp.Flag("proxy-server", proxy.Server()),
			chromedp.Flag("proxy-bypass-list", proxy.BypassList()))
	}
	if opts.EnableChromeNetworkService {
		allocatorOpts = append(allocatorOpts, chromedp.Flag("enable-features", "NetworkService"))
	}
	if opts.EnableChromeSeamlessSSO {
		allocatorOpts = append(allocatorOpts,
			chromedp.Flag("auth-server-allowlist", "autologon.microsoftazuread-sso.com"),
			chromedp.Flag("auth-negotiate-delegate-allowlist", "autologon.microsoftazuread-sso.com"))
	}
	policy := statePolicy{}
	if b.deps != nil {
		allocatorOpts = append(allocatorOpts, b.deps.allocatorOptions...)
		policy = b.deps.statePolicy
	}
	allocatorCtx, stopAllocator := chromedp.NewExecAllocator(ctx, allocatorOpts...)
	browserCtx, stopBrowser := chromedp.NewContext(allocatorCtx,
		chromedp.WithLogf(func(string, ...any) {}),
		chromedp.WithErrorf(func(string, ...any) {}))
	workCtx, stopWork := context.WithCancel(browserCtx)
	var workers sync.WaitGroup
	defer func() {
		stopWork()
		workers.Wait()
		// A graceful successful shutdown flushes remembered cookies. Cancellation
		// still kills the owned browser, and allocator cancellation waits for reaping.
		if chromedp.FromContext(browserCtx).Browser != nil {
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(browserCtx), 3*time.Second)
			_ = chromedp.Cancel(shutdownCtx)
			cancel()
		}
		stopBrowser()
		stopAllocator()
	}()
	if err := chromedp.Run(browserCtx); err != nil {
		return "", browserFailure(ctx, "could not start Chromium; check --browser and sandbox support (use --no-sandbox only when deliberately required)")
	}

	results := make(chan acquisitionResult, 1)
	var once sync.Once
	finish := func(value string, failure error) {
		once.Do(func() { results <- acquisitionResult{value, failure} })
	}
	// Listener callbacks run synchronously on the CDP event dispatcher. Never
	// execute CDP commands there: bounded dispatch to this owned worker avoids deadlock.
	events := make(chan any, 128)
	chromedp.ListenTarget(workCtx, func(event any) {
		switch event.(type) {
		case *fetch.EventRequestPaused, *fetch.EventAuthRequired:
			select {
			case events <- event:
			case <-workCtx.Done():
			default:
				finish("", errors.New("browser request queue overflow; authentication stopped safely"))
			}
		}
	})
	executorCtx := cdp.WithExecutor(workCtx, chromedp.FromContext(browserCtx).Target)
	workers.Add(1)
	go func() {
		defer workers.Done()
		authAttempts := make(map[fetch.RequestID]bool)
		for {
			select {
			case <-workCtx.Done():
				return
			case event := <-events:
				switch event := event.(type) {
				case *fetch.EventAuthRequired:
					response := &fetch.AuthChallengeResponse{Response: fetch.AuthChallengeResponseResponseCancelAuth}
					challenge := event.AuthChallenge
					if challenge != nil && strings.EqualFold(challenge.Scheme, "basic") && !authAttempts[event.RequestID] && len(authAttempts) < 64 {
						user, password, ok := proxy.CredentialsForChallenge(string(challenge.Source), challenge.Origin)
						if ok {
							authAttempts[event.RequestID] = true
							response.Response = fetch.AuthChallengeResponseResponseProvideCredentials
							response.Username, response.Password = user, password
						}
					}
					if challenge != nil && string(challenge.Source) == "Server" && opts.Mode == "gui" && strings.EqualFold(challenge.Scheme, "basic") {
						// GUI recovery leaves origin authentication to the operator.
						response.Response = fetch.AuthChallengeResponseResponseDefault
					}
					if challenge != nil && string(challenge.Source) == "Server" && opts.EnableChromeSeamlessSSO && strings.EqualFold(challenge.Scheme, "negotiate") {
						origin, parseErr := url.Parse(challenge.Origin)
						if parseErr == nil && origin.Scheme == "https" && strings.EqualFold(origin.Hostname(), "autologon.microsoftazuread-sso.com") && effectivePort(origin) == "443" && origin.User == nil {
							// Let Chromium use its explicitly allowlisted OS credentials;
							// never supply HTTP proxy credentials to an origin challenge.
							response.Response = fetch.AuthChallengeResponseResponseDefault
						}
					}
					if err := fetch.ContinueWithAuth(event.RequestID, response).Do(executorCtx); err != nil {
						finish("", browserFailure(ctx, "browser proxy authentication failed"))
						return
					}
				case *fetch.EventRequestPaused:
					if event.Request == nil {
						finish("", errors.New("browser returned an invalid intercepted request"))
						return
					}
					u, parseErr := url.Parse(event.Request.URL)
					if parseErr != nil || !strings.EqualFold(u.Hostname(), acs.Hostname()) || u.Path != "/saml" {
						if err := fetch.ContinueRequest(event.RequestID).Do(executorCtx); err != nil {
							finish("", browserFailure(ctx, "could not continue browser request"))
							return
						}
						continue
					}
					value, failure := callbackAssertion(executorCtx, event, u, acs)
					status, body := int64(200), "Authentication complete. You may close this window."
					if failure != nil {
						status, body = 400, "Authentication callback rejected."
					}
					fulfillErr := fetch.FulfillRequest(event.RequestID, status).
						WithResponseHeaders([]*fetch.HeaderEntry{
							{Name: "Content-Type", Value: "text/plain; charset=utf-8"},
							{Name: "Cache-Control", Value: "no-store"},
							{Name: "Content-Security-Policy", Value: "default-src 'none'"},
						}).WithBody(base64.StdEncoding.EncodeToString([]byte(body))).Do(executorCtx)
					if failure == nil && fulfillErr != nil {
						failure = browserFailure(ctx, "could not complete intercepted SAML callback")
					}
					finish(value, failure)
					return
				}
			}
		}
	}()
	if err := chromedp.Run(workCtx,
		network.Enable().WithMaxPostDataSize(maxFormBody),
		// Remember cookies, not cacheable sign-in pages containing assertions.
		network.SetCacheDisabled(true),
		network.SetExtraHTTPHeaders(network.Headers{"Accept-Language": "en"}),
		fetch.Enable().WithHandleAuthRequests(true)); err != nil {
		return "", browserFailure(ctx, "could not enable safe browser interception")
	}
	if b.deps != nil && b.deps.onStarted != nil {
		b.deps.onStarted(browserCtx)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := chromedp.Run(workCtx, chromedp.Navigate(opts.LoginURL)); err != nil {
			finish("", browserFailure(ctx, "browser navigation failed; check network, proxy and TLS configuration"))
			return
		}
		if opts.Mode != "gui" {
			if err := driveStates(workCtx, opts, policy); err != nil {
				finish("", err)
			}
		}
	}()
	select {
	case result := <-results:
		if result.err != nil {
			return "", result.err
		}
		return result.assertion, nil
	case <-ctx.Done():
		return "", ctx.Err()
	case <-browserCtx.Done():
		return "", browserFailure(ctx, "Chromium exited before completing authentication")
	}
}

func browserFailure(ctx context.Context, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New(message)
}

func browserExecutable(explicit string) (string, error) {
	candidate := explicit
	if candidate == "" {
		candidate = os.Getenv("CHROME_BIN")
	}
	if candidate != "" {
		path, err := exec.LookPath(candidate)
		if err == nil {
			if info, statErr := os.Stat(path); statErr == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
				return path, nil
			}
		}
		return "", errors.New("invalid Chromium executable; supply an executable with --browser or CHROME_BIN")
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", errors.New("Chromium was not found; install a browser and supply --browser or CHROME_BIN")
}

func (b Browser) endpoint(raw string, acs bool, trusted []string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid browser authentication endpoint")
	}
	if b.deps != nil && b.deps.allowEndpoint != nil && b.deps.allowEndpoint(u) {
		return u, nil
	}
	if u.Scheme != "https" || (u.Port() != "" && u.Port() != "443") {
		return nil, errors.New("browser authentication endpoints require HTTPS on the default port")
	}
	host := strings.ToLower(u.Hostname())
	if acs {
		if u.EscapedPath() != "/saml" || (host != "signin.aws.amazon.com" && host != "signin.amazonaws-us-gov.com" && host != "signin.amazonaws.cn") {
			return nil, errors.New("invalid AWS SAML callback endpoint")
		}
		return u, nil
	}
	if host == "login.microsoftonline.com" || host == "login.live.com" {
		return u, nil
	}
	for _, allowed := range trusted {
		if strings.EqualFold(host, allowed) {
			return u, nil
		}
	}
	return nil, errors.New("untrusted login endpoint; use a Microsoft login URL or an explicit --trusted-login-host")
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	if u.Scheme == "http" {
		return "80"
	}
	return ""
}

func callbackAssertion(ctx context.Context, event *fetch.EventRequestPaused, u, acs *url.URL) (string, error) {
	if u.Scheme != acs.Scheme || effectivePort(u) != effectivePort(acs) || u.User != nil || u.Fragment != "" || u.EscapedPath() != "/saml" {
		return "", errors.New("SAML callback used an invalid endpoint")
	}
	if event.Request.Method != "POST" {
		return "", errors.New("SAML callback must use POST")
	}
	var contentType string
	for name, value := range event.Request.Headers {
		if strings.EqualFold(name, "content-type") {
			contentType, _ = value.(string)
			break
		}
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return "", errors.New("SAML callback must use URL-encoded form data")
	}
	body, err := requestBody(ctx, event)
	if err != nil {
		return "", err
	}
	form, err := url.ParseQuery(body)
	if err != nil {
		return "", errors.New("SAML callback contains malformed form data")
	}
	values := form["SAMLResponse"]
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return "", errors.New("SAML callback requires exactly one nonempty SAMLResponse")
	}
	if len(values[0]) > maxAssertion {
		return "", errors.New("SAML assertion exceeds the 100000-character limit")
	}
	return values[0], nil
}

func requestBody(ctx context.Context, event *fetch.EventRequestPaused) (string, error) {
	if len(event.Request.PostDataEntries) != 0 {
		var body strings.Builder
		complete := true
		for _, entry := range event.Request.PostDataEntries {
			if entry == nil || entry.Bytes == "" {
				complete = false
				break
			}
			if base64.StdEncoding.DecodedLen(len(entry.Bytes)) > maxFormBody-body.Len()+2 {
				return "", errors.New("SAML callback form exceeds the 1 MiB limit")
			}
			decoded, err := base64.StdEncoding.DecodeString(entry.Bytes)
			if err != nil {
				return "", errors.New("browser returned malformed SAML callback data")
			}
			if len(decoded) > maxFormBody-body.Len() {
				return "", errors.New("SAML callback form exceeds the 1 MiB limit")
			}
			body.Write(decoded)
		}
		if complete {
			return body.String(), nil
		}
	}
	if event.NetworkID == "" {
		return "", errors.New("browser did not provide the SAML callback body")
	}
	body, err := network.GetRequestPostData(event.NetworkID).Do(ctx)
	if err != nil {
		return "", errors.New("could not obtain SAML callback body from Chromium")
	}
	if len(body) > maxFormBody {
		return "", errors.New("SAML callback form exceeds the 1 MiB limit")
	}
	return string(body), nil
}

func scrubbedBrowserEnvironment() []string {
	var overrides []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "AZURE_DEFAULT_PASSWORD", "AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
			// chromedp merges its environment with os.Environ; final empty
			// overrides remove secret values rather than accidentally re-inheriting them.
			overrides = append(overrides, name+"=")
		}
	}
	return overrides
}

func browserProfile(ctx context.Context, opts Options) (string, func() error, error) {
	if !opts.RememberMe {
		dir, err := os.MkdirTemp("", "aalogin-browser-")
		if err != nil {
			return "", nil, errors.New("could not create private temporary browser state")
		}
		return dir, func() error {
			if err := os.RemoveAll(dir); err != nil {
				return errors.New("could not remove temporary browser state")
			}
			return nil
		}, nil
	}
	root := os.Getenv("XDG_STATE_HOME")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", nil, errors.New("remembered browser state requires HOME or XDG_STATE_HOME")
		}
		root = filepath.Join(home, ".local", "state")
	}
	if !filepath.IsAbs(root) {
		return "", nil, errors.New("XDG_STATE_HOME must be an absolute path")
	}
	digest := sha256.Sum256([]byte(opts.Tenant + "\x00" + opts.Username))
	parent := filepath.Join(root, "aalogin")
	dir := filepath.Join(parent, "browser", hex.EncodeToString(digest[:]))
	for _, private := range []string{parent, filepath.Join(parent, "browser"), dir} {
		if err := privateDirectory(private); err != nil {
			return "", nil, err
		}
	}
	fd, err := unix.Open(filepath.Join(dir, ".aalogin.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return "", nil, errors.New("could not open private browser state lock")
	}
	lock := os.NewFile(uintptr(fd), "browser state lock")
	if err := lock.Chmod(0600); err != nil {
		lock.Close()
		return "", nil, errors.New("could not protect browser state lock")
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			lock.Close()
			return "", nil, err
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return dir, func() error {
				_ = unix.Flock(fd, unix.LOCK_UN)
				return lock.Close()
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			lock.Close()
			return "", nil, errors.New("could not lock private browser state")
		}
		select {
		case <-ctx.Done():
			lock.Close()
			return "", nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return errors.New("could not create private browser state directory")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("browser state directory must be a real private directory")
	}
	if err := os.Chmod(path, 0700); err != nil {
		return errors.New("could not protect browser state directory")
	}
	return nil
}

func disablePasswordSaving(dir string) error {
	profile := filepath.Join(dir, "Default")
	if err := privateDirectory(profile); err != nil {
		return err
	}
	path := filepath.Join(profile, "Preferences")
	preferences := make(map[string]json.RawMessage)
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("could not read private browser preferences")
	}
	if len(data) != 0 {
		if err := json.Unmarshal(data, &preferences); err != nil || preferences == nil {
			return errors.New("private browser preferences contain invalid JSON")
		}
	}
	profilePreferences := make(map[string]json.RawMessage)
	if old, ok := preferences["profile"]; ok {
		if err := json.Unmarshal(old, &profilePreferences); err != nil || profilePreferences == nil {
			return errors.New("private browser profile preferences contain invalid JSON")
		}
	}
	preferences["credentials_enable_service"] = json.RawMessage("false")
	profilePreferences["password_manager_enabled"] = json.RawMessage("false")
	profilePreferences["password_manager_leak_detection"] = json.RawMessage("false")
	preferences["profile"], err = json.Marshal(profilePreferences)
	if err != nil {
		return errors.New("could not prepare private browser preferences")
	}
	data, err = json.Marshal(preferences)
	if err != nil {
		return errors.New("could not prepare private browser preferences")
	}
	file, err := os.CreateTemp(profile, ".aalogin-preferences-")
	if err != nil {
		return errors.New("could not create private browser preferences")
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("could not write private browser preferences")
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return errors.New("could not install private browser preferences")
	}
	return nil
}
