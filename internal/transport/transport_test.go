package transport

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func clearEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY", "AWS_CA_BUNDLE"} {
		t.Setenv(name, "")
	}
}

func TestProxyPrecedenceBypassAndChallengeBoundaries(t *testing.T) {
	clearEnvironment(t)
	t.Setenv("https_proxy", "https://synthetic-user:synthetic-pass@proxy.example:443")
	t.Setenv("HTTPS_PROXY", "http://other.example:80")
	t.Setenv("no_proxy", ".example.org,exact.test:8443,10.0.0.0/8,[::1]:443")
	t.Setenv("NO_PROXY", "ignored.example")
	proxy, err := ResolveProxy()
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Server() != "https://proxy.example:443" || strings.Contains(proxy.BypassList(), "ignored.example") {
		t.Fatalf("incorrect proxy precedence: %s %s", proxy.Server(), proxy.BypassList())
	}
	for _, item := range []struct {
		url    string
		direct bool
	}{
		{"https://example.org", true}, {"https://child.example.org", true}, {"https://notexample.org", false},
		{"https://exact.test:8443", true}, {"https://exact.test", false}, {"https://10.2.3.4", true},
		{"https://[::1]", true}, {"https://[::1]:8443", false}, {"https://ignored.example", false},
	} {
		request, _ := http.NewRequest(http.MethodGet, item.url, nil)
		endpoint, err := proxy.ForRequest(request)
		if err != nil || (endpoint == nil) != item.direct {
			t.Fatalf("incorrect routing for %s: %v, %v", item.url, endpoint != nil, err)
		}
	}
	for _, item := range []struct {
		source, origin string
		allowed        bool
	}{
		{"Proxy", "https://proxy.example", true}, {"Proxy", "https://PROXY.example:443/", true},
		{"Server", "https://proxy.example:443", false}, {"Proxy", "http://proxy.example:443", false},
		{"Proxy", "https://other.example:443", false}, {"Proxy", "https://proxy.example:444", false},
		{"Proxy", "https://proxy.example:443/login", false},
	} {
		username, password, ok := proxy.CredentialsForChallenge(item.source, item.origin)
		if ok != item.allowed || ok && (username != "synthetic-user" || password != "synthetic-pass") || !ok && (username != "" || password != "") {
			t.Fatalf("incorrect proxy challenge authorization for %s %s", item.source, item.origin)
		}
	}
	t.Setenv("https_proxy", "")
	proxy, err = ResolveProxy()
	if err != nil || proxy.Server() != "http://other.example:80" {
		t.Fatalf("uppercase fallback failed: %v", err)
	}
	t.Setenv("HTTPS_PROXY", "")
	proxy, err = ResolveProxy()
	if err != nil || proxy.Server() != "" {
		t.Fatalf("direct fallback failed: %v", err)
	}
}

func TestProxyConfigurationRejectsInvalidValuesWithoutEchoingSecrets(t *testing.T) {
	clearEnvironment(t)
	for _, value := range []string{"socks5://PRIVATE_PASSWORD@proxy.test:1080", "http://PRIVATE_PASSWORD@proxy.test:99999", "http://PRIVATE_PASSWORD@proxy.test/path", "http://PRIVATE_PASSWORD@proxy.test?query", "http://PRIVATE_PASSWORD@proxy.test:", "not-a-url-PRIVATE_PASSWORD"} {
		t.Setenv("https_proxy", value)
		if _, err := ResolveProxy(); err == nil || strings.Contains(err.Error(), "PRIVATE_PASSWORD") {
			t.Fatalf("invalid proxy was accepted or leaked: %v", err)
		}
	}
	t.Setenv("https_proxy", "http://proxy.test")
	for _, value := range []string{"https://host.test", "host.test:abc", "10.0.0.0/999", "host.*.test"} {
		t.Setenv("no_proxy", value)
		if _, err := ResolveProxy(); err == nil {
			t.Fatalf("invalid bypass accepted: %s", value)
		}
	}
}

func TestProxyCONNECTAuthenticationAndBypass(t *testing.T) {
	for _, secureProxy := range []bool{false, true} {
		t.Run(fmt.Sprintf("HTTPSProxy=%t", secureProxy), func(t *testing.T) {
			clearEnvironment(t)
			var targetRequests, proxyRequests atomic.Int32
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetRequests.Add(1)
				fmt.Fprint(w, "synthetic response")
			}))
			defer target.Close()
			targetURL, _ := url.Parse(target.URL)
			proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxyRequests.Add(1)
				if r.Method != http.MethodConnect || r.Host != targetURL.Host {
					t.Error("unexpected proxy route")
					w.WriteHeader(400)
					return
				}
				if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("synthetic-user:synthetic-pass")) {
					w.WriteHeader(http.StatusProxyAuthRequired)
					return
				}
				upstream, err := net.Dial("tcp", targetURL.Host)
				if err != nil {
					t.Error(err)
					w.WriteHeader(502)
					return
				}
				client, buffer, err := w.(http.Hijacker).Hijack()
				if err != nil {
					upstream.Close()
					t.Error(err)
					return
				}
				fmt.Fprint(buffer, "HTTP/1.1 200 Connection Established\r\n\r\n")
				if err := buffer.Flush(); err != nil {
					upstream.Close()
					client.Close()
					return
				}
				go func() { defer upstream.Close(); defer client.Close(); io.Copy(upstream, buffer) }()
				io.Copy(client, upstream)
				upstream.Close()
				client.Close()
			})
			var proxyServer *httptest.Server
			if secureProxy {
				proxyServer = httptest.NewTLSServer(proxyHandler)
			} else {
				proxyServer = httptest.NewServer(proxyHandler)
			}
			defer proxyServer.Close()
			bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw})
			if secureProxy {
				bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxyServer.Certificate().Raw})...)
			}
			bundlePath := filepath.Join(t.TempDir(), "bundle.pem")
			if err := os.WriteFile(bundlePath, bundle, 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("AWS_CA_BUNDLE", bundlePath)
			proxyURL, _ := url.Parse(proxyServer.URL)
			proxyURL.User = url.UserPassword("synthetic-user", "synthetic-pass")
			t.Setenv("https_proxy", proxyURL.String())
			request := func() {
				t.Helper()
				client, err := NewHTTPClient(Options{})
				if err != nil {
					t.Fatal(err)
				}
				defer client.CloseIdleConnections()
				response, err := client.Get(target.URL)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil || string(body) != "synthetic response" {
					t.Fatalf("proxy response failed: %v", err)
				}
			}
			request()
			if proxyRequests.Load() != 1 || targetRequests.Load() != 1 {
				t.Fatal("proxy route did not reach target exactly once")
			}
			t.Setenv("no_proxy", targetURL.Host)
			request()
			if proxyRequests.Load() != 1 || targetRequests.Load() != 2 {
				t.Fatal("bypass did not connect directly")
			}
			t.Setenv("no_proxy", "")
			proxyURL.User = url.UserPassword("synthetic-user", "wrong-pass")
			t.Setenv("https_proxy", proxyURL.String())
			client, err := NewHTTPClient(Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			if response, err := client.Get(target.URL); err == nil {
				response.Body.Close()
				t.Fatal("proxy authentication failure was ignored")
			}
			if targetRequests.Load() != 2 {
				t.Fatal("proxy auth failure fell back to direct")
			}
		})
	}
}

func TestCABundleValidationAndExplicitInsecureOptIn(t *testing.T) {
	clearEnvironment(t)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer target.Close()
	client, err := NewHTTPClient(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if response, err := client.Get(target.URL); err == nil {
		response.Body.Close()
		t.Fatal("untrusted TLS certificate accepted by default")
	}
	client, err = NewHTTPClient(Options{NoVerifySSL: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("explicit insecure opt-in failed: %v", err)
	}
	response.Body.Close()
	bundle := filepath.Join(t.TempDir(), "bad.pem")
	for _, contents := range []string{"", "not a certificate", "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"} {
		if err := os.WriteFile(bundle, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWS_CA_BUNDLE", bundle)
		if _, err := NewHTTPClient(Options{NoVerifySSL: true}); err == nil {
			t.Fatal("invalid CA bundle silently ignored")
		}
	}
	t.Setenv("AWS_CA_BUNDLE", filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := NewHTTPClient(Options{}); err == nil {
		t.Fatal("unreadable CA bundle silently ignored")
	}
}
