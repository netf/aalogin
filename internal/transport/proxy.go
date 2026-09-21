// Package transport shares explicit proxy policy between Chromium and STS.
package transport

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Proxy struct {
	endpoint *url.URL
	bypass   []bypassRule
}

type bypassRule struct {
	host   string
	port   string
	prefix netip.Prefix
	all    bool
}

// ResolveProxy deliberately does not consult HTTP_PROXY or the platform proxy
// settings. The same HTTPS proxy and bypass rules apply to the browser and STS.
func ResolveProxy() (*Proxy, error) {
	proxy := &Proxy{}
	value := firstNonemptyEnv("https_proxy", "HTTPS_PROXY")
	if value != "" {
		endpoint, err := url.Parse(value)
		if err != nil || endpoint == nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.Opaque != "" || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawQuery != "" || endpoint.ForceQuery || strings.Contains(value, "#") || !validHost(endpoint.Hostname()) || (strings.Contains(endpoint.Hostname(), ":") && !strings.HasPrefix(endpoint.Host, "[")) {
			return nil, errors.New("https_proxy/HTTPS_PROXY must be a valid HTTP or HTTPS proxy URL")
		}
		if strings.HasSuffix(endpoint.Host, ":") || (endpoint.Port() != "" && !validPort(endpoint.Port())) {
			return nil, errors.New("https_proxy/HTTPS_PROXY contains an invalid proxy port")
		}
		endpoint.Path = ""
		endpoint.RawPath = ""
		proxy.endpoint = endpoint
	}
	value = firstNonemptyEnv("no_proxy", "NO_PROXY")
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		rule, err := parseBypass(entry)
		if err != nil {
			return nil, err
		}
		proxy.bypass = append(proxy.bypass, rule)
	}
	return proxy, nil
}

func firstNonemptyEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func parseBypass(entry string) (bypassRule, error) {
	invalid := errors.New("no_proxy/NO_PROXY must contain comma-separated hosts, host:port entries, IP addresses, CIDRs, or *")
	if entry == "*" {
		return bypassRule{all: true}, nil
	}
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		return bypassRule{prefix: prefix.Masked()}, nil
	}
	host, port := entry, ""
	if strings.HasPrefix(entry, "[") {
		if strings.HasSuffix(entry, "]") {
			host = entry[1 : len(entry)-1]
		} else {
			var err error
			host, port, err = net.SplitHostPort(entry)
			if err != nil || !validPort(port) {
				return bypassRule{}, invalid
			}
		}
	} else if strings.Count(entry, ":") == 1 {
		host, port, _ = strings.Cut(entry, ":")
		if !validPort(port) {
			return bypassRule{}, invalid
		}
	}
	host = strings.TrimPrefix(strings.TrimPrefix(host, "*."), ".")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if !validHost(host) {
		return bypassRule{}, invalid
	}
	if port != "" {
		number, _ := strconv.Atoi(port)
		port = strconv.Itoa(number)
	}
	return bypassRule{host: host, port: port}, nil
}

func validPort(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	number, err := strconv.Atoi(value)
	return err == nil && number > 0 && number <= 65535
}

func validHost(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == ""
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if char != '-' && (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
				return false
			}
		}
	}
	return true
}

// Server is safe for Chromium argv: it never contains a username or password.
func (proxy *Proxy) Server() string {
	if proxy == nil || proxy.endpoint == nil {
		return ""
	}
	return (&url.URL{Scheme: proxy.endpoint.Scheme, Host: proxy.endpoint.Host}).String()
}

// BypassList uses explicit rules rather than Chromium's implicit loopback bypass,
// so a proxy request has the same routing decision in Chromium and Go.
func (proxy *Proxy) BypassList() string {
	if proxy == nil || proxy.endpoint == nil {
		return ""
	}
	rules := []string{"<-loopback>"}
	for _, rule := range proxy.bypass {
		if rule.all {
			rules = append(rules, "*")
			continue
		}
		if rule.prefix.IsValid() {
			rules = append(rules, rule.prefix.String())
			continue
		}
		host := rule.host
		address, ip := netip.ParseAddr(host)
		if ip == nil && address.Is6() {
			host = "[" + address.String() + "]"
		}
		suffix := ""
		if rule.port != "" {
			suffix = ":" + rule.port
		}
		rules = append(rules, host+suffix)
		if ip != nil {
			rules = append(rules, "*."+host+suffix)
		}
	}
	return strings.Join(rules, ";")
}

func effectivePort(endpoint *url.URL) string {
	if port := endpoint.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err == nil {
			return strconv.Itoa(number)
		}
		return port
	}
	if endpoint.Scheme == "https" {
		return "443"
	}
	return "80"
}

// CredentialsForChallenge must be called with CDP's challenge source and origin.
// Origin HTTP auth never receives proxy credentials, even on an identical host.
func (proxy *Proxy) CredentialsForChallenge(source, origin string) (string, string, bool) {
	if proxy == nil || proxy.endpoint == nil || proxy.endpoint.User == nil || source != "Proxy" {
		return "", "", false
	}
	endpoint, err := url.Parse(origin)
	if err != nil || endpoint.User != nil || endpoint.Scheme != proxy.endpoint.Scheme || !strings.EqualFold(endpoint.Hostname(), proxy.endpoint.Hostname()) || effectivePort(endpoint) != effectivePort(proxy.endpoint) || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return "", "", false
	}
	password, _ := proxy.endpoint.User.Password()
	return proxy.endpoint.User.Username(), password, true
}

func (proxy *Proxy) ForRequest(request *http.Request) (*url.URL, error) {
	if proxy == nil || proxy.endpoint == nil {
		return nil, nil
	}
	host := strings.TrimSuffix(strings.ToLower(request.URL.Hostname()), ".")
	address, addressErr := netip.ParseAddr(host)
	for _, rule := range proxy.bypass {
		if rule.all {
			return nil, nil
		}
		if rule.port != "" && rule.port != effectivePort(request.URL) {
			continue
		}
		if rule.prefix.IsValid() {
			if addressErr == nil && rule.prefix.Contains(address) {
				return nil, nil
			}
			continue
		}
		if addressErr == nil {
			if bypassAddress, err := netip.ParseAddr(rule.host); err == nil && address == bypassAddress {
				return nil, nil
			}
		} else if host == rule.host || strings.HasSuffix(host, "."+rule.host) {
			return nil, nil
		}
	}
	return proxy.endpoint, nil
}
