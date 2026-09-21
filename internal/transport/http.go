package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
)

type Options struct {
	// NoVerifySSL is an explicit STS-only insecure opt-in. Callers must warn.
	NoVerifySSL bool
}

// NewHTTPClient never falls back to direct connections or insecure TLS after a
// configuration error. Browser TLS must not use this STS-only configuration.
func NewHTTPClient(options Options) (*http.Client, error) {
	proxy, err := ResolveProxy()
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.NoVerifySSL} // Explicit compatibility opt-in only.
	if path := os.Getenv("AWS_CA_BUNDLE"); path != "" {
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, errors.New("cannot read AWS_CA_BUNDLE certificate file")
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("cannot load system certificate pool for AWS_CA_BUNDLE")
		}
		count := 0
		for len(bytes.TrimSpace(contents)) != 0 {
			contents = bytes.TrimSpace(contents)
			if !bytes.HasPrefix(contents, []byte("-----BEGIN CERTIFICATE-----")) {
				return nil, errors.New("AWS_CA_BUNDLE must contain valid PEM certificates")
			}
			block, rest := pem.Decode(contents)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return nil, errors.New("AWS_CA_BUNDLE contains an invalid PEM certificate")
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("AWS_CA_BUNDLE contains an invalid certificate")
			}
			pool.AddCert(certificate)
			count++
			contents = rest
		}
		if count == 0 {
			return nil, errors.New("AWS_CA_BUNDLE contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = proxy.ForRequest
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("STS redirect refused")
		},
	}, nil
}
