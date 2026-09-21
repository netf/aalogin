package sts

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aalogin/internal/saml"
)

var fixtureRole = saml.Role{
	RoleARN:      "arn:aws:iam::123456789012:role/Synthetic",
	PrincipalARN: "arn:aws:iam::123456789012:saml-provider/Synthetic",
}

func isolatedTransport(t *testing.T) {
	t.Helper()
	for _, key := range []string{"https_proxy", "HTTPS_PROXY", "no_proxy", "NO_PROXY", "AWS_CA_BUNDLE"} {
		t.Setenv(key, "")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "SHOULD_NOT_SIGN")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SHOULD_NOT_LOAD_SECRET")
	t.Setenv("AWS_SESSION_TOKEN", "SHOULD_NOT_LOAD_TOKEN")
	t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:1")
	t.Setenv("AWS_ENDPOINT_URL_STS", "http://127.0.0.1:1")
}

func credentialXML(expiration, token string) string {
	return fmt.Sprintf(`<AssumeRoleWithSAMLResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithSAMLResult><Credentials><AccessKeyId>SYNTHETIC_ACCESS</AccessKeyId><SecretAccessKey>SYNTHETIC_SECRET</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithSAMLResult><ResponseMetadata><RequestId>fixture-request-123</RequestId></ResponseMetadata></AssumeRoleWithSAMLResponse>`, token, expiration)
}

func TestExchangeUsesUnsignedQueryAndRequestedDuration(t *testing.T) {
	isolatedTransport(t)
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || r.Header.Get("X-Amz-Security-Token") != "" {
			t.Error("STS request was not an anonymous POST")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		for key, want := range map[string]string{"Action": "AssumeRoleWithSAML", "Version": "2011-06-15", "RoleArn": fixtureRole.RoleARN, "PrincipalArn": fixtureRole.PrincipalARN, "DurationSeconds": "2345", "SAMLAssertion": "SYNTHETIC_ASSERTION"} {
			if r.PostForm.Get(key) != want {
				t.Errorf("incorrect %s parameter", key)
			}
		}
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, credentialXML(expires.Format(time.RFC3339), "SYNTHETIC_SESSION"))
	}))
	defer server.Close()
	credentials, err := (Client{endpoint: server.URL}).Exchange(context.Background(), "SYNTHETIC_ASSERTION", fixtureRole, 2345, "us-east-1", TransportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if credentials.AccessKeyID != "SYNTHETIC_ACCESS" || credentials.SecretAccessKey != "SYNTHETIC_SECRET" || credentials.SessionToken != "SYNTHETIC_SESSION" || !credentials.Expiration.Equal(expires) {
		t.Fatalf("unexpected synthetic credentials: %#v", credentials)
	}
	if requests.Load() != 1 {
		t.Fatalf("unexpected requests: %d", requests.Load())
	}
}

func TestExchangeRejectsIncompleteResponsesAndKeepsDiagnosticsSafe(t *testing.T) {
	isolatedTransport(t)
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	secret := "DO_NOT_PRINT_ASSERTION_PASSWORD_SESSION_TOKEN"
	for _, item := range []struct {
		name     string
		status   int
		body     string
		wantCode bool
	}{
		{"service rejection", 400, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>` + secret + `</Message></Error><RequestId>fixture-request-123</RequestId></ErrorResponse>`, true},
		{"incomplete credentials", 200, credentialXML(expires, ""), false},
		{"expired credentials", 200, credentialXML("2001-01-01T00:00:00Z", secret), false},
		{"no credentials", 200, `<AssumeRoleWithSAMLResponse><AssumeRoleWithSAMLResult/></AssumeRoleWithSAMLResponse>`, false},
		{"invalid XML", 200, `<AssumeRoleWithSAMLResponse>` + secret, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "text/xml")
				w.WriteHeader(item.status)
				fmt.Fprint(w, item.body)
			}))
			defer server.Close()
			credentials, err := (Client{endpoint: server.URL}).Exchange(context.Background(), secret, fixtureRole, 43200, "us-east-1", TransportOptions{})
			if err == nil || credentials != (Credentials{}) {
				t.Fatalf("unsuccessful exchange yielded credentials: %#v, %v", credentials, err)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "SYNTHETIC_SECRET") || strings.Contains(err.Error(), "SHOULD_NOT_LOAD") {
				t.Fatalf("secret in diagnostic: %v", err)
			}
			if item.wantCode && (!strings.Contains(err.Error(), "InvalidIdentityToken") || !strings.Contains(err.Error(), "fixture-request-123")) {
				t.Fatalf("missing safe error metadata: %v", err)
			}
			if item.wantCode && requests.Load() != 1 {
				t.Fatalf("rejected duration/assertion retried: %d requests", requests.Load())
			}
		})
	}
}

func TestExchangeRefusesRedirectAndInvalidInputs(t *testing.T) {
	isolatedTransport(t)
	var forwarded atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); w.WriteHeader(500) }))
	defer sink.Close()
	var requests atomic.Int32
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Location", sink.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client := Client{endpoint: redirect.URL}
	_, err := client.Exchange(context.Background(), "synthetic", fixtureRole, 3600, "us-east-1", TransportOptions{})
	if err == nil || forwarded.Load() != 0 {
		t.Fatalf("assertion followed redirect: %v, forwarded %d", err, forwarded.Load())
	}
	before := requests.Load()
	for _, duration := range []int32{899, 43201} {
		if _, err := client.Exchange(context.Background(), "synthetic", fixtureRole, duration, "us-east-1", TransportOptions{}); err == nil {
			t.Fatal("invalid duration accepted")
		}
	}
	if _, err := client.Exchange(context.Background(), "synthetic", fixtureRole, 3600, "cn-north-1", TransportOptions{}); err == nil {
		t.Fatal("cross-partition role accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Exchange(ctx, "synthetic", fixtureRole, 3600, "us-east-1", TransportOptions{}); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
	if requests.Load() != before {
		t.Fatal("invalid inputs reached the network")
	}
}
