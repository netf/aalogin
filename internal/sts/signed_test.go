package sts

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aalogin/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func sourceCredentials() Credentials {
	return Credentials{
		AccessKeyID: "SUPPLIED_ACCESS", SecretAccessKey: "SUPPLIED_SECRET", SessionToken: "SUPPLIED_TOKEN",
		Expiration: time.Now().Add(time.Hour),
	}
}

func roleStep() config.RoleStep {
	return config.RoleStep{
		RoleARN: fixtureRole.RoleARN, Region: "us-east-1", DurationSeconds: 3600,
		RoleSessionName: "fixture-session", ExternalID: "fixture-external",
	}
}

func assumeXML(expiration, token string) string {
	return strings.ReplaceAll(credentialXML(expiration, token), "AssumeRoleWithSAML", "AssumeRole")
}

func identityXML(account, arn string) string {
	return fmt.Sprintf(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>%s</Account><Arn>%s</Arn><UserId>fixture:session</UserId></GetCallerIdentityResult><ResponseMetadata><RequestId>fixture-request-123</RequestId></ResponseMetadata></GetCallerIdentityResponse>`, account, arn)
}

func TestSignedOperationsUseOnlySuppliedCredentials(t *testing.T) {
	isolatedTransport(t)
	source := sourceCredentials()
	step := roleStep()
	expires := time.Now().Add(37 * time.Minute).UTC().Truncate(time.Second)
	const callerARN = "arn:aws:sts::123456789012:assumed-role/Synthetic/fixture-session"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("X-Amz-Security-Token") != source.SessionToken {
			t.Error("request did not use the supplied session")
		}
		signedAt, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		if err != nil {
			t.Error("request has no valid signing date")
			w.WriteHeader(400)
			return
		}
		// Re-sign with the supplied secret: a credential-name-only check would
		// miss a signer accidentally loading a different secret from the environment.
		expected := r.Clone(context.Background())
		expected.URL.Scheme = "http"
		expected.URL.Host = r.Host
		expected.Header.Del("Authorization")
		_, signedHeaders, _ := strings.Cut(r.Header.Get("Authorization"), "SignedHeaders=")
		signedHeaders, _, _ = strings.Cut(signedHeaders, ",")
		for name := range expected.Header {
			if !strings.Contains(";"+signedHeaders+";", ";"+strings.ToLower(name)+";") {
				expected.Header.Del(name)
			}
		}
		digest := sha256.Sum256(body)
		err = v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{
			AccessKeyID: source.AccessKeyID, SecretAccessKey: source.SecretAccessKey, SessionToken: source.SessionToken,
		}, expected, fmt.Sprintf("%x", digest), "sts", step.Region, signedAt)
		if err != nil || r.Header.Get("Authorization") != expected.Header.Get("Authorization") {
			t.Error("request signature does not match supplied credentials")
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if r.PostForm.Get("Version") != "2011-06-15" {
			t.Error("unexpected STS API version")
		}
		w.Header().Set("Content-Type", "text/xml")
		switch r.PostForm.Get("Action") {
		case "AssumeRole":
			for key, want := range map[string]string{"RoleArn": step.RoleARN, "RoleSessionName": step.RoleSessionName, "ExternalId": step.ExternalID, "DurationSeconds": "3600"} {
				if r.PostForm.Get(key) != want {
					t.Errorf("incorrect %s parameter", key)
				}
			}
			fmt.Fprint(w, assumeXML(expires.Format(time.RFC3339), "SYNTHETIC_SESSION"))
		case "GetCallerIdentity":
			fmt.Fprint(w, identityXML("123456789012", callerARN))
		default:
			t.Error("unexpected STS operation")
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	client := Client{endpoint: server.URL}
	creds, err := client.Assume(context.Background(), source, step, TransportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "SYNTHETIC_ACCESS" || creds.SecretAccessKey != "SYNTHETIC_SECRET" || creds.SessionToken != "SYNTHETIC_SESSION" || !creds.Expiration.Equal(expires) {
		t.Fatal("AssumeRole did not return the actual temporary credentials and expiration")
	}
	identity, err := client.Identity(context.Background(), source, step.Region, TransportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if identity != (Identity{Account: "123456789012", ARN: callerARN}) || requests.Load() != 2 {
		t.Fatalf("unexpected identity or request count: %#v, %d", identity, requests.Load())
	}
}

func TestSignedOperationsRejectUnsafeResponsesWithoutRetry(t *testing.T) {
	isolatedTransport(t)
	const secret = "DO_NOT_PRINT_SOURCE_SECRET_OR_SESSION_TOKEN"
	for _, operation := range []string{"AssumeRole", "GetCallerIdentity"} {
		for _, item := range []struct {
			name   string
			status int
			body   string
			code   string
		}{
			{"rejected authentication", 403, `<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>` + secret + `</Message></Error><RequestId>fixture-request-123</RequestId></ErrorResponse>`, "InvalidClientTokenId"},
			{"retryable service error", 500, `<ErrorResponse><Error><Code>InternalFailure</Code><Message>` + secret + `</Message></Error><RequestId>fixture-request-123</RequestId></ErrorResponse>`, "InternalFailure"},
			{"malformed XML", 200, "<" + secret, ""},
			{"missing result", 200, "<" + operation + "Response/>", ""},
		} {
			t.Run(operation+"/"+item.name, func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					w.Header().Set("Content-Type", "text/xml")
					w.WriteHeader(item.status)
					fmt.Fprint(w, item.body)
				}))
				defer server.Close()
				client := Client{endpoint: server.URL}
				var err error
				if operation == "AssumeRole" {
					var result Credentials
					result, err = client.Assume(context.Background(), sourceCredentials(), roleStep(), TransportOptions{})
					if result != (Credentials{}) {
						t.Fatal("failed AssumeRole returned credentials")
					}
				} else {
					var result Identity
					result, err = client.Identity(context.Background(), sourceCredentials(), "us-east-1", TransportOptions{})
					if result != (Identity{}) {
						t.Fatal("failed GetCallerIdentity returned identity")
					}
				}
				if err == nil || strings.Contains(err.Error(), secret) || requests.Load() != 1 {
					t.Fatalf("unsafe error, accepted invalid response, or retried request: %v, requests %d", err, requests.Load())
				}
				if item.code != "" && (!strings.Contains(err.Error(), item.code) || !strings.Contains(err.Error(), "fixture-request-123") || !strings.Contains(err.Error(), operation)) {
					t.Fatalf("missing operation or safe error metadata: %v", err)
				}
			})
		}
	}
}

func TestSignedOperationsRejectInvalidInputsBeforeNetwork(t *testing.T) {
	isolatedTransport(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	client := Client{endpoint: server.URL}
	for _, mutate := range []func(*Credentials){
		func(c *Credentials) { c.AccessKeyID = "" },
		func(c *Credentials) { c.SecretAccessKey = " " },
		func(c *Credentials) { c.SessionToken = "" },
		func(c *Credentials) { c.Expiration = time.Now().Add(-time.Minute) },
	} {
		source := sourceCredentials()
		mutate(&source)
		if _, err := client.Assume(context.Background(), source, roleStep(), TransportOptions{}); err == nil {
			t.Fatal("AssumeRole accepted invalid source credentials")
		}
		if _, err := client.Identity(context.Background(), source, "us-east-1", TransportOptions{}); err == nil {
			t.Fatal("GetCallerIdentity accepted invalid credentials")
		}
	}
	for _, mutate := range []func(*config.RoleStep){
		func(s *config.RoleStep) { s.Region = "" },
		func(s *config.RoleStep) { s.Region = "us-east-1/invalid" },
		func(s *config.RoleStep) { s.Region = "cn-north-1" },
		func(s *config.RoleStep) { s.RoleARN = fixtureRole.PrincipalARN },
		func(s *config.RoleStep) { s.DurationSeconds = 899 },
		func(s *config.RoleStep) { s.DurationSeconds = 3601 },
		func(s *config.RoleStep) { s.RoleSessionName = "invalid name" },
		func(s *config.RoleStep) { s.ExternalID = "invalid external id" },
	} {
		step := roleStep()
		mutate(&step)
		if _, err := client.Assume(context.Background(), sourceCredentials(), step, TransportOptions{}); err == nil {
			t.Fatal("AssumeRole accepted invalid role step")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Assume(ctx, sourceCredentials(), roleStep(), TransportOptions{}); err != context.Canceled {
		t.Fatalf("AssumeRole lost cancellation: %v", err)
	}
	if _, err := client.Identity(ctx, sourceCredentials(), "us-east-1", TransportOptions{}); err != context.Canceled {
		t.Fatalf("GetCallerIdentity lost cancellation: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid signed inputs reached the network: %d", requests.Load())
	}
}

func TestAssumeRejectsIncompleteOrExpiredCredentials(t *testing.T) {
	isolatedTransport(t)
	for _, body := range []string{
		assumeXML(time.Now().Add(time.Hour).UTC().Format(time.RFC3339), ""),
		assumeXML("2001-01-01T00:00:00Z", "SYNTHETIC_SESSION"),
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		result, err := (Client{endpoint: server.URL}).Assume(context.Background(), sourceCredentials(), roleStep(), TransportOptions{})
		server.Close()
		if err == nil || result != (Credentials{}) {
			t.Fatal("AssumeRole accepted incomplete or expired credentials")
		}
	}
}

func TestIdentityRejectsMismatchedAccount(t *testing.T) {
	isolatedTransport(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, identityXML("123456789012", "arn:aws:sts::999999999999:assumed-role/Synthetic/session"))
	}))
	defer server.Close()
	identity, err := (Client{endpoint: server.URL}).Identity(context.Background(), sourceCredentials(), "us-east-1", TransportOptions{})
	if err == nil || identity != (Identity{}) {
		t.Fatal("GetCallerIdentity accepted an inconsistent identity")
	}
}
