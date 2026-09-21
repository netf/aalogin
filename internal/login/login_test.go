package login

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aalogin/internal/browser"
	"aalogin/internal/cli"
	"aalogin/internal/config"
	"aalogin/internal/saml"
	"aalogin/internal/sts"
)

type fixtureBrowser struct {
	calls int
	err   error
}

func (b *fixtureBrowser) Acquire(context.Context, browser.Options) (string, error) {
	b.calls++
	return base64.StdEncoding.EncodeToString([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion><saml:AttributeStatement><saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><saml:AttributeValue>arn:aws:iam::123456789012:role/example,arn:aws:iam::123456789012:saml-provider/example</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`)), b.err
}

type fixtureSTS struct {
	credentials sts.Credentials
	err         error
}

func (s fixtureSTS) Exchange(context.Context, string, saml.Role, int32, string, sts.TransportOptions) (sts.Credentials, error) {
	return s.credentials, s.err
}
func fixture(t *testing.T) (*Runner, *fixtureBrowser, *bytes.Buffer, *bytes.Buffer, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	creds := filepath.Join(dir, "credentials")
	t.Setenv("AWS_CONFIG_FILE", cfg)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
	for _, k := range []string{"azure_tenant_id", "azure_app_id_uri", "azure_default_username", "azure_default_password", "azure_default_role_arn", "azure_default_duration_hours", "AWS_REGION", "AWS_DEFAULT_REGION"} {
		t.Setenv(k, "")
		t.Setenv(strings.ToUpper(k), "")
	}
	if err := os.WriteFile(cfg, []byte("[profile fixture]\nazure_tenant_id = example.onmicrosoft.com\nazure_app_id_uri = urn:test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(creds, []byte("[unrelated]\ncustom = retained\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, diag := new(bytes.Buffer), new(bytes.Buffer)
	r := New(nil, out, diag)
	b := &fixtureBrowser{}
	r.browser = b
	r.sts = fixtureSTS{credentials: sts.Credentials{AccessKeyID: "fake-access", SecretAccessKey: "fake-secret", SessionToken: "fake-session", Expiration: time.Now().Add(time.Hour)}}
	return r, b, out, diag, creds
}
func TestProcessContractAndFailurePreservation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{true: "failure", false: "success"}[fail], func(t *testing.T) {
			r, _, out, diag, path := fixture(t)
			before, _ := os.ReadFile(path)
			if fail {
				r.sts = fixtureSTS{err: errors.New("STS rejected request")}
			}
			err := r.Run(context.Background(), cli.Options{Profile: "fixture", Mode: "cli", NoPrompt: true, CredentialProcess: true, Timeout: time.Second})
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("process invocation changed credentials")
			}
			if fail {
				if err == nil || out.Len() != 0 {
					t.Fatalf("failure err=%v stdout=%q", err, out.String())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err = json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if len(got) != 5 || got["Version"] != float64(1) || got["AccessKeyId"] != "fake-access" || got["SecretAccessKey"] != "fake-secret" || got["SessionToken"] != "fake-session" {
				t.Fatalf("invalid process schema: %v", got)
			}
			if _, err = time.Parse(time.RFC3339, got["Expiration"].(string)); err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"fake-secret", "fake-session", "SAMLResponse"} {
				if strings.Contains(diag.String(), secret) {
					t.Fatal("secret in diagnostic")
				}
			}
		})
	}
}
func TestFailureNeverReplacesCredentials(t *testing.T) {
	for _, stage := range []string{"browser", "STS"} {
		t.Run(stage, func(t *testing.T) {
			r, b, out, _, path := fixture(t)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "browser" {
				b.err = errors.New("browser failed")
			} else {
				r.sts = fixtureSTS{err: errors.New("STS failed")}
			}
			if err = r.Run(context.Background(), cli.Options{Profile: "fixture", Mode: "cli", NoPrompt: true, Timeout: time.Second}); err == nil {
				t.Fatal("expected failure")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || out.Len() != 0 {
				t.Fatal("failed login mutated credentials or stdout")
			}
		})
	}
}
func TestFreshBoundary(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	v := map[string]string{"aws_access_key_id": "a", "aws_secret_access_key": "b", "aws_session_token": "c"}
	for _, delta := range []time.Duration{11*time.Minute - time.Second, 11 * time.Minute, 11*time.Minute + time.Second} {
		v["aws_expiration"] = now.Add(delta).Format(time.RFC3339)
		if fresh(v, now) != (delta > 11*time.Minute) {
			t.Fatalf("boundary %v", delta)
		}
	}
	delete(v, "aws_session_token")
	if fresh(v, now) {
		t.Fatal("incomplete credentials skipped")
	}
}
func TestLoginReusesCacheUntilForced(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "all"}[all], func(t *testing.T) {
			r, b, out, _, path := fixture(t)
			text := "[fixture]\naws_access_key_id=a\naws_secret_access_key=b\naws_session_token=c\naws_expiration=" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + "\n"
			if err := os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			o := cli.Options{Profile: "fixture", AllProfiles: all, Mode: "cli", NoPrompt: true, Timeout: time.Second}
			if err := r.Run(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, []byte(text)) || out.Len() != 0 || b.calls != 0 {
				t.Fatalf("fresh cache was not reused without writes: %v", err)
			}
			o.ForceRefresh = true
			if err := r.Run(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			if b.calls != 1 {
				t.Fatal("force did not refresh")
			}
		})
	}
}
func TestStaleDefaultDoesNotSwitchRole(t *testing.T) {
	_, err := selectRole(context.Background(), []saml.Role{{RoleARN: "arn:aws:iam::123456789012:role/one"}}, "arn:aws:iam::123456789012:role/two", &cli.Prompt{NoPrompt: true})
	if err == nil {
		t.Fatal("stale default switched role")
	}
}

func TestProcessReusesCacheWithoutWriting(t *testing.T) {
	r, b, out, _, path := fixture(t)
	text := "[fixture]\naws_access_key_id=cached-access\naws_secret_access_key=cached-secret\naws_session_token=cached-token\naws_expiration=" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + "\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	err := r.Run(context.Background(), cli.Options{Profile: "fixture", CredentialProcess: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var result processCredentials
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.AccessKeyID != "cached-access" || result.SessionToken != "cached-token" || b.calls != 0 {
		t.Fatal("process did not return the cached session")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != text {
		t.Fatal("process changed the credentials file")
	}
}

func TestChangedConfiguredRoleDoesNotReuseOldPrivileges(t *testing.T) {
	r, b, _, _, path := fixture(t)
	t.Setenv("AZURE_DEFAULT_ROLE_ARN", "arn:aws:iam::123456789012:role/example")
	text := "[fixture]\naws_access_key_id=old-access\naws_secret_access_key=old-secret\naws_session_token=old-token\naalogin_role_arn=arn:aws:iam::123456789012:role/old-role\naws_expiration=" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + "\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background(), cli.Options{Profile: "fixture", NoPrompt: true, Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	doc, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	values, err := doc.Values("fixture")
	if err != nil || values["aws_access_key_id"] == "old-access" || values["aalogin_role_arn"] != "arn:aws:iam::123456789012:role/example" || b.calls != 1 {
		t.Fatalf("stale role binding reused: %v", err)
	}
}

type fixtureRoleAccess struct {
	err error
}

func (f fixtureRoleAccess) Assume(context.Context, sts.Credentials, config.RoleStep, sts.TransportOptions) (sts.Credentials, error) {
	return sts.Credentials{AccessKeyID: "target-access", SecretAccessKey: "target-secret", SessionToken: "target-token", Expiration: time.Now().Add(time.Hour)}, f.err
}

func (f fixtureRoleAccess) Identity(context.Context, sts.Credentials, string, sts.TransportOptions) (sts.Identity, error) {
	return sts.Identity{Account: "987654321012", ARN: "arn:aws:sts::987654321012:assumed-role/target/session"}, f.err
}

func TestTargetLoginPreservesSourceAndNeverStoresTargetCredentials(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "denied"}[fail], func(t *testing.T) {
			r, b, out, _, path := fixture(t)
			if err := config.Update(context.Background(), os.Getenv("AWS_CONFIG_FILE"), "profile target", map[string]string{
				"source_profile": "fixture", "role_arn": "arn:aws:iam::987654321012:role/target", "region": "us-east-1",
			}); err != nil {
				t.Fatal(err)
			}
			text := "[fixture]\naws_access_key_id=cached-access\naws_secret_access_key=cached-secret\naws_session_token=cached-token\naws_expiration=" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + "\n"
			if err := os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			access := fixtureRoleAccess{}
			if fail {
				access.err = errors.New("access denied")
			}
			r.roles = access
			err := r.Run(context.Background(), cli.Options{Profile: "target", NoPrompt: true, Timeout: time.Second})
			if (err != nil) != fail {
				t.Fatalf("target result: %v", err)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || string(after) != text || b.calls != 0 || out.Len() != 0 {
				t.Fatalf("target operation mutated cached credentials or authenticated again: %v", readErr)
			}
		})
	}
}
