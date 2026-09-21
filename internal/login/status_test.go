package login

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aalogin/internal/cli"
)

const statusSourceConfig = "[profile source]\nazure_tenant_id = tenant\nazure_app_id_uri = https://example.com/app\nazure_default_role_arn = arn:aws:iam::123456789012:role/Source\nazure_default_password = do-not-print-password\n"

func statusFixture(t *testing.T, configuration, credentials string) (*Runner, *bytes.Buffer, string) {
	t.Helper()
	for _, key := range []string{"azure_tenant_id", "azure_app_id_uri", "azure_default_username", "azure_default_password", "azure_default_role_arn", "azure_default_duration_hours"} {
		t.Setenv(key, "")
		t.Setenv(strings.ToUpper(key), "")
	}
	dir := t.TempDir()
	configPath, credentialsPath := filepath.Join(dir, "config"), filepath.Join(dir, "credentials")
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	if credentials != "" {
		if err := os.WriteFile(credentialsPath, []byte(credentials), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsPath)
	t.Setenv("AWS_PROFILE", "unrelated")
	var out bytes.Buffer
	// No input, browser, or STS client is available: any authentication path is
	// a regression. Run, not status directly, proves the dispatch stays offline.
	r := &Runner{Out: &out, Err: io.Discard, now: func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) }}
	return r, &out, credentialsPath
}

func statusCache(expiration, metadata string) string {
	return "[source]\naws_access_key_id = do-not-print-key\naws_secret_access_key = do-not-print-secret\naws_session_token = do-not-print-token\naws_expiration = " + expiration + "\n" + metadata
}

func TestStatusRunsOfflineAcrossChainsAndFiltersExplicitProfile(t *testing.T) {
	configuration := statusSourceConfig + "[profile target]\nsource_profile = source\nrole_arn = arn:aws:iam::222222222222:role/Target\n[profile other]\nazure_tenant_id = tenant\nazure_app_id_uri = https://example.com/other\n"
	credentials := statusCache("2026-09-21T13:00:00Z", "aalogin_role_arn = arn:aws:iam::123456789012:role/Source\n")
	r, out, path := statusFixture(t, configuration, credentials)
	o, err := cli.Parse([]string{"status"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, evidence := range []string{"source", "target", "other", "222222222222", "Target"} {
		if !strings.Contains(text, evidence) {
			t.Errorf("missing local evidence %q in %s", evidence, text)
		}
	}
	for _, secret := range []string{"do-not-print-key", "do-not-print-secret", "do-not-print-token", "do-not-print-password"} {
		if strings.Contains(text, secret) {
			t.Fatal("status disclosed sensitive data")
		}
	}
	out.Reset()
	o, err = cli.Parse([]string{"status", "--profile", "target"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "222222222222") || !strings.Contains(out.String(), "source") || strings.Contains(out.String(), "other") {
		t.Fatalf("explicit profile did not filter the graph: %s", out.String())
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != credentials {
		t.Fatalf("status changed credentials: %v", err)
	}
	after, err = os.ReadFile(os.Getenv("AWS_CONFIG_FILE"))
	if err != nil || string(after) != configuration {
		t.Fatalf("status changed config: %v", err)
	}
}

func TestStatusRejectsInvalidGraphsWithoutPartialOutput(t *testing.T) {
	for name, configuration := range map[string]string{
		"empty":          "[profile unrelated]\nregion = us-east-1\n",
		"missing-source": statusSourceConfig + "[profile broken]\nsource_profile = missing\nrole_arn = arn:aws:iam::222222222222:role/Target\n",
		"cycle":          "[profile a]\nsource_profile = b\nrole_arn = arn:aws:iam::222222222222:role/A\n[profile b]\nsource_profile = a\nrole_arn = arn:aws:iam::222222222222:role/B\n",
	} {
		t.Run(name, func(t *testing.T) {
			r, out, _ := statusFixture(t, configuration, "")
			err := r.Run(context.Background(), cli.Options{Status: true})
			if err == nil || !IsConfigError(err) || out.Len() != 0 {
				t.Fatalf("invalid graph emitted status or lacked config error: %v, %s", err, out.String())
			}
			if name == "missing-source" {
				if err := r.Run(context.Background(), cli.Options{Status: true, ProfileExplicit: true, Profile: "source"}); err != nil {
					t.Fatalf("unrelated invalid chain prevented explicit status: %v", err)
				}
			}
		})
	}
}

func TestStatusEscapesUntrustedCacheMetadata(t *testing.T) {
	metadata := "aalogin_role_arn = arn:aws:iam::123456789012:role/Bad\x1b[2J\n"
	r, out, _ := statusFixture(t, statusSourceConfig, statusCache("2026-09-21T13:00:00Z", metadata))
	if err := r.Run(context.Background(), cli.Options{Status: true}); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Fatal("status emitted a terminal escape from credential metadata")
	}
}
