package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var legacyEnvironmentKeys = []string{
	"azure_tenant_id", "azure_app_id_uri", "azure_default_username",
	"azure_default_password", "azure_default_role_arn", "azure_default_duration_hours",
}

func clearLegacyEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range legacyEnvironmentKeys {
		t.Setenv(key, "")
		t.Setenv(strings.ToUpper(key), "")
	}
}

func TestLegacyEnvironmentPrecedenceAndLiteralValues(t *testing.T) {
	clearLegacyEnvironment(t)
	path := fixtureFile(t, "[profile example]\nazure_tenant_id = file.onmicrosoft.com\nazure_app_id_uri = 'urn:file?x=one&y=two#fragment'\nazure_default_username = file-user\nazure_default_password = 'fake#password;literal=part'\nazure_default_role_arn = file-role\nazure_default_duration_hours = 1\nazure_default_remember_me = true\nregion = file-region\n")
	doc, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	expectedFile := []string{"file.onmicrosoft.com", "urn:file?x=one&y=two#fragment", "file-user", "fake#password;literal=part", "file-role", "1"}
	upper := []string{"upper.onmicrosoft.com", "urn:upper", "upper-user", "fake-upper-password", "upper-role", "2"}
	lower := []string{"lower.onmicrosoft.com", "urn:lower", "lower-user", "fake-lower-password", "lower-role", "3"}
	for _, stage := range []struct {
		name     string
		expected []string
	}{{"file", expectedFile}, {"uppercase", upper}, {"lowercase", lower}, {"empty-lowercase", upper}, {"empty-environment", expectedFile}} {
		for i, key := range legacyEnvironmentKeys {
			switch stage.name {
			case "uppercase":
				t.Setenv(strings.ToUpper(key), upper[i])
			case "lowercase":
				t.Setenv(key, lower[i])
			case "empty-lowercase":
				t.Setenv(key, "")
			case "empty-environment":
				t.Setenv(strings.ToUpper(key), "")
			}
		}
		// These are intentionally not legacy override fields.
		t.Setenv("azure_default_remember_me", "false")
		t.Setenv("AZURE_DEFAULT_REMEMBER_ME", "false")
		t.Setenv("REGION", "ignored-region")
		profile, err := doc.Profile("example")
		if err != nil {
			t.Fatalf("%s: %v", stage.name, err)
		}
		actual := []string{profile.Tenant, profile.AppID, profile.Username, profile.Password, profile.RoleARN, profile.DurationHours}
		if !reflect.DeepEqual(actual, stage.expected) || !profile.RememberMe || profile.Region != "file-region" {
			t.Fatalf("%s: legacy environment precedence or literal-value handling changed", stage.name)
		}
	}
}

func TestMissingProfileCannotBeCreatedByEnvironment(t *testing.T) {
	clearLegacyEnvironment(t)
	t.Setenv("AZURE_TENANT_ID", "example.onmicrosoft.com")
	t.Setenv("AZURE_APP_ID_URI", "urn:example:aws")
	path := filepath.Join(t.TempDir(), "missing")
	doc, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doc.Profile("new"); err == nil {
		t.Fatal("login accepted an absent profile")
	}
	profile, err := doc.ConfigureProfile("new")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Tenant != "example.onmicrosoft.com" || profile.AppID != "urn:example:aws" {
		t.Fatal("new configure profile lost environment seeds")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reading a missing file created it: %v", err)
	}
}

func TestProfileRejectsTypedErrorsAndSecretInjection(t *testing.T) {
	clearLegacyEnvironment(t)
	base := "[default]\nazure_tenant_id = example.onmicrosoft.com\nazure_app_id_uri = urn:example\n"
	for _, extra := range []string{
		"azure_default_remember_me = TRUE\n",
		"azure_default_remember_me =\n",
		"azure_default_duration_hours =\n",
		"azure_default_duration_hours = 0.2501\n",
		"azure_default_duration_hours = NaN\n",
		"azure_default_password = fake-private-marker\nazure_default_password = other-secret\n",
	} {
		doc, err := Load(fixtureFile(t, base+extra))
		if err != nil {
			t.Fatal(err)
		}
		for _, lookup := range []func(string) (Profile, error){doc.Profile, doc.ConfigureProfile} {
			if _, err := lookup("default"); err == nil {
				t.Fatalf("accepted invalid typed or duplicate settings: %q", strings.Split(extra, " =")[0])
			} else if strings.Contains(err.Error(), "fake-private-marker") || strings.Contains(err.Error(), "other-secret") {
				t.Fatal("configuration error exposed password")
			}
		}
	}
	profile := Profile{Name: "default", Tenant: "example.onmicrosoft.com", AppID: "urn:example", Password: "fake-private-marker\n[malicious]"}
	if err := profile.Validate(); err == nil || strings.Contains(err.Error(), "fake-private-marker") {
		t.Fatal("multiline password was accepted or disclosed")
	}
	profile.Password = "safe-fake-password"
	profile.Name = "default]\n[malicious"
	if err := profile.Validate(); err == nil {
		t.Fatal("profile-name injection accepted")
	}
}

func TestTenantMustBeSingleUnescapedSegment(t *testing.T) {
	for _, tenant := range []string{"https://example.com", "example.com/path", "example.com?query", "example.com#fragment", "example.com%2fpath", "example.com\\path", "..", ".", "", "example.com\nother", "user@example.com"} {
		profile := Profile{Name: "default", Tenant: tenant, AppID: "urn:example"}
		if err := profile.Validate(); err == nil {
			t.Fatalf("unsafe tenant %q accepted", tenant)
		}
	}
	for _, tenant := range []string{"example.onmicrosoft.com", "11111111-2222-3333-4444-555555555555"} {
		profile := Profile{Name: "default", Tenant: tenant, AppID: "urn:example?x=1&y=2"}
		if err := profile.Validate(); err != nil {
			t.Fatalf("valid tenant rejected: %v", err)
		}
	}
}

func TestDurationRequiresExactWholeSecondsWithinAWSLimits(t *testing.T) {
	for _, test := range []struct {
		hours   string
		seconds int32
	}{
		{"", 43200}, {".25", 900}, {"12", 43200}, {"0.28", 1008}, {"1.0025", 3609}, {"2.5e-1", 900},
	} {
		seconds, err := (Profile{DurationHours: test.hours}).DurationSeconds()
		if err != nil || seconds != test.seconds {
			t.Fatalf("duration %q: got %d, %v; want %d", test.hours, seconds, err, test.seconds)
		}
	}
	for _, hours := range []string{"NaN", "Inf", "-1", "0.2499", "12.0001", "0.2501", "1/2", "1 hour", "1.00000000000000000000001", "0.24999999999999999999999999", "12.000000000000000000000001", "1e99999999"} {
		if _, err := (Profile{DurationHours: hours}).DurationSeconds(); err == nil {
			t.Fatalf("invalid or fractional-second duration %q accepted", hours)
		}
	}
}

func TestPathOverridesAreIndependentAndRelativeToInvocation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AWS_CONFIG_FILE", "relative-config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	paths, err := ResolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if paths.Config != filepath.Join(working, "relative-config") || paths.Credentials != filepath.Join(home, ".aws", "credentials") {
		t.Fatalf("incorrect independent path overrides: %+v", paths)
	}
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "relative-credentials")
	paths, err = ResolvePaths()
	if err != nil || paths.Config != filepath.Join(home, ".aws", "config") || paths.Credentials != filepath.Join(working, "relative-credentials") {
		t.Fatalf("incorrect inverse independent overrides: %+v, %v", paths, err)
	}
}

func TestRegionPrecedence(t *testing.T) {
	profile := Profile{Region: "profile-region"}
	t.Setenv("AWS_REGION", "primary-region")
	t.Setenv("AWS_DEFAULT_REGION", "fallback-region")
	if got := ResolveRegion(profile); got != "primary-region" {
		t.Fatalf("AWS_REGION did not win: %q", got)
	}
	t.Setenv("AWS_REGION", "")
	if got := ResolveRegion(profile); got != "fallback-region" {
		t.Fatalf("AWS_DEFAULT_REGION did not win: %q", got)
	}
	t.Setenv("AWS_DEFAULT_REGION", "")
	if got := ResolveRegion(profile); got != "profile-region" {
		t.Fatalf("profile region was ignored: %q", got)
	}
}
