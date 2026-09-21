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

func TestResolveLoginProfileOrdersChainsFromEntraSource(t *testing.T) {
	clearLegacyEnvironment(t)
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	doc, err := Load(fixtureFile(t, "[profile rsg]\nazure_tenant_id = example.onmicrosoft.com\nazure_app_id_uri = urn:example\ncredential_process = aalogin --profile rsg --credential-process\n[profile cni]\nsource_profile = rsg\nrole_arn = arn:aws:iam::123456789012:role/CNI\n[profile deployment]\nsource_profile = cni\nrole_arn = arn:aws:iam::210987654321:role/Deployment\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		roles []string
	}{
		{"rsg", nil},
		{"cni", []string{"arn:aws:iam::123456789012:role/CNI"}},
		{"deployment", []string{"arn:aws:iam::123456789012:role/CNI", "arn:aws:iam::210987654321:role/Deployment"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile, err := doc.ResolveLoginProfile(test.name)
			if err != nil {
				t.Fatal(err)
			}
			if profile.Source.Name != "rsg" || profile.Name != test.name {
				t.Fatalf("resolved wrong source/target: %s -> %s", profile.Source.Name, profile.Name)
			}
			var roles []string
			source := profile.Source.Name
			for _, step := range profile.Steps {
				if step.SourceProfile != source {
					t.Fatalf("broken execution order: %s follows %s", step.Name, source)
				}
				source = step.Name
				roles = append(roles, step.RoleARN)
			}
			if !reflect.DeepEqual(roles, test.roles) {
				t.Fatalf("role execution order: got %v, want %v", roles, test.roles)
			}
		})
	}
}

func TestResolveLoginProfileRejectsInvalidGraphsAndAuthentication(t *testing.T) {
	clearLegacyEnvironment(t)
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	root := "[profile rsg]\nazure_tenant_id = example.onmicrosoft.com\nazure_app_id_uri = urn:example\n"
	role := "role_arn = arn:aws:iam::123456789012:role/CNI\n"
	for _, test := range []struct {
		name    string
		content string
	}{
		{"self-cycle", "[profile cni]\nsource_profile = cni\n" + role},
		{"indirect-cycle", "[profile cni]\nsource_profile = middle\n" + role + "[profile middle]\nsource_profile = cni\n" + role},
		{"missing-source", "[profile cni]\nsource_profile = absent\n" + role},
		{"missing-source-setting", "[profile cni]\n" + role},
		{"missing-role-setting", "[profile cni]\nsource_profile = rsg\n"},
		{"empty-source", "[profile cni]\nsource_profile =\n" + role},
		{"non-entra-root", "[profile cni]\nsource_profile = unrelated\n" + role + "[profile unrelated]\nregion = us-east-1\n"},
		{"root-role-ambiguity", "[profile cni]\nsource_profile = rsg\n" + role + "azure_tenant_id = example.onmicrosoft.com\nazure_app_id_uri = urn:example\n"},
		{"credential-source", "[profile cni]\nsource_profile = rsg\n" + role + "credential_source = Environment\n"},
		{"mfa", "[profile cni]\nsource_profile = rsg\n" + role + "mfa_serial = arn:aws:iam::123456789012:mfa/example\n"},
		{"web-identity", "[profile cni]\nsource_profile = rsg\n" + role + "web_identity_token_file = /private/token\n"},
		{"process-on-step", "[profile cni]\nsource_profile = rsg\n" + role + "credential_process = other-command\n"},
		{"sso-source", "[profile cni]\nsource_profile = rsg\n" + role + "sso_session = other\n"},
		{"wrong-arn-kind", "[profile cni]\nsource_profile = rsg\nrole_arn = arn:aws:iam::123456789012:user/example\n"},
		{"invalid-account", "[profile cni]\nsource_profile = rsg\nrole_arn = arn:aws:iam::123:role/example\n"},
		{"unknown-partition", "[profile cni]\nsource_profile = rsg\nrole_arn = arn:unknown:iam::123456789012:role/example\n"},
		{"partition-region-mismatch", "[profile cni]\nsource_profile = rsg\nrole_arn = arn:aws-cn:iam::123456789012:role/example\nregion = us-east-1\n"},
		{"duplicate-source", "[profile cni]\nsource_profile = rsg\nsource_profile = other\n" + role},
		{"duplicate-role", "[profile cni]\nsource_profile = rsg\n" + role + role},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc, err := Load(fixtureFile(t, root+test.content))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := doc.ResolveLoginProfile("cni"); err == nil {
				t.Fatal("invalid graph or authentication was accepted")
			}
		})
	}
}

func TestRoleStepRejectsInvalidRequestBeforeLogin(t *testing.T) {
	clearLegacyEnvironment(t)
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	base := "[profile rsg]\nazure_tenant_id = example.onmicrosoft.com\nazure_app_id_uri = urn:example\n[profile cni]\nsource_profile = rsg\nrole_arn = arn:aws:iam::123456789012:role/CNI\n"
	for _, setting := range []string{
		"duration_seconds = 899", "duration_seconds = 3601",
		"duration_seconds = 900.5", "duration_seconds =", "duration_seconds = 1e3",
		"role_session_name = x", "role_session_name = fake-private-marker/invalid",
		"external_id = x", "external_id = fake-private-marker invalid",
	} {
		doc, err := Load(fixtureFile(t, base+setting+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := doc.ResolveLoginProfile("cni"); err == nil {
			t.Fatalf("accepted invalid %s", strings.Split(setting, " =")[0])
		} else if strings.Contains(err.Error(), "fake-private-marker") {
			t.Fatal("request validation disclosed field contents")
		}
	}
}

func TestLoginProfileNamesDoesNotEnrollEnvironmentOnlyProfiles(t *testing.T) {
	clearLegacyEnvironment(t)
	t.Setenv("azure_tenant_id", "environment.onmicrosoft.com")
	t.Setenv("AZURE_APP_ID_URI", "urn:environment")
	doc, err := Load(fixtureFile(t, "[profile rsg]\nazure_tenant_id = file.onmicrosoft.com\nazure_app_id_uri = urn:file\n[profile cni]\nsource_profile = rsg\nrole_arn = arn:aws:iam::123456789012:role/CNI\n[profile incomplete-role]\nsource_profile =\n[profile unrelated]\nregion = us-east-1\n[profile tenant-only]\nazure_tenant_id = file.onmicrosoft.com\n[profile nested-only]\ns3 =\n  azure_tenant_id = nested.invalid\n  azure_app_id_uri = urn:nested\n  source_profile = rsg\n[services ignored]\nsource_profile = rsg\n[default]\nazure_tenant_id = file.onmicrosoft.com\nazure_app_id_uri = urn:file\n"))
	if err != nil {
		t.Fatal(err)
	}
	names, err := doc.LoginProfileNames()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"cni", "default", "incomplete-role", "rsg"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("enumerated %v, want only file-backed candidates %v", names, want)
	}
	t.Setenv("AWS_REGION", "us-east-1")
	inherited, err := Load(fixtureFile(t, "[profile cni]\nsource_profile = unrelated\nrole_arn = arn:aws:iam::123456789012:role/CNI\n[profile unrelated]\nregion = us-east-1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inherited.ResolveLoginProfile("cni"); err == nil {
		t.Fatal("environment credentials enrolled an unrelated source profile into an Entra chain")
	}
}
