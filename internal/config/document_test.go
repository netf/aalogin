package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fixtureFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestUpdatePreservesUnrelatedBytesAndNestedSettings(t *testing.T) {
	original := "; preamble\r\n[profile selected]\r\n  region = 'old-region'  \r\nazure_default_password = 'fake#secret;part=two'\r\ns3 =\r\n    region = nested-one\r\n    region = nested-two\r\n    addressing_style = path\r\n\r\n# keep this comment\r\n[services untouched]\r\nkey = literal#suffix;still-value"
	path := fixtureFile(t, original)
	if err := Update(context.Background(), path, "profile selected", map[string]string{"region": "new-region", "azure_tenant_id": "example.onmicrosoft.com"}); err != nil {
		t.Fatal(err)
	}
	expected := strings.Replace(original, "'old-region'", "new-region", 1)
	expected = strings.Replace(expected, "[services untouched]", "azure_tenant_id = example.onmicrosoft.com\r\n[services untouched]", 1)
	if actual := readFixture(t, path); actual != expected {
		t.Fatalf("unrelated INI bytes changed:\nwant %q\ngot  %q", expected, actual)
	}
	doc, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	values, err := doc.Values("profile selected")
	if err != nil {
		t.Fatal(err)
	}
	if values["region"] != "new-region" || values["azure_tenant_id"] != "example.onmicrosoft.com" || values["azure_default_password"] != "fake#secret;part=two" {
		t.Fatal("top-level scalars did not survive the patch")
	}
	if _, exists := values["addressing_style"]; exists {
		t.Fatal("nested setting escaped into top-level values")
	}
}

func TestUpdateAppendsOutsideTrailingNestedBlock(t *testing.T) {
	path := fixtureFile(t, "[default]\ns3 =\n    azure_tenant_id = nested.invalid\n    azure_app_id_uri = urn:nested")
	if err := Update(context.Background(), path, "default", map[string]string{"azure_tenant_id": "example.onmicrosoft.com", "azure_app_id_uri": "urn:example:aws"}); err != nil {
		t.Fatal(err)
	}
	doc, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	values, err := doc.Values("default")
	if err != nil {
		t.Fatal(err)
	}
	if values["azure_tenant_id"] != "example.onmicrosoft.com" || values["azure_app_id_uri"] != "urn:example:aws" {
		t.Fatalf("new settings were captured by the nested block: %v", values)
	}
}

func TestUpdateFailuresPreservePriorBytes(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		section string
		values  map[string]string
		key     string
	}{
		{"duplicate-section", "[default]\nregion = first\n[default]\nregion = second\n", "default", map[string]string{"region": "new"}, "default"},
		{"duplicate-owned-key", "[default]\nazure_default_password = fake-private-marker\nazure_default_password = another-fake-secret\n", "default", map[string]string{"region": "new"}, "azure_default_password"},
		{"duplicate-role-metadata", "[default]\naalogin_role_arn = arn:aws:iam::123456789012:role/First\naalogin_role_arn = arn:aws:iam::123456789012:role/Second\n", "default", map[string]string{"region": "new"}, "aalogin_role_arn"},
		{"duplicate-source-profile", "[default]\nsource_profile = first\nsource_profile = second\n", "default", map[string]string{"region": "new"}, "source_profile"},
		{"nested-scalar", "[default]\nregion =\n    child = preserved\n", "default", map[string]string{"region": "new"}, "region"},
		{"multiline-value", "[default]\nregion = old\n", "default", map[string]string{"azure_default_password": "fake-private-marker\n[other]"}, "azure_default_password"},
		{"section-injection", "[default]\nregion = old\n", "default]\n[other", map[string]string{"region": "new"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := fixtureFile(t, test.content)
			err := Update(context.Background(), path, test.section, test.values)
			if err == nil {
				t.Fatal("invalid update succeeded")
			}
			if strings.Contains(err.Error(), "fake-private-marker") || strings.Contains(err.Error(), "another-fake-secret") {
				t.Fatal("error disclosed a password value")
			}
			if test.key != "" && !strings.Contains(err.Error(), test.key) {
				t.Fatalf("error did not identify the affected section/key: %v", err)
			}
			if actual := readFixture(t, path); actual != test.content {
				t.Fatal("failed update modified prior file")
			}
		})
	}
}

func TestSymlinkUpdatesTargetWithoutReplacingLink(t *testing.T) {
	for _, existing := range []bool{true, false} {
		t.Run(map[bool]string{true: "existing-target", false: "missing-target"}[existing], func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "private", "credentials")
			if existing {
				if err := os.Mkdir(filepath.Dir(target), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte("[example]\ncustom = keep\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			link := filepath.Join(dir, "credentials-link")
			if err := os.Symlink("private/credentials", link); err != nil {
				t.Fatal(err)
			}
			if err := Update(context.Background(), link, "example", map[string]string{"aws_access_key_id": "fake-key"}); err != nil {
				t.Fatal(err)
			}
			if destination, err := os.Readlink(link); err != nil || destination != "private/credentials" {
				t.Fatalf("symlink changed: %q, %v", destination, err)
			}
			if actual := readFixture(t, target); !strings.Contains(actual, "aws_access_key_id = fake-key\n") || (existing && !strings.Contains(actual, "custom = keep\n")) {
				t.Fatalf("wrong target content: %q", actual)
			}
			for _, file := range []string{target, target + ".aalogin.lock"} {
				info, err := os.Stat(file)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatalf("private mode missing for %s: %v", file, err)
				}
			}
		})
	}
}

func TestCreatingParentsDoesNotChangeExistingAncestorPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "new", "deeper", "credentials")
	if err := Update(context.Background(), path, "example", map[string]string{"aws_session_token": "fake-token"}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path string
		mode os.FileMode
	}{
		{dir, 0755}, {filepath.Dir(filepath.Dir(path)), 0700}, {filepath.Dir(path), 0700},
	} {
		info, err := os.Stat(test.path)
		if err != nil || info.Mode().Perm() != test.mode {
			t.Fatalf("unexpected directory permissions on %s: %v", test.path, err)
		}
	}
}

func TestConcurrentWritersPreserveOtherProfiles(t *testing.T) {
	path := fixtureFile(t, "# shared\n[unrelated]\ncustom = unchanged\n")
	start := make(chan struct{})
	errors := make(chan error, 2)
	var workers sync.WaitGroup
	for _, profile := range []string{"first", "second"} {
		workers.Add(1)
		go func(name string) {
			defer workers.Done()
			<-start
			for _, value := range []string{"initial", "final"} {
				if err := Update(context.Background(), path, name, map[string]string{"aws_access_key_id": name + "-" + value}); err != nil {
					errors <- err
					return
				}
			}
		}(profile)
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	doc, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"first", "second"} {
		values, err := doc.Values(profile)
		if err != nil || values["aws_access_key_id"] != profile+"-final" {
			t.Fatalf("lost %s update: %v, %v", profile, values, err)
		}
	}
	if !strings.HasPrefix(readFixture(t, path), "# shared\n[unrelated]\ncustom = unchanged\n") {
		t.Fatal("concurrent writes altered unrelated profile")
	}
}

func TestAzureProfilesUsesOnlyFileIdentifiers(t *testing.T) {
	t.Setenv("azure_tenant_id", "environment.onmicrosoft.com")
	t.Setenv("AZURE_APP_ID_URI", "urn:environment")
	path := fixtureFile(t, "[profile zebra]\nazure_tenant_id = example.onmicrosoft.com\nazure_app_id_uri = urn:example\n[profile unrelated]\nregion = eu-west-1\n[profile tenant-only]\nazure_tenant_id = example.onmicrosoft.com\n[profile nested-only]\ns3 =\n  azure_tenant_id = nested.invalid\n  azure_app_id_uri = urn:nested\n[sso-session ignored]\nazure_tenant_id = example.onmicrosoft.com\nazure_app_id_uri = urn:example\n[services ignored]\nazure_tenant_id = example.onmicrosoft.com\nazure_app_id_uri = urn:example\n[default]\nazure_tenant_id = example.onmicrosoft.com\nazure_app_id_uri = urn:example\n")
	doc, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	names, err := doc.AzureProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(names, []string{"default", "zebra"}) {
		t.Fatalf("wrong Azure profile enumeration: %v", names)
	}
}

func TestLoadAndUpdateRejectNonregularFiles(t *testing.T) {
	path := t.TempDir()
	if _, err := Load(path); err == nil {
		t.Fatal("directory was accepted as a config document")
	}
	if err := Update(context.Background(), path, "default", map[string]string{"region": "us-east-1"}); err == nil {
		t.Fatal("directory was replaced as a config document")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatalf("failed write changed destination: %v", err)
	}
}

func TestUpdateCancellationWhileWriterLockHeld(t *testing.T) {
	path := fixtureFile(t, "[default]\nregion = unchanged\n")
	lock, err := os.OpenFile(path+".aalogin.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- Update(ctx, path, "default", map[string]string{"region": "must-not-be-written"})
	}()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("waiting writer returned %v, want context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting writer ignored context cancellation")
	}
	if readFixture(t, path) != "[default]\nregion = unchanged\n" {
		t.Fatal("canceled writer changed credentials")
	}
}

func TestRelativeSymlinkTargetUsesPhysicalParent(t *testing.T) {
	root := t.TempDir()
	physical := filepath.Join(root, "physical")
	inner := filepath.Join(physical, "inner")
	if err := os.MkdirAll(inner, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(inner, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../target", filepath.Join(inner, "config")); err != nil {
		t.Fatal(err)
	}
	if err := Update(context.Background(), filepath.Join(alias, "config"), "default", map[string]string{"region": "us-west-2"}); err != nil {
		t.Fatal(err)
	}
	if actual := readFixture(t, filepath.Join(physical, "target")); actual != "[default]\nregion = us-west-2\n" {
		t.Fatalf("incorrect symlink target contents: %q", actual)
	}
	if _, err := os.Stat(filepath.Join(root, "target")); !os.IsNotExist(err) {
		t.Fatalf("relative symlink was resolved against lexical instead of physical parent: %v", err)
	}
}

func TestSymlinkedLockIsRejectedWithoutChangingFiles(t *testing.T) {
	path := fixtureFile(t, "[default]\nregion = unchanged\n")
	unrelated := filepath.Join(filepath.Dir(path), "unrelated")
	if err := os.WriteFile(unrelated, []byte("must remain untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(unrelated, path+".aalogin.lock"); err != nil {
		t.Fatal(err)
	}
	if err := Update(context.Background(), path, "default", map[string]string{"region": "new"}); err == nil {
		t.Fatal("followed an unexpected lock-file symlink")
	}
	if readFixture(t, path) != "[default]\nregion = unchanged\n" || readFixture(t, unrelated) != "must remain untouched" {
		t.Fatal("rejected lock changed files")
	}
}
