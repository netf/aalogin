package login

import (
	"bytes"
	"context"
	"os"
	"testing"

	"aalogin/internal/cli"
)

func TestConfigureInvalidInputPreservesFiles(t *testing.T) {
	r, _, out, _, credentials := fixture(t)
	path := os.Getenv("AWS_CONFIG_FILE")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := os.ReadFile(credentials)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZURE_TENANT_ID", "https://not-a-tenant")
	err = r.Run(context.Background(), cli.Options{Configure: true, Profile: "fixture", NoPrompt: true})
	if err == nil || !IsConfigError(err) {
		t.Fatalf("expected configuration error, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	afterCreds, err := os.ReadFile(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || !bytes.Equal(creds, afterCreds) || out.Len() != 0 {
		t.Fatal("invalid configure changed files or emitted stdout")
	}
}

func TestConfigurePreservesLegacyPasswordWithoutPrintingIt(t *testing.T) {
	r, _, out, diag, _ := fixture(t)
	path := os.Getenv("AWS_CONFIG_FILE")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("azure_default_password = synthetic-password!#;\n")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	err = r.Run(context.Background(), cli.Options{Configure: true, Profile: "fixture", NoPrompt: true})
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(after, []byte("azure_default_password = synthetic-password!#;\n")) {
		t.Fatal("legacy password changed")
	}
	if bytes.Contains(diag.Bytes(), []byte("synthetic-password")) || out.Len() != 0 {
		t.Fatal("configure leaked password")
	}
}
