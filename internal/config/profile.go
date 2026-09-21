// Legacy configuration compatibility follows aws-azure-login.
// Copyright (c) 2022 aws-azure-login devs. Licensed under the MIT license.
package config

import (
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Paths struct {
	Config      string
	Credentials string
}

// ResolvePaths applies the two independent AWS shared-file overrides. Relative
// overrides are resolved against the invocation's current working directory.
func ResolvePaths() (Paths, error) {
	paths := Paths{Config: os.Getenv("AWS_CONFIG_FILE"), Credentials: os.Getenv("AWS_SHARED_CREDENTIALS_FILE")}
	if paths.Config == "" || paths.Credentials == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve AWS shared-file paths: %w", err)
		}
		if paths.Config == "" {
			paths.Config = filepath.Join(home, ".aws", "config")
		}
		if paths.Credentials == "" {
			paths.Credentials = filepath.Join(home, ".aws", "credentials")
		}
	}
	var err error
	paths.Config, err = filepath.Abs(paths.Config)
	if err != nil {
		return Paths{}, fmt.Errorf("resolve AWS config path: %w", err)
	}
	paths.Credentials, err = filepath.Abs(paths.Credentials)
	if err != nil {
		return Paths{}, fmt.Errorf("resolve AWS credentials path: %w", err)
	}
	return paths, nil
}

type Profile struct {
	Name          string
	Tenant        string
	AppID         string
	Username      string
	Password      string
	RoleARN       string
	DurationHours string
	Region        string
	RememberMe    bool
}

// Profile loads a selected shared-config profile, applying nonempty lowercase
// then uppercase legacy environment overrides to the six upstream fields.
func (d *Document) Profile(name string) (Profile, error) {
	return d.profile(name, false)
}

// ConfigureProfile applies the same parsing and precedence as Profile, while
// permitting a new section and missing required tenant/app values to be seeded
// by interactive configuration. Malformed existing typed values still fail.
func (d *Document) ConfigureProfile(name string) (Profile, error) {
	return d.profile(name, true)
}

func (d *Document) profile(name string, allowMissing bool) (Profile, error) {
	if err := validateProfileName(name); err != nil {
		return Profile{}, err
	}
	sectionName := ConfigSection(name)
	sec, err := d.findSection(sectionName)
	if err != nil {
		return Profile{}, err
	}
	if sec == nil && !allowMissing {
		return Profile{}, fmt.Errorf("%s: profile [%s] does not exist; run --configure --profile %s", d.path, sectionName, name)
	}
	values, err := d.Values(sectionName)
	if err != nil {
		return Profile{}, err
	}
	profile := Profile{
		Name:          name,
		Tenant:        legacyValue(values, "azure_tenant_id"),
		AppID:         legacyValue(values, "azure_app_id_uri"),
		Username:      legacyValue(values, "azure_default_username"),
		Password:      legacyValue(values, "azure_default_password"),
		RoleARN:       legacyValue(values, "azure_default_role_arn"),
		DurationHours: legacyValue(values, "azure_default_duration_hours"),
		Region:        values["region"],
	}
	if profile.DurationHours == "" {
		if _, exists := values["azure_default_duration_hours"]; exists {
			return Profile{}, fmt.Errorf("%s: section [%s]: azure_default_duration_hours must not be empty", d.path, sectionName)
		}
		profile.DurationHours = "12"
	}
	if value, exists := values["azure_default_remember_me"]; exists {
		switch value {
		case "true":
			profile.RememberMe = true
		case "false":
		default:
			return Profile{}, fmt.Errorf("%s: section [%s]: azure_default_remember_me must be true or false", d.path, sectionName)
		}
	}
	if err := profile.validateValues(); err != nil {
		return Profile{}, fmt.Errorf("%s: section [%s]: %w", d.path, sectionName, err)
	}
	if !allowMissing {
		if err := profile.Validate(); err != nil {
			return Profile{}, fmt.Errorf("%s: section [%s]: %w", d.path, sectionName, err)
		}
	}
	return profile, nil
}

func legacyValue(values map[string]string, key string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	if value := os.Getenv(strings.ToUpper(key)); value != "" {
		return value
	}
	return values[key]
}

var tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var decimalPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

// Validate rejects invalid required identifiers, configuration injection, and
// durations AWS cannot accept. Password contents are never included in errors.
func (p Profile) Validate() error {
	if err := validateProfileName(p.Name); err != nil {
		return err
	}
	if err := p.validateValues(); err != nil {
		return err
	}
	if p.Tenant == "" {
		return fmt.Errorf("azure_tenant_id is required; run --configure")
	}
	if strings.TrimSpace(p.AppID) == "" {
		return fmt.Errorf("azure_app_id_uri is required; run --configure")
	}
	return nil
}

func (p Profile) validateValues() error {
	fields := []struct{ key, value string }{
		{"azure_tenant_id", p.Tenant},
		{"azure_app_id_uri", p.AppID},
		{"azure_default_username", p.Username},
		{"azure_default_password", p.Password},
		{"azure_default_role_arn", p.RoleARN},
		{"azure_default_duration_hours", p.DurationHours},
		{"region", p.Region},
	}
	for _, field := range fields {
		if err := validateValue(field.value); err != nil {
			return fmt.Errorf("%s: %w", field.key, err)
		}
	}
	if p.Tenant != "" && !tenantPattern.MatchString(p.Tenant) {
		return fmt.Errorf("azure_tenant_id must be a single tenant domain or ID, not a URL")
	}
	if _, err := p.DurationSeconds(); err != nil {
		return err
	}
	return nil
}

func validateValue(value string) error {
	if strings.ContainsAny(value, "\r\n\x00") || !utf8.ValidString(value) {
		return fmt.Errorf("configuration values must be single-line UTF-8 text")
	}
	return nil
}

// DurationSeconds evaluates decimal hours exactly, not by floating-point
// truncation. The preliminary float parse only bounds the value; rational
// arithmetic decides whether it represents an integral number of seconds.
func (p Profile) DurationSeconds() (int32, error) {
	value := p.DurationHours
	if value == "" {
		value = "12"
	}
	invalid := func() (int32, error) {
		return 0, fmt.Errorf("azure_default_duration_hours must represent whole seconds between 900 and 43200 (0.25 to 12 hours)")
	}
	if !decimalPattern.MatchString(value) {
		return invalid()
	}
	hours, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(hours) || math.IsInf(hours, 0) || hours < 0.25 || hours > 12 {
		return invalid()
	}
	rational, ok := new(big.Rat).SetString(value)
	if !ok {
		return invalid()
	}
	rational.Mul(rational, big.NewRat(3600, 1))
	if !rational.IsInt() || !rational.Num().IsInt64() {
		return invalid()
	}
	seconds := rational.Num().Int64()
	if seconds < 900 || seconds > 43200 {
		return invalid()
	}
	return int32(seconds), nil
}

// ResolveRegion does not load the SDK's default credential chain.
func ResolveRegion(p Profile) string {
	if region := os.Getenv("AWS_REGION"); region != "" {
		return region
	}
	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
		return region
	}
	if p.Region != "" {
		return p.Region
	}
	return "us-east-1"
}
