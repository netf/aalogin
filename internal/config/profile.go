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

	"aalogin/internal/saml"
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

// RoleStep describes one AssumeRole request, using the preceding source's credentials.
type RoleStep struct {
	Name            string
	RoleARN         string
	SourceProfile   string
	Region          string
	ExternalID      string
	RoleSessionName string
	DurationSeconds int32
}

// LoginProfile resolves a selected profile to its Entra source and ordered role chain.
type LoginProfile struct {
	Name   string
	Source Profile
	Steps  []RoleStep
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

// ResolveLoginProfile validates the entire source_profile graph before login.
// Role steps are returned in execution order, from the Entra source to the target.
func (d *Document) ResolveLoginProfile(name string) (LoginProfile, error) {
	result := LoginProfile{Name: name}
	seen := make(map[string]bool)
	current := name
	for {
		if err := validateProfileName(current); err != nil {
			return LoginProfile{}, err
		}
		if seen[current] {
			return LoginProfile{}, fmt.Errorf("%s: source_profile cycle at profile [%s]", d.path, ConfigSection(current))
		}
		seen[current] = true
		sectionName := ConfigSection(current)
		sec, err := d.findSection(sectionName)
		if err != nil {
			return LoginProfile{}, err
		}
		if sec == nil {
			return LoginProfile{}, fmt.Errorf("%s: profile [%s] does not exist", d.path, sectionName)
		}
		values, err := d.Values(sectionName)
		if err != nil {
			return LoginProfile{}, err
		}
		fail := func(message string) (LoginProfile, error) {
			return LoginProfile{}, fmt.Errorf("%s: section [%s]: %s", d.path, sectionName, message)
		}
		_, hasSource := values["source_profile"]
		_, hasRole := values["role_arn"]
		for _, key := range []string{
			"credential_source", "mfa_serial", "web_identity_token_file",
			"sso_session", "sso_start_url", "sso_region", "sso_account_id", "sso_role_name",
			"aws_access_key_id", "aws_secret_access_key", "aws_session_token",
		} {
			if _, exists := values[key]; exists {
				return fail(key + " authentication is unsupported for Entra login")
			}
		}
		if !hasSource && !hasRole {
			if len(result.Steps) > 0 && (values["azure_tenant_id"] == "" || values["azure_app_id_uri"] == "") {
				return fail("source_profile chain must end in a file-backed Entra profile")
			}
			result.Source, err = d.Profile(current)
			if err != nil {
				return LoginProfile{}, err
			}
			for left, right := 0, len(result.Steps)-1; left < right; left, right = left+1, right-1 {
				result.Steps[left], result.Steps[right] = result.Steps[right], result.Steps[left]
			}
			return result, nil
		}
		if _, exists := values["credential_process"]; exists {
			return fail("credential_process authentication is unsupported on role-chain profiles")
		}
		for key := range values {
			if strings.HasPrefix(key, "azure_") {
				return fail("ambiguous Entra and source_profile/role_arn authentication")
			}
		}
		if !hasSource || !hasRole || values["source_profile"] == "" || values["role_arn"] == "" {
			return fail("role-chain profiles require nonempty source_profile and role_arn")
		}
		step, err := parseRoleStep(current, values)
		if err != nil {
			return fail(err.Error())
		}
		result.Steps = append(result.Steps, step)
		current = step.SourceProfile
	}
}

var roleSessionPattern = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{2,64}$`)
var externalIDPattern = regexp.MustCompile(`^[A-Za-z0-9_+=,.@:/-]+$`)
var secondsPattern = regexp.MustCompile(`^[0-9]+$`)

func parseRoleStep(name string, values map[string]string) (RoleStep, error) {
	step := RoleStep{
		Name:            name,
		RoleARN:         values["role_arn"],
		SourceProfile:   values["source_profile"],
		Region:          ResolveRegion(Profile{Region: values["region"]}),
		ExternalID:      values["external_id"],
		RoleSessionName: "aalogin",
		DurationSeconds: 3600,
	}
	if err := validateProfileName(step.SourceProfile); err != nil {
		return RoleStep{}, fmt.Errorf("source_profile: %w", err)
	}
	if err := validateValue(step.Region); err != nil {
		return RoleStep{}, fmt.Errorf("region: %w", err)
	}
	if err := saml.ValidateIAMRoleRegion(step.RoleARN, step.Region); err != nil {
		return RoleStep{}, fmt.Errorf("role_arn: %w", err)
	}
	if value, exists := values["role_session_name"]; exists {
		if !roleSessionPattern.MatchString(value) {
			return RoleStep{}, fmt.Errorf("role_session_name must be 2 to 64 characters using letters, digits, or _+=,.@-")
		}
		step.RoleSessionName = value
	}
	if value, exists := values["external_id"]; exists {
		if len(value) < 2 || len(value) > 1224 || !externalIDPattern.MatchString(value) {
			return RoleStep{}, fmt.Errorf("external_id must be 2 to 1224 characters using letters, digits, or _+=,.@:/-")
		}
	}
	if value, exists := values["duration_seconds"]; exists {
		seconds, err := strconv.ParseInt(value, 10, 32)
		if err != nil || !secondsPattern.MatchString(value) || seconds < 900 || seconds > 3600 {
			return RoleStep{}, fmt.Errorf("duration_seconds must be whole seconds between 900 and 3600 for role chaining")
		}
		step.DurationSeconds = int32(seconds)
	}
	return step, nil
}
