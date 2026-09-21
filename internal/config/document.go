package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

// Document retains the original shared INI bytes. Only requested scalar values
// are replaced when a document is updated; unrelated syntax is not regenerated.
type Document struct {
	path     string
	data     []byte
	sections []section
}

type section struct {
	name  string
	start int
	body  int
	end   int
}

type entry struct {
	key        string
	value      string
	valueStart int
	valueEnd   int
	indent     int
	nested     bool
}

type sourceLine struct {
	start      int
	contentEnd int
	end        int
}

var ownedKeys = map[string]bool{
	"azure_tenant_id":              true,
	"azure_app_id_uri":             true,
	"azure_default_username":       true,
	"azure_default_password":       true,
	"azure_default_role_arn":       true,
	"azure_default_duration_hours": true,
	"azure_default_remember_me":    true,
	"region":                       true,
	"aws_access_key_id":            true,
	"aws_secret_access_key":        true,
	"aws_session_token":            true,
	"aws_expiration":               true,
	"aalogin_role_arn":             true,
	"source_profile":               true,
	"role_arn":                     true,
	"external_id":                  true,
	"role_session_name":            true,
	"duration_seconds":             true,
	"credential_source":            true,
	"credential_process":           true,
	"mfa_serial":                   true,
	"web_identity_token_file":      true,
	"sso_session":                  true,
	"sso_start_url":                true,
	"sso_region":                   true,
	"sso_account_id":               true,
	"sso_role_name":                true,
}

// Load reads a shared INI file. A missing file is an empty document, while all
// other read errors are returned. Profile still requires its selected section.
func Load(path string) (*Document, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return parseDocument(path, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("read %s: not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return parseDocument(path, data)
}

func parseDocument(path string, data []byte) (*Document, error) {
	doc := &Document{path: path, data: data}
	for offset := 0; offset < len(data); {
		line := nextLine(data, offset)
		offset = line.end
		text := strings.TrimSpace(string(data[line.start:line.contentEnd]))
		if !strings.HasPrefix(text, "[") {
			continue
		}
		close := strings.IndexByte(text, ']')
		if close < 0 {
			return nil, fmt.Errorf("%s: malformed section header", path)
		}
		name := strings.TrimSpace(text[1:close])
		rest := strings.TrimSpace(text[close+1:])
		if err := validateSection(name); err != nil || (rest != "" && rest[0] != '#' && rest[0] != ';') {
			return nil, fmt.Errorf("%s: malformed section header", path)
		}
		if len(doc.sections) > 0 {
			doc.sections[len(doc.sections)-1].end = line.start
		}
		doc.sections = append(doc.sections, section{name: name, start: line.start, body: line.end, end: len(data)})
	}
	return doc, nil
}

func nextLine(data []byte, offset int) sourceLine {
	line := sourceLine{start: offset, contentEnd: len(data), end: len(data)}
	if n := bytes.IndexByte(data[offset:], '\n'); n >= 0 {
		line.contentEnd = offset + n
		line.end = line.contentEnd + 1
	}
	if line.contentEnd > line.start && data[line.contentEnd-1] == '\r' {
		line.contentEnd--
	}
	return line
}

func (d *Document) findSection(name string) (*section, error) {
	if err := validateSection(name); err != nil {
		return nil, err
	}
	var found *section
	for i := range d.sections {
		if d.sections[i].name != name {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%s: duplicate section [%s]", d.path, name)
		}
		found = &d.sections[i]
	}
	return found, nil
}

// Values returns the selected section's top-level values without environment
// overrides. Missing sections return an empty map. Nested settings' children
// are deliberately excluded, regardless of their key names.
func (d *Document) Values(name string) (map[string]string, error) {
	sec, err := d.findSection(name)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	if sec == nil {
		return values, nil
	}
	entries, err := d.entries(*sec, nil)
	if err != nil {
		return nil, err
	}
	for _, item := range entries {
		values[item.key] = item.value
	}
	return values, nil
}

func (d *Document) entries(sec section, additionalOwned map[string]string) ([]entry, error) {
	var entries []entry
	seen := make(map[string]bool)
	blockIndent := -1
	candidate := -1
	for offset := sec.body; offset < sec.end; {
		line := nextLine(d.data[:sec.end], offset)
		offset = line.end
		text := string(d.data[line.start:line.contentEnd])
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == ';' {
			continue
		}
		indent := indentation(text)
		if blockIndent >= 0 {
			if indent > blockIndent {
				continue
			}
			blockIndent = -1
		}
		equals := strings.IndexByte(text, '=')
		if equals < 0 {
			candidate = -1
			continue
		}
		if candidate >= 0 && indent > entries[candidate].indent {
			entries[candidate].nested = true
			blockIndent = entries[candidate].indent
			candidate = -1
			continue
		}
		candidate = -1
		key := strings.TrimSpace(text[:equals])
		if key == "" {
			continue
		}
		_, extraOwned := additionalOwned[key]
		if seen[key] && (ownedKeys[key] || extraOwned) {
			return nil, fmt.Errorf("%s: section [%s]: duplicate key %s", d.path, sec.name, key)
		}
		seen[key] = true
		raw := text[equals+1:]
		leftTrimmed := strings.TrimLeft(raw, " \t")
		start := line.start + equals + 1 + len(raw) - len(leftTrimmed)
		value := strings.TrimSpace(raw)
		end := start + len(strings.TrimRight(leftTrimmed, " \t"))
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		entries = append(entries, entry{key: key, value: value, valueStart: start, valueEnd: end, indent: indent})
		if value == "" {
			candidate = len(entries) - 1
		}
	}
	return entries, nil
}

func indentation(text string) int {
	width := 0
	for _, ch := range text {
		switch ch {
		case ' ':
			width++
		case '\t':
			width += 8 - width%8
		default:
			return width
		}
	}
	return width
}

// AzureProfiles enumerates only AWS config profile sections whose own file
// values contain both Azure identifiers. Environment values do not qualify an
// unrelated AWS, SSO, or service section for all-profile login.
func (d *Document) AzureProfiles() ([]string, error) {
	return d.profileNames(false)
}

// LoginProfileNames includes file-backed Entra roots and role-chain candidates.
// Invalid candidates remain visible so resolution can report their errors.
// Environment overrides never enroll unrelated sections.
func (d *Document) LoginProfileNames() ([]string, error) {
	return d.profileNames(true)
}

func (d *Document) profileNames(includeRoles bool) ([]string, error) {
	var names []string
	for _, sec := range d.sections {
		name := ""
		if sec.name == "default" {
			name = "default"
		} else if strings.HasPrefix(sec.name, "profile ") {
			name = strings.TrimPrefix(sec.name, "profile ")
		} else {
			continue
		}
		if err := validateProfileName(name); err != nil {
			return nil, fmt.Errorf("%s: invalid profile section: %w", d.path, err)
		}
		values, err := d.Values(sec.name)
		if err != nil {
			return nil, err
		}
		_, hasSource := values["source_profile"]
		_, hasRole := values["role_arn"]
		if (values["azure_tenant_id"] != "" && values["azure_app_id_uri"] != "") || (includeRoles && (hasSource || hasRole)) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func validateSection(name string) error {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name || strings.ContainsAny(name, "[]\r\n\x00") || !utf8.ValidString(name) {
		return fmt.Errorf("invalid INI section name")
	}
	return nil
}

func validateProfileName(name string) error {
	if err := validateSection(name); err != nil {
		return fmt.Errorf("invalid AWS profile name")
	}
	return nil
}

// ConfigSection maps a profile name to AWS shared-config section naming.
func ConfigSection(name string) string {
	if name == "default" {
		return "default"
	}
	return "profile " + name
}
