// Package saml implements request construction and untrusted assertion role selection.
// Parsing an assertion does not authenticate it; AWS STS verifies its signature and validity.
package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	MaxAssertionLength = 100000
	protocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	assertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	roleAttributeName  = "https://aws.amazon.com/SAML/Attributes/Role"
	successStatus      = "urn:oasis:names:tc:SAML:2.0:status:Success"
)

var errInvalidIAMARN = errors.New("SAML role attribute contains an invalid IAM role or SAML provider ARN")

type Role struct {
	RoleARN      string
	PrincipalARN string
}

type authnRequest struct {
	XMLName                     xml.Name     `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string       `xml:"ID,attr"`
	Version                     string       `xml:"Version,attr"`
	IssueInstant                string       `xml:"IssueInstant,attr"`
	IsPassive                   string       `xml:"IsPassive,attr"`
	AssertionConsumerServiceURL string       `xml:"AssertionConsumerServiceURL,attr"`
	Issuer                      string       `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDPolicy                nameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
}

type nameIDPolicy struct {
	Format string `xml:"Format,attr"`
}

func BuildLoginURL(tenant, appID, acs string, now time.Time) (string, error) {
	if tenant == "" || tenant == "." || tenant == ".." {
		return "", errors.New("Azure tenant must be a tenant UUID or domain in one URL path segment")
	}
	for _, char := range tenant {
		if char != '.' && char != '-' && (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
			return "", errors.New("Azure tenant must be a tenant UUID or domain in one URL path segment")
		}
	}
	if strings.TrimSpace(appID) == "" {
		return "", errors.New("Azure app ID URI is required")
	}
	callback, err := url.Parse(acs)
	if err != nil || callback.Scheme != "https" || callback.Host == "" || callback.User != nil || callback.Fragment != "" {
		return "", errors.New("SAML assertion consumer URL must be HTTPS")
	}
	var randomID [20]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return "", errors.New("cannot generate SAML request ID")
	}
	request, err := xml.Marshal(authnRequest{
		ID: "id" + hex.EncodeToString(randomID[:]), Version: "2.0",
		IssueInstant: now.UTC().Format(time.RFC3339Nano), IsPassive: "false",
		AssertionConsumerServiceURL: acs, Issuer: appID,
		NameIDPolicy: nameIDPolicy{Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"},
	})
	if err != nil {
		return "", errors.New("cannot encode SAML request")
	}
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		return "", errors.New("cannot create SAML compressor")
	}
	if _, err := writer.Write(request); err != nil {
		writer.Close()
		return "", errors.New("cannot compress SAML request")
	}
	if err := writer.Close(); err != nil {
		return "", errors.New("cannot finish SAML request compression")
	}
	query := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(compressed.Bytes())}}
	login := url.URL{Scheme: "https", Host: "login.microsoftonline.com", Path: "/" + tenant + "/saml2", RawQuery: query.Encode()}
	return login.String(), nil
}

// ACSURL selects the AWS sign-in partition, not an STS endpoint.
func ACSURL(region string) string {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		return "https://signin.amazonaws-us-gov.com/saml"
	case strings.HasPrefix(region, "cn-"):
		return "https://signin.amazonaws.cn/saml"
	default:
		return "https://signin.aws.amazon.com/saml"
	}
}

func ParseRoles(assertion string) ([]Role, error) {
	if len(assertion) == 0 || len(assertion) > MaxAssertionLength || strings.ContainsAny(assertion, "\r\n\t ") {
		return nil, errors.New("SAML assertion is empty, oversized, or invalid base64")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(assertion)
	if err != nil {
		return nil, errors.New("SAML assertion is invalid base64")
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var stack []xml.Name
	var pairs []string
	var value strings.Builder
	var rootSeen, rootClosed, statusSeen, statusOK bool
	attributeDepth, valueDepth := 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("SAML assertion contains malformed XML")
		}
		switch token := token.(type) {
		case xml.Directive:
			return nil, errors.New("SAML assertion must not contain XML directives")
		case xml.ProcInst:
			if token.Target != "xml" || rootSeen {
				return nil, errors.New("SAML assertion contains an unexpected XML instruction")
			}
		case xml.StartElement:
			if len(token.Attr) > 1 {
				seen := make(map[xml.Name]struct{}, len(token.Attr))
				for _, attr := range token.Attr {
					if _, duplicate := seen[attr.Name]; duplicate {
						return nil, errors.New("SAML assertion contains duplicate XML attributes")
					}
					seen[attr.Name] = struct{}{}
				}
			}
			if valueDepth != 0 {
				return nil, errors.New("SAML role values must contain only text")
			}
			if len(stack) == 0 {
				if rootSeen || token.Name != (xml.Name{Space: protocolNamespace, Local: "Response"}) {
					return nil, errors.New("SAML assertion must contain one SAML Response")
				}
				rootSeen = true
			}
			stack = append(stack, token.Name)
			depth := len(stack)
			if depth == 3 && stack[1] == (xml.Name{Space: protocolNamespace, Local: "Status"}) && token.Name == (xml.Name{Space: protocolNamespace, Local: "StatusCode"}) {
				if statusSeen {
					return nil, errors.New("SAML response has duplicate status codes")
				}
				statusSeen = true
				statusOK = attribute(token.Attr, "Value") == successStatus
			}
			if depth == 4 && stack[1] == (xml.Name{Space: assertionNamespace, Local: "Assertion"}) && stack[2] == (xml.Name{Space: assertionNamespace, Local: "AttributeStatement"}) && token.Name == (xml.Name{Space: assertionNamespace, Local: "Attribute"}) && attribute(token.Attr, "Name") == roleAttributeName {
				attributeDepth = depth
			}
			if attributeDepth != 0 && depth == attributeDepth+1 && token.Name == (xml.Name{Space: assertionNamespace, Local: "AttributeValue"}) {
				valueDepth = depth
				value.Reset()
			}
		case xml.CharData:
			if valueDepth != 0 {
				value.Write(token)
			} else if len(stack) == 0 && strings.TrimSpace(string(token)) != "" {
				return nil, errors.New("SAML assertion contains text outside its response")
			}
		case xml.EndElement:
			depth := len(stack)
			if depth == valueDepth {
				pairs = append(pairs, value.String())
				valueDepth = 0
			}
			if depth == attributeDepth {
				attributeDepth = 0
			}
			stack = stack[:depth-1]
			if depth == 1 {
				rootClosed = true
			}
		}
	}
	if !rootSeen || !rootClosed || len(stack) != 0 {
		return nil, errors.New("SAML assertion contains incomplete XML")
	}
	if !statusSeen || !statusOK {
		return nil, errors.New("SAML response did not report success")
	}
	if len(pairs) == 0 {
		return nil, errors.New("SAML response contains no AWS IAM roles")
	}
	roles := make([]Role, 0, len(pairs))
	providers := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		parts := strings.Split(pair, ",")
		if len(parts) != 2 {
			return nil, errors.New("SAML role attribute must contain one role and one provider ARN")
		}
		first, second := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		partition1, account1, kind1, err := parseIAMARN(first)
		if err != nil {
			return nil, err
		}
		partition2, account2, kind2, err := parseIAMARN(second)
		if err != nil {
			return nil, err
		}
		if partition1 != partition2 || account1 != account2 || kind1 == kind2 {
			return nil, errors.New("SAML role/provider ARNs must have matching accounts and partitions and distinct types")
		}
		role := Role{RoleARN: first, PrincipalARN: second}
		if kind1 == "saml-provider" {
			role.RoleARN, role.PrincipalARN = second, first
		}
		if provider, exists := providers[role.RoleARN]; exists {
			if provider != role.PrincipalARN {
				return nil, errors.New("SAML response assigns multiple providers to the same role")
			}
			continue
		}
		providers[role.RoleARN] = role.PrincipalARN
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].RoleARN < roles[j].RoleARN })
	return roles, nil
}

func attribute(attrs []xml.Attr, name string) string {
	for _, attr := range attrs {
		if attr.Name.Space == "" && attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}

func parseIAMARN(value string) (partition, account, kind string, err error) {
	invalid := errInvalidIAMARN
	parts := strings.SplitN(value, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || parts[3] != "" || len(parts[4]) != 12 || strings.IndexFunc(value, unicode.IsSpace) >= 0 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", "", "", invalid
	}
	if (parts[1] != "aws" && !strings.HasPrefix(parts[1], "aws-")) || strings.HasSuffix(parts[1], "-") {
		return "", "", "", invalid
	}
	for _, char := range parts[1] {
		if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return "", "", "", invalid
		}
	}
	for _, char := range parts[4] {
		if char < '0' || char > '9' {
			return "", "", "", invalid
		}
	}
	kind, name, found := strings.Cut(parts[5], "/")
	if !found || name == "" || strings.HasSuffix(name, "/") || strings.Contains(name, ":") || (kind != "role" && kind != "saml-provider") || (kind == "saml-provider" && strings.Contains(name, "/")) {
		return "", "", "", invalid
	}
	return parts[1], parts[4], kind, nil
}

// ValidateRoleRegion rejects an accidental cross-partition role selection.
func ValidateRoleRegion(role Role, region string) error {
	partition, account, kind, err := parseIAMARN(role.RoleARN)
	if err != nil || kind != "role" {
		return errors.New("selected role ARN is invalid")
	}
	providerPartition, providerAccount, providerKind, err := parseIAMARN(role.PrincipalARN)
	if err != nil || providerKind != "saml-provider" || providerPartition != partition || providerAccount != account {
		return errors.New("selected provider ARN does not match the role")
	}
	want := "aws"
	if strings.HasPrefix(region, "us-gov-") {
		want = "aws-us-gov"
	} else if strings.HasPrefix(region, "cn-") {
		want = "aws-cn"
	}
	if partition != want {
		return errors.New("selected role partition does not match the AWS region; configure the matching region")
	}
	return nil
}

// SelectRole uses zero-based indexes for choose; -1 means there is no configured default.
func SelectRole(roles []Role, defaultARN string, noPrompt bool, choose func([]Role, int) (int, error)) (Role, error) {
	if len(roles) == 0 {
		return Role{}, errors.New("SAML response contains no AWS IAM roles")
	}
	allIdentityCenter := true
	for _, role := range roles {
		name := role.RoleARN[strings.LastIndex(role.RoleARN, "/")+1:]
		if !strings.HasPrefix(name, "AWSReservedSSO_") {
			allIdentityCenter = false
			break
		}
	}
	if allIdentityCenter {
		return Role{}, errors.New("only IAM Identity Center AWSReservedSSO_ roles were offered; AssumeRoleWithSAML cannot use these roles; configure an IAM role for the Entra SAML provider instead")
	}
	defaultIndex := -1
	for index, role := range roles {
		if role.RoleARN == defaultARN {
			defaultIndex = index
			break
		}
	}
	if defaultARN != "" && defaultIndex == -1 {
		return Role{}, errors.New("configured default role is not present in the SAML response; update azure_default_role_arn")
	}
	if len(roles) == 1 {
		return roles[0], nil
	}
	if noPrompt {
		if defaultIndex == -1 {
			return Role{}, errors.New("multiple roles require azure_default_role_arn; rerun without --no-prompt to select a role")
		}
		return roles[defaultIndex], nil
	}
	if choose == nil {
		return Role{}, errors.New("interaction required; rerun without --no-prompt")
	}
	index, err := choose(roles, defaultIndex)
	if err != nil {
		return Role{}, err
	}
	if index < 0 || index >= len(roles) {
		return Role{}, fmt.Errorf("role choice must be between 1 and %d", len(roles))
	}
	return roles[index], nil
}
