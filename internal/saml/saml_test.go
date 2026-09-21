package saml

import (
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	roleA    = "arn:aws:iam::123456789012:role/Alpha"
	roleB    = "arn:aws:iam::123456789012:role/path/Beta"
	provider = "arn:aws:iam::123456789012:saml-provider/Entra"
)

func response(values ...string) string {
	var data strings.Builder
	data.WriteString(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion"><p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></p:Status><a:Assertion><a:AttributeStatement><a:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">`)
	for _, value := range values {
		data.WriteString("<a:AttributeValue>")
		xml.EscapeText(&data, []byte(value))
		data.WriteString("</a:AttributeValue>")
	}
	data.WriteString("</a:Attribute></a:AttributeStatement></a:Assertion></p:Response>")
	return base64.StdEncoding.EncodeToString([]byte(data.String()))
}

func changeXML(assertion string, change func(string) string) string {
	data, _ := base64.StdEncoding.DecodeString(assertion)
	return base64.StdEncoding.EncodeToString([]byte(change(string(data))))
}

func TestAuthnRequestRoundTrip(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.FixedZone("offset", 3600))
	app := `https://example.invalid/app?first="one"&second=<two>`
	login, err := BuildLoginURL("example.onmicrosoft.com", app, ACSURL("cn-north-1"), now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(login)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "login.microsoftonline.com" || parsed.Path != "/example.onmicrosoft.com/saml2" {
		t.Fatalf("unexpected login location: %s", login)
	}
	data, err := base64.StdEncoding.Strict().DecodeString(parsed.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	reader := flate.NewReader(strings.NewReader(string(data)))
	defer reader.Close()
	request, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("request must use raw DEFLATE: %v", err)
	}
	var decoded authnRequest
	if err := xml.Unmarshal(request, &decoded); err != nil {
		t.Fatal(err)
	}
	// Entra requires a UTC .NET round-trip DateTime, not nine-digit nanoseconds.
	if decoded.IssueInstant != "2026-01-02T02:04:05.1234567Z" {
		t.Fatalf("IssueInstant must use Entra-compatible UTC precision: %q", decoded.IssueInstant)
	}
	if decoded.XMLName.Space != protocolNamespace || decoded.Version != "2.0" || decoded.IsPassive != "false" || decoded.Issuer != app || decoded.AssertionConsumerServiceURL != "https://signin.amazonaws.cn/saml" || decoded.NameIDPolicy.Format != "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" {
		t.Fatalf("AuthnRequest did not round-trip: %#v", decoded)
	}
	if !strings.HasPrefix(decoded.ID, "id") || len(decoded.ID) < 34 {
		t.Fatalf("invalid request ID: %q", decoded.ID)
	}
	second, err := BuildLoginURL("example.onmicrosoft.com", app, ACSURL("cn-north-1"), now)
	if err != nil {
		t.Fatal(err)
	}
	if second == login {
		t.Fatal("request IDs must be independently random")
	}
	for _, tenant := range []string{"", "../other", "example?query", "example#fragment", "example%2fother", "user@example", "a\nb"} {
		if _, err := BuildLoginURL(tenant, app, ACSURL("us-east-1"), now); err == nil {
			t.Fatalf("accepted unsafe tenant %q", tenant)
		}
	}
}

func TestParseRolesNamespacesOrderingAndDeduplication(t *testing.T) {
	roles, err := ParseRoles(response(provider+", "+roleB, " "+roleA+" , "+provider+" ", roleB+","+provider))
	if err != nil {
		t.Fatal(err)
	}
	want := []Role{{roleA, provider}, {roleB, provider}}
	if len(roles) != len(want) {
		t.Fatalf("roles: %#v", roles)
	}
	for index := range want {
		if roles[index] != want[index] {
			t.Fatalf("roles: %#v", roles)
		}
	}
}

func TestParseRolesRejectsUntrustedMalformedResponses(t *testing.T) {
	valid := response(roleA + "," + provider)
	cases := map[string]string{
		"empty":                "",
		"invalid base64":       "!!!!",
		"noncanonical padding": "Zh==",
		"base64 whitespace":    valid + "\n",
		"oversized":            strings.Repeat("A", MaxAssertionLength+1),
		"missing roles":        response(),
		"role only":            response(roleA),
		"provider only":        response(provider + "," + provider),
		"non IAM":              response("arn:aws:s3::123456789012:role/Alpha," + provider),
		"wrong account":        response(roleA + ",arn:aws:iam::999999999999:saml-provider/Entra"),
		"wrong partition":      response(roleA + ",arn:aws-cn:iam::123456789012:saml-provider/Entra"),
		"ambiguous provider":   response(roleA+","+provider, roleA+",arn:aws:iam::123456789012:saml-provider/Other"),
		"failed status":        changeXML(valid, func(value string) string { return strings.Replace(value, ":status:Success", ":status:Responder", 1) }),
		"missing status": changeXML(valid, func(value string) string {
			start := strings.Index(value, "<p:Status>")
			end := strings.Index(value, "</p:Status>") + len("</p:Status>")
			return value[:start] + value[end:]
		}),
		"wrong namespace":    changeXML(valid, func(value string) string { return strings.ReplaceAll(value, assertionNamespace, "urn:wrong") }),
		"doctype":            changeXML(valid, func(value string) string { return "<!DOCTYPE Response>" + value }),
		"malformed XML":      changeXML(valid, func(value string) string { return value[:len(value)-5] }),
		"multiple responses": changeXML(valid, func(value string) string { return value + value }),
		"nested role text": changeXML(valid, func(value string) string {
			return strings.Replace(value, "<a:AttributeValue>", "<a:AttributeValue><a:child/>", 1)
		}),
		"duplicate XML attributes": changeXML(valid, func(value string) string {
			return strings.Replace(value, "<p:StatusCode ", `<p:StatusCode Value="" `, 1)
		}),
	}
	for name, assertion := range cases {
		t.Run(name, func(t *testing.T) {
			roles, err := ParseRoles(assertion)
			if err == nil || len(roles) != 0 {
				t.Fatalf("accepted malformed response: %#v, %v", roles, err)
			}
			if strings.Contains(err.Error(), roleA) || strings.Contains(err.Error(), assertion) && assertion != "" {
				t.Fatalf("diagnostic contains assertion contents: %s", err)
			}
		})
	}
}

func TestSelectRoleExplainsIdentityCenterMismatch(t *testing.T) {
	reserved := Role{"arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_Admin_0123456789abcdef", provider}
	for _, roles := range [][]Role{{reserved}, {reserved, {"arn:aws:iam::123456789012:role/AWSReservedSSO_ReadOnly_0123456789abcdef", provider}}} {
		_, err := SelectRole(roles, reserved.RoleARN, true, nil)
		if err == nil || !strings.Contains(err.Error(), "IAM Identity Center") || !strings.Contains(err.Error(), "AssumeRoleWithSAML") {
			t.Fatalf("missing actionable Identity Center mismatch: %v", err)
		}
	}
	mixed := []Role{reserved, {roleA, provider}}
	chosen, err := SelectRole(mixed, roleA, true, nil)
	if err != nil || chosen.RoleARN != roleA {
		t.Fatalf("mixed roles rejected a valid configured role: %#v, %v", chosen, err)
	}
	chosen, err = SelectRole(mixed, "", false, func([]Role) (int, error) { return 1, nil })
	if err != nil || chosen.RoleARN != roleA {
		t.Fatalf("mixed roles rejected an interactive valid role: %#v, %v", chosen, err)
	}
}

func TestSelectRoleDoesNotSilentlySwitchPrivileges(t *testing.T) {
	roles := []Role{{roleA, provider}, {roleB, provider}}
	if _, err := SelectRole(roles[:1], roleB, false, nil); err == nil {
		t.Fatal("stale default silently switched a single role")
	}
	if _, err := SelectRole(roles, "arn:aws:iam::123456789012:role/Missing", true, nil); err == nil {
		t.Fatal("stale default silently switched roles")
	}
	if _, err := SelectRole(roles, "", true, nil); err == nil {
		t.Fatal("no-prompt selected a role without a default")
	}
	chosen, err := SelectRole(roles, roleB, true, func([]Role) (int, error) { t.Fatal("no-prompt requested input"); return 0, nil })
	if err != nil || chosen.RoleARN != roleB {
		t.Fatalf("default role: %#v, %v", chosen, err)
	}
	chosen, err = SelectRole(roles, roleB, false, func([]Role) (int, error) {
		t.Fatal("configured role requested input")
		return 0, nil
	})
	if err != nil || chosen.RoleARN != roleB {
		t.Fatalf("configured role: %#v, %v", chosen, err)
	}
	if _, err := SelectRole(roles, "", false, func([]Role) (int, error) { return len(roles), nil }); err == nil {
		t.Fatal("out-of-range choice accepted")
	}
	cancel := errors.New("choice canceled")
	if _, err := SelectRole(roles, "", false, func([]Role) (int, error) { return 0, cancel }); !errors.Is(err, cancel) {
		t.Fatalf("lost choice cancellation: %v", err)
	}
}

func TestRoleRegionPartition(t *testing.T) {
	for _, item := range []struct{ region, partition, acs string }{
		{"us-east-1", "aws", "https://signin.aws.amazon.com/saml"},
		{"us-gov-west-1", "aws-us-gov", "https://signin.amazonaws-us-gov.com/saml"},
		{"cn-north-1", "aws-cn", "https://signin.amazonaws.cn/saml"},
	} {
		role := Role{strings.Replace(roleA, "arn:aws:", "arn:"+item.partition+":", 1), strings.Replace(provider, "arn:aws:", "arn:"+item.partition+":", 1)}
		if ACSURL(item.region) != item.acs {
			t.Fatalf("wrong ACS for %s", item.region)
		}
		if err := ValidateRoleRegion(role, item.region); err != nil {
			t.Fatal(err)
		}
		if err := ValidateIAMRoleRegion(role.RoleARN, item.region); err != nil {
			t.Fatal(err)
		}
		if err := ValidateRoleRegion(role, "cn-other-1"); (err == nil) != (item.partition == "aws-cn") {
			t.Fatalf("partition validation: %v", err)
		}
	}
}

func TestStandaloneRoleRegionRejectsInvalidRoles(t *testing.T) {
	for _, arn := range []string{
		provider,
		"arn:aws:iam::123:role/Test",
		"arn:aws-other:iam::123456789012:role/Test",
		"arn:aws-cn:iam::123456789012:role/Test",
		"arn:aws:iam::123456789012:role/",
		"arn:aws:iam::123456789012:role/path/",
		"arn:aws:iam::123456789012:role/invalid*name",
		"arn:aws:iam::123456789012:role/" + strings.Repeat("x", 65),
		"arn:aws:iam::123456789012:role/" + strings.Repeat("x", 512) + "/Name",
	} {
		if err := ValidateIAMRoleRegion(arn, "us-east-1"); err == nil {
			t.Errorf("accepted invalid standalone role %q", arn)
		}
	}
	if err := ValidateIAMRoleRegion("arn:aws:iam::123456789012:role/team/subteam/Role_+=,.@-", "us-east-1"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRoleRegion(Role{RoleARN: roleA, PrincipalARN: strings.Replace(provider, "123456789012", "999999999999", 1)}, "us-east-1"); err == nil {
		t.Fatal("standalone role validation bypassed SAML provider account validation")
	}
}
