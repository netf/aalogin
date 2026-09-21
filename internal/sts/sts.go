// Package sts exchanges SAML assertions and signs requests only with supplied credentials.
package sts

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"aalogin/internal/config"
	"aalogin/internal/saml"
	"aalogin/internal/transport"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
)

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

type Identity struct {
	Account string
	ARN     string
}

var (
	regionPattern      = regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$`)
	sessionNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_+=,.@-]{2,64}$`)
	externalIDPattern  = regexp.MustCompile(`^[a-zA-Z0-9_+=,.@:/-]+$`)
	accountPattern     = regexp.MustCompile(`^[0-9]{12}$`)
)

type TransportOptions = transport.Options

// Client's zero value is ready for production. Endpoint overrides are restricted
// to package-local fixtures; there is no CLI or environment endpoint bypass.
type Client struct {
	endpoint string
}

func (client Client) Exchange(ctx context.Context, assertion string, role saml.Role, duration int32, region string, options TransportOptions) (Credentials, error) {
	if err := ctx.Err(); err != nil {
		return Credentials{}, err
	}
	if assertion == "" || len(assertion) > saml.MaxAssertionLength {
		return Credentials{}, errors.New("SAML assertion is empty or exceeds the AWS size limit")
	}
	if duration < 900 || duration > 43200 {
		return Credentials{}, errors.New("STS duration must be between 900 and 43200 seconds")
	}
	if region == "" {
		return Credentials{}, errors.New("AWS region is required for STS")
	}
	if err := saml.ValidateRoleRegion(role, region); err != nil {
		return Credentials{}, err
	}
	sdk, closeIdle, err := client.sdk(region, aws.AnonymousCredentials{}, options)
	if err != nil {
		return Credentials{}, err
	}
	defer closeIdle()
	result, err := sdk.AssumeRoleWithSAML(ctx, &awssts.AssumeRoleWithSAMLInput{
		SAMLAssertion:   aws.String(assertion),
		RoleArn:         aws.String(role.RoleARN),
		PrincipalArn:    aws.String(role.PrincipalARN),
		DurationSeconds: aws.Int32(duration),
	})
	if err != nil {
		if ctx.Err() != nil {
			return Credentials{}, ctx.Err()
		}
		return Credentials{}, safeOperationError("AssumeRoleWithSAML", err)
	}
	if result == nil {
		return Credentials{}, errors.New("STS returned no credentials")
	}
	return temporaryCredentials(result.Credentials)
}

// Assume uses only source credentials, never the SDK's ambient credential chain.
func (client Client) Assume(ctx context.Context, source Credentials, step config.RoleStep, options TransportOptions) (Credentials, error) {
	if err := validateSignedInput(ctx, source, step.Region); err != nil {
		return Credentials{}, err
	}
	if err := saml.ValidateIAMRoleRegion(step.RoleARN, step.Region); err != nil {
		return Credentials{}, err
	}
	if step.DurationSeconds < 900 || step.DurationSeconds > 3600 {
		return Credentials{}, errors.New("STS role chaining duration must be between 900 and 3600 seconds")
	}
	sessionName := step.RoleSessionName
	if sessionName == "" {
		sessionName = "aalogin"
	}
	if !sessionNamePattern.MatchString(sessionName) {
		return Credentials{}, errors.New("STS role session name must contain 2–64 letters, digits, or _+=,.@- characters")
	}
	if step.ExternalID != "" && (len(step.ExternalID) < 2 || len(step.ExternalID) > 1224 || !externalIDPattern.MatchString(step.ExternalID)) {
		return Credentials{}, errors.New("STS external ID must contain 2–1224 letters, digits, or _+=,.@:/- characters")
	}
	sdk, closeIdle, err := client.sdk(step.Region, suppliedCredentials(source), options)
	if err != nil {
		return Credentials{}, err
	}
	defer closeIdle()
	input := &awssts.AssumeRoleInput{
		RoleArn:         aws.String(step.RoleARN),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(step.DurationSeconds),
	}
	if step.ExternalID != "" {
		input.ExternalId = aws.String(step.ExternalID)
	}
	result, err := sdk.AssumeRole(ctx, input)
	if err != nil {
		if ctx.Err() != nil {
			return Credentials{}, ctx.Err()
		}
		return Credentials{}, safeOperationError("AssumeRole", err)
	}
	if result == nil {
		return Credentials{}, errors.New("STS AssumeRole returned no credentials")
	}
	return temporaryCredentials(result.Credentials)
}

// Identity obtains the actual caller identity using only the supplied credentials.
func (client Client) Identity(ctx context.Context, creds Credentials, region string, options TransportOptions) (Identity, error) {
	if err := validateSignedInput(ctx, creds, region); err != nil {
		return Identity{}, err
	}
	sdk, closeIdle, err := client.sdk(region, suppliedCredentials(creds), options)
	if err != nil {
		return Identity{}, err
	}
	defer closeIdle()
	result, err := sdk.GetCallerIdentity(ctx, &awssts.GetCallerIdentityInput{})
	if err != nil {
		if ctx.Err() != nil {
			return Identity{}, ctx.Err()
		}
		return Identity{}, safeOperationError("GetCallerIdentity", err)
	}
	if result == nil {
		return Identity{}, errors.New("STS GetCallerIdentity returned no identity")
	}
	identity := Identity{Account: aws.ToString(result.Account), ARN: aws.ToString(result.Arn)}
	parts := strings.SplitN(identity.ARN, ":", 6)
	if !accountPattern.MatchString(identity.Account) || len(parts) != 6 || parts[0] != "arn" || (parts[2] != "sts" && parts[2] != "iam") || parts[3] != "" || parts[4] != identity.Account || parts[5] == "" || len(identity.ARN) > 2048 || strings.IndexFunc(identity.ARN, func(char rune) bool { return char < '!' || char > '~' }) >= 0 {
		return Identity{}, errors.New("STS GetCallerIdentity returned an incomplete or invalid identity")
	}
	wantPartition := "aws"
	if strings.HasPrefix(region, "us-gov-") {
		wantPartition = "aws-us-gov"
	} else if strings.HasPrefix(region, "cn-") {
		wantPartition = "aws-cn"
	}
	if parts[1] != wantPartition {
		return Identity{}, errors.New("STS GetCallerIdentity returned an identity from a different AWS partition")
	}
	return identity, nil
}

func validateSignedInput(ctx context.Context, source Credentials, region string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(source.AccessKeyID) == "" || strings.TrimSpace(source.SecretAccessKey) == "" || strings.TrimSpace(source.SessionToken) == "" || !source.Expiration.After(time.Now()) {
		return errors.New("STS requires complete, unexpired source session credentials")
	}
	if !regionPattern.MatchString(region) {
		return errors.New("a valid AWS region is required for STS")
	}
	return nil
}

func suppliedCredentials(source Credentials) aws.CredentialsProvider {
	return aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID:     source.AccessKeyID,
			SecretAccessKey: source.SecretAccessKey,
			SessionToken:    source.SessionToken,
			CanExpire:       true,
			Expires:         source.Expiration,
			Source:          "aalogin supplied credentials",
		}, nil
	})
}

func (client Client) sdk(region string, credentials aws.CredentialsProvider, options TransportOptions) (*awssts.Client, func(), error) {
	httpClient, err := transport.NewHTTPClient(options)
	if err != nil {
		return nil, nil, err
	}
	sdk := awssts.NewFromConfig(aws.Config{
		Region:      region,
		Credentials: credentials,
		HTTPClient:  httpClient,
	}, func(options *awssts.Options) {
		options.RetryMaxAttempts = 1
		if client.endpoint != "" {
			options.BaseEndpoint = aws.String(client.endpoint)
		}
	})
	return sdk, httpClient.CloseIdleConnections, nil
}

func temporaryCredentials(credentials *types.Credentials) (Credentials, error) {
	if credentials == nil {
		return Credentials{}, errors.New("STS returned no credentials")
	}
	if strings.TrimSpace(aws.ToString(credentials.AccessKeyId)) == "" || strings.TrimSpace(aws.ToString(credentials.SecretAccessKey)) == "" || strings.TrimSpace(aws.ToString(credentials.SessionToken)) == "" || credentials.Expiration == nil || !credentials.Expiration.After(time.Now()) {
		return Credentials{}, errors.New("STS returned incomplete or expired credentials")
	}
	return Credentials{
		AccessKeyID:     *credentials.AccessKeyId,
		SecretAccessKey: *credentials.SecretAccessKey,
		SessionToken:    *credentials.SessionToken,
		Expiration:      credentials.Expiration.UTC(),
	}, nil
}

func safeOperationError(operation string, err error) error {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		code := diagnosticToken(apiError.ErrorCode(), 64)
		if code == "" {
			code = "service error"
		}
		hint := ""
		if apiError.ErrorCode() == "ValidationError" {
			message := apiError.ErrorMessage()
			if strings.Contains(message, "DurationSeconds") || strings.Contains(message, "MaxSessionDuration") {
				if operation == "AssumeRoleWithSAML" {
					hint = "; request a shorter session with --duration 1h or lower azure_default_duration_hours in your configuration"
				} else if operation == "AssumeRole" {
					hint = "; lower duration_seconds in the target role profile (role chaining permits at most one hour)"
				}
			}
		}
		var requestError interface{ ServiceRequestID() string }
		if errors.As(err, &requestError) {
			if requestID := diagnosticToken(requestError.ServiceRequestID(), 128); requestID != "" {
				return fmt.Errorf("STS %s failed: %s (request ID %s)%s", operation, code, requestID, hint)
			}
		}
		return fmt.Errorf("STS %s failed: %s%s", operation, code, hint)
	}
	var certificateError *tls.CertificateVerificationError
	if errors.As(err, &certificateError) {
		return fmt.Errorf("STS %s TLS certificate verification failed; check the system trust store or AWS_CA_BUNDLE", operation)
	}
	// Do not retain or wrap SDK errors: their messages can contain response bodies,
	// assertions, proxy userinfo, or credential-bearing request URLs.
	return fmt.Errorf("STS %s request failed; check the network, proxy, certificate configuration, and AWS region", operation)
}

func diagnosticToken(value string, limit int) string {
	if len(value) == 0 || len(value) > limit {
		return ""
	}
	for _, char := range value {
		if char != '-' && char != '_' && char != '.' && char != ':' && (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
			return ""
		}
	}
	return value
}
