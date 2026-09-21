// Package sts exchanges a SAML assertion without loading AWS credential sources.
package sts

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"aalogin/internal/saml"
	"aalogin/internal/transport"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

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
	httpClient, err := transport.NewHTTPClient(options)
	if err != nil {
		return Credentials{}, err
	}
	defer httpClient.CloseIdleConnections()
	sdk := awssts.NewFromConfig(aws.Config{
		Region:      region,
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  httpClient,
	}, func(options *awssts.Options) {
		if client.endpoint != "" {
			options.BaseEndpoint = aws.String(client.endpoint)
		}
	})
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
		return Credentials{}, safeExchangeError(err)
	}
	if result == nil || result.Credentials == nil {
		return Credentials{}, errors.New("STS returned no credentials")
	}
	credentials := result.Credentials
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

func safeExchangeError(err error) error {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		code := diagnosticToken(apiError.ErrorCode(), 64)
		if code == "" {
			code = "service error"
		}
		var requestError interface{ ServiceRequestID() string }
		if errors.As(err, &requestError) {
			if requestID := diagnosticToken(requestError.ServiceRequestID(), 128); requestID != "" {
				return fmt.Errorf("STS AssumeRoleWithSAML failed: %s (request ID %s)", code, requestID)
			}
		}
		return fmt.Errorf("STS AssumeRoleWithSAML failed: %s", code)
	}
	var certificateError *tls.CertificateVerificationError
	if errors.As(err, &certificateError) {
		return errors.New("STS TLS certificate verification failed; check the system trust store or AWS_CA_BUNDLE")
	}
	// Do not retain or wrap SDK errors: their messages can contain response bodies,
	// assertions, proxy userinfo, or credential-bearing request URLs.
	return errors.New("STS request failed; check the network, proxy, certificate configuration, and AWS region")
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
