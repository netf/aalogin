package login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"aalogin/internal/browser"
	"aalogin/internal/cli"
	"aalogin/internal/config"
	"aalogin/internal/saml"
	"aalogin/internal/sts"
)

type configError struct{ error }

func IsConfigError(err error) bool { var target configError; return errors.As(err, &target) }
func invalid(err error) error      { return configError{err} }

type acquirer interface {
	Acquire(context.Context, browser.Options) (string, error)
}
type exchanger interface {
	Exchange(context.Context, string, saml.Role, int32, string, sts.TransportOptions) (sts.Credentials, error)
}

type roleAccess interface {
	Assume(context.Context, sts.Credentials, config.RoleStep, sts.TransportOptions) (sts.Credentials, error)
	Identity(context.Context, sts.Credentials, string, sts.TransportOptions) (sts.Identity, error)
}

type Runner struct {
	In       *os.File
	Out, Err io.Writer
	browser  acquirer
	sts      exchanger
	roles    roleAccess
	now      func() time.Time
}

func New(in *os.File, out, err io.Writer) *Runner {
	client := &sts.Client{}
	return &Runner{In: in, Out: out, Err: err, browser: &browser.Browser{}, sts: client, roles: client, now: time.Now}
}

func (r *Runner) Run(ctx context.Context, o cli.Options) error {
	paths, err := config.ResolvePaths()
	if err != nil {
		return invalid(err)
	}
	doc, err := config.Load(paths.Config)
	if err != nil {
		return invalid(err)
	}
	if o.Status {
		return r.status(ctx, paths, doc, o)
	}
	prompt := &cli.Prompt{In: r.In, Out: r.Err, NoPrompt: o.NoPrompt || o.CredentialProcess}
	if o.Configure {
		return r.configure(ctx, paths, doc, o, prompt)
	}
	names := []string{o.Profile}
	if o.AllProfiles {
		names, err = doc.AzureProfiles()
		if err != nil {
			return invalid(err)
		}
		if len(names) == 0 {
			return invalid(errors.New("no Azure profiles found"))
		}
	}
	// Validate every selected profile before starting any authentication.
	profiles := make([]config.LoginProfile, 0, len(names))
	for _, name := range names {
		p, e := doc.ResolveLoginProfile(name)
		if e != nil {
			return invalid(e)
		}
		profiles = append(profiles, p)
	}
	if o.NoVerifySSL {
		fmt.Fprintln(r.Err, "warning: STS TLS certificate verification is disabled")
	}
	if o.CredentialProcess {
		fmt.Fprintln(r.Err, "warning: existing static credentials take precedence over credential_process; remove them deliberately if appropriate")
	}
	for _, p := range profiles {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = r.warnLegacyPassword(doc, p.Source.Name); err != nil {
			return invalid(err)
		}
		if len(p.Steps) > 0 {
			fmt.Fprintf(r.Err, "%s: using source profile %s\n", p.Name, p.Source.Name)
		}
		creds, e := r.ensureSource(ctx, paths, o, p.Source, prompt)
		if e != nil {
			return fmt.Errorf("profile %s: %w", p.Source.Name, e)
		}
		if len(p.Steps) > 0 {
			creds, e = r.verifyTarget(ctx, o, p, creds)
			if e != nil {
				return fmt.Errorf("profile %s: %w", p.Name, e)
			}
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if o.CredentialProcess {
			return json.NewEncoder(r.Out).Encode(processCredentials{1, creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, creds.Expiration.UTC().Format(time.RFC3339)})
		}
	}
	return nil
}

func (r *Runner) warnLegacyPassword(doc *config.Document, name string) error {
	values, err := doc.Values(config.ConfigSection(name))
	if err != nil {
		return err
	}
	if _, exists := values["azure_default_password"]; exists {
		fmt.Fprintln(r.Err, "warning: legacy password key is preserved; prefer environment or interactive credentials")
	}
	return nil
}

type processCredentials struct {
	Version         int
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

func cachedCredentials(v map[string]string) (sts.Credentials, bool) {
	creds := sts.Credentials{AccessKeyID: v["aws_access_key_id"], SecretAccessKey: v["aws_secret_access_key"], SessionToken: v["aws_session_token"]}
	if strings.TrimSpace(creds.AccessKeyID) == "" || strings.TrimSpace(creds.SecretAccessKey) == "" || strings.TrimSpace(creds.SessionToken) == "" {
		return sts.Credentials{}, false
	}
	expiration, err := time.Parse(time.RFC3339, v["aws_expiration"])
	if err != nil {
		return sts.Credentials{}, false
	}
	creds.Expiration = expiration
	return creds, true
}

func fresh(v map[string]string, now time.Time) bool {
	creds, ok := cachedCredentials(v)
	return ok && creds.Expiration.After(now.Add(11*time.Minute))
}

func (r *Runner) ensureSource(ctx context.Context, paths config.Paths, o cli.Options, p config.Profile, prompt *cli.Prompt) (sts.Credentials, error) {
	if !o.ForceRefresh {
		doc, err := config.Load(paths.Credentials)
		if err != nil {
			return sts.Credentials{}, err
		}
		values, err := doc.Values(p.Name)
		if err != nil {
			return sts.Credentials{}, err
		}
		if fresh(values, r.now()) {
			creds, _ := cachedCredentials(values)
			role := values["aalogin_role_arn"]
			matches := p.RoleARN == "" || role == p.RoleARN
			if p.RoleARN != "" && role == "" {
				// Older caches have no role metadata. Confirm the identity rather
				// than silently using a different role from the configured one.
				checkCtx, cancel := context.WithTimeout(ctx, o.Timeout)
				identity, err := r.roles.Identity(checkCtx, creds, config.ResolveRegion(p), sts.TransportOptions{NoVerifySSL: o.NoVerifySSL})
				cancel()
				if err != nil {
					return sts.Credentials{}, fmt.Errorf("cannot verify cached role; use --force-refresh to authenticate again: %w", err)
				}
				matches = identityMatchesRole(identity, p.RoleARN)
			}
			if matches {
				fmt.Fprintf(r.Err, "%s: reusing cached credentials; expires %s\n", p.Name, creds.Expiration.Local().Format("02 Jan 2006, 15:04:05 MST (UTC-07:00)"))
				return creds, nil
			}
		}
	}
	session, err := r.authenticate(ctx, o, p, prompt)
	if err != nil {
		return sts.Credentials{}, err
	}
	if err = ctx.Err(); err != nil {
		return sts.Credentials{}, err
	}
	creds := session.credentials
	if !o.CredentialProcess {
		if err = config.Update(ctx, paths.Credentials, p.Name, map[string]string{
			"aws_access_key_id": creds.AccessKeyID, "aws_secret_access_key": creds.SecretAccessKey,
			"aws_session_token": creds.SessionToken, "aws_expiration": creds.Expiration.UTC().Format(time.RFC3339),
			"aalogin_role_arn": session.role.RoleARN,
		}); err != nil {
			return sts.Credentials{}, err
		}
	}
	fmt.Fprintf(r.Err, "%s: authenticated as %s\nExpires %s · requested %gh\n",
		p.Name, roleLabel(session.role), creds.Expiration.Local().Format("02 Jan 2006, 15:04:05 MST (UTC-07:00)"),
		float64(session.duration)/3600)
	return creds, nil
}

func (r *Runner) verifyTarget(ctx context.Context, o cli.Options, p config.LoginProfile, source sts.Credentials) (sts.Credentials, error) {
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	creds := source
	for _, step := range p.Steps {
		var err error
		creds, err = r.roles.Assume(ctx, creds, step, sts.TransportOptions{NoVerifySSL: o.NoVerifySSL})
		if err != nil {
			return sts.Credentials{}, fmt.Errorf("cannot assume role for %s: %w", step.Name, err)
		}
	}
	target := p.Steps[len(p.Steps)-1]
	identity, err := r.roles.Identity(ctx, creds, target.Region, sts.TransportOptions{NoVerifySSL: o.NoVerifySSL})
	if err != nil {
		return sts.Credentials{}, err
	}
	if !identityMatchesRole(identity, target.RoleARN) {
		return sts.Credentials{}, errors.New("AWS returned an identity different from the configured target role")
	}
	fmt.Fprintf(r.Err, "%s: verified access as %s\nTarget session expires %s; AWS manages target credentials through source_profile\n",
		p.Name, roleLabel(saml.Role{RoleARN: target.RoleARN}), creds.Expiration.Local().Format("02 Jan 2006, 15:04:05 MST (UTC-07:00)"))
	return creds, nil
}

func identityMatchesRole(identity sts.Identity, roleARN string) bool {
	parts := strings.SplitN(roleARN, ":", 6)
	if len(parts) != 6 || !strings.HasPrefix(parts[5], "role/") || identity.Account != parts[4] {
		return false
	}
	name := parts[5][strings.LastIndex(parts[5], "/")+1:]
	prefix := "arn:" + parts[1] + ":sts::" + parts[4] + ":assumed-role/" + name + "/"
	return strings.HasPrefix(identity.ARN, prefix) && len(identity.ARN) > len(prefix)
}

type loginSession struct {
	credentials sts.Credentials
	role        saml.Role
	duration    int32
}

func (r *Runner) authenticate(ctx context.Context, o cli.Options, p config.Profile, prompt *cli.Prompt) (loginSession, error) {
	var empty loginSession
	duration, err := p.DurationSeconds()
	if o.Duration != 0 {
		duration = int32(o.Duration / time.Second)
	}
	if err != nil {
		return empty, invalid(err)
	}
	region := config.ResolveRegion(p)
	loginURL, err := saml.BuildLoginURL(p.Tenant, p.AppID, saml.ACSURL(region), r.now())
	if err != nil {
		return empty, err
	}
	authCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	assertion, err := r.browser.Acquire(authCtx, browser.Options{Executable: o.Browser, Mode: o.Mode, Tenant: p.Tenant, Username: p.Username, Password: p.Password, LoginURL: loginURL, ACS: saml.ACSURL(region), RememberMe: p.RememberMe, NoPrompt: prompt.NoPrompt, CredentialProcess: o.CredentialProcess, NoSandbox: o.NoSandbox, EnableChromeNetworkService: o.EnableChromeNetworkService, EnableChromeSeamlessSSO: o.EnableChromeSeamlessSSO, NoDisableExtensions: o.NoDisableExtensions, DisableGPU: o.DisableGPU, TrustedLoginHosts: o.TrustedLoginHosts, Prompt: prompt, Out: r.Err})
	if err != nil {
		return empty, err
	}
	roles, err := saml.ParseRoles(assertion)
	if err != nil {
		return empty, err
	}
	if len(roles) > 1 && p.RoleARN == "" && !prompt.NoPrompt {
		fmt.Fprintf(r.Err, "AWS login · %s\n", p.Name)
	}
	role, err := selectRole(ctx, roles, p.RoleARN, prompt)
	if err != nil {
		return empty, err
	}
	if err = saml.ValidateRoleRegion(role, region); err != nil {
		return empty, err
	}
	creds, err := r.sts.Exchange(ctx, assertion, role, duration, region, sts.TransportOptions{NoVerifySSL: o.NoVerifySSL})
	if err != nil {
		return empty, err
	}
	return loginSession{credentials: creds, role: role, duration: duration}, nil
}
