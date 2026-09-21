package login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
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

type Runner struct {
	In       *os.File
	Out, Err io.Writer
	browser  acquirer
	sts      exchanger
	now      func() time.Time
}

func New(in *os.File, out, err io.Writer) *Runner {
	return &Runner{In: in, Out: out, Err: err, browser: &browser.Browser{}, sts: &sts.Client{}, now: time.Now}
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
	profiles := make([]config.Profile, 0, len(names))
	for _, name := range names {
		p, e := doc.Profile(name)
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
		if o.AllProfiles && !o.ForceRefresh {
			d, e := config.Load(paths.Credentials)
			if e != nil {
				return e
			}
			v, e := d.Values(p.Name)
			if e != nil {
				return e
			}
			if fresh(v, r.now()) {
				fmt.Fprintf(r.Err, "%s: credentials remain valid; skipping\n", p.Name)
				continue
			}
		}
		if err = r.warnLegacyPassword(doc, p.Name); err != nil {
			return invalid(err)
		}
		creds, e := r.authenticate(ctx, o, p, prompt)
		if e != nil {
			return fmt.Errorf("profile %s: %w", p.Name, e)
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if o.CredentialProcess {
			return json.NewEncoder(r.Out).Encode(processCredentials{1, creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, creds.Expiration.UTC().Format(time.RFC3339)})
		}
		if e = config.Update(ctx, paths.Credentials, p.Name, map[string]string{"aws_access_key_id": creds.AccessKeyID, "aws_secret_access_key": creds.SecretAccessKey, "aws_session_token": creds.SessionToken, "aws_expiration": creds.Expiration.UTC().Format(time.RFC3339)}); e != nil {
			return e
		}
		fmt.Fprintf(r.Err, "%s: credentials expire %s\n", p.Name, creds.Expiration.UTC().Format(time.RFC3339))
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

func fresh(v map[string]string, now time.Time) bool {
	for _, key := range []string{"aws_access_key_id", "aws_secret_access_key", "aws_session_token"} {
		if v[key] == "" {
			return false
		}
	}
	expiration, err := time.Parse(time.RFC3339, v["aws_expiration"])
	return err == nil && expiration.After(now.Add(11*time.Minute))
}
func (r *Runner) authenticate(ctx context.Context, o cli.Options, p config.Profile, prompt *cli.Prompt) (sts.Credentials, error) {
	var empty sts.Credentials
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
	role, err := selectRole(ctx, roles, p.RoleARN, prompt)
	if err != nil {
		return empty, err
	}
	if err = saml.ValidateRoleRegion(role, region); err != nil {
		return empty, err
	}
	if !prompt.NoPrompt {
		p.DurationHours, err = prompt.Read(ctx, "Session duration (hours)", p.DurationHours, false)
		if err != nil {
			return empty, err
		}
	}
	duration, err := p.DurationSeconds()
	if err != nil {
		return empty, invalid(err)
	}
	return r.sts.Exchange(ctx, assertion, role, duration, region, sts.TransportOptions{NoVerifySSL: o.NoVerifySSL})
}
func selectRole(ctx context.Context, roles []saml.Role, def string, prompt *cli.Prompt) (saml.Role, error) {
	return saml.SelectRole(roles, def, prompt.NoPrompt, func(roles []saml.Role, index int) (int, error) {
		for i, role := range roles {
			fmt.Fprintf(prompt.Out, "%d: %s\n", i+1, role.RoleARN)
		}
		seed := ""
		if index >= 0 {
			seed = strconv.Itoa(index + 1)
		}
		text, err := prompt.Read(ctx, "Role number", seed, false)
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(text)
		if err != nil {
			return 0, errors.New("invalid role number")
		}
		return n - 1, nil
	})
}
