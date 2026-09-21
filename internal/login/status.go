package login

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"aalogin/internal/cli"
	"aalogin/internal/config"
	"aalogin/internal/saml"
)

// status reports local evidence only. It deliberately does not authenticate or
// consult STS, even when the cache is missing or a role chain is configured.
func (r *Runner) status(ctx context.Context, paths config.Paths, doc *config.Document, o cli.Options) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	names := []string{o.Profile}
	if !o.ProfileExplicit {
		var err error
		names, err = doc.LoginProfileNames()
		if err != nil {
			return invalid(fmt.Errorf("cannot enumerate login profiles: %q; check AWS config", err.Error()))
		}
	}
	if len(names) == 0 {
		return invalid(errors.New("no Entra or source_profile role-chain profiles found; configure one with aalogin --configure --profile NAME"))
	}
	profiles := make([]config.LoginProfile, 0, len(names))
	for _, name := range names {
		p, err := doc.ResolveLoginProfile(name)
		if err != nil {
			return invalid(fmt.Errorf("profile %q: %q; check its source_profile chain and Entra source settings", name, err.Error()))
		}
		profiles = append(profiles, p)
	}
	credentials, err := config.Load(paths.Credentials)
	if err != nil {
		return invalid(fmt.Errorf("cannot read local credentials: %q", err.Error()))
	}
	sources := make(map[string]map[string]string)
	var sourceProfiles []config.Profile
	for _, p := range profiles {
		if _, exists := sources[p.Source.Name]; exists {
			continue
		}
		values, err := credentials.Values(p.Source.Name)
		if err != nil {
			return invalid(fmt.Errorf("source %q: cannot read local credentials: %q", p.Source.Name, err.Error()))
		}
		sources[p.Source.Name] = values
		sourceProfiles = append(sourceProfiles, p.Source)
	}

	now := r.now()
	var out strings.Builder
	fmt.Fprintln(&out, "Local status only; AWS access and cached role metadata are unverified.")
	sourcesTable := tabwriter.NewWriter(&out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(sourcesTable, "\nSOURCE\tCACHED ROLE / ACCOUNT\tEXPIRES (LOCAL)\tREMAINING\tCACHE")
	for _, source := range sourceProfiles {
		values := sources[source.Name]
		cached, complete := cachedCredentials(values)
		expiration, _ := time.Parse(time.RFC3339, values["aws_expiration"])
		state := "missing"
		if values["aws_access_key_id"] != "" || values["aws_secret_access_key"] != "" || values["aws_session_token"] != "" || values["aws_expiration"] != "" {
			state = "incomplete"
		}
		if complete {
			expiration = cached.Expiration
			switch {
			case !expiration.After(now):
				state = "expired"
			case source.RoleARN != "" && values["aalogin_role_arn"] != "" && values["aalogin_role_arn"] != source.RoleARN:
				state = "refresh due (cached role differs from configured default)"
			case !fresh(values, now):
				state = "refresh due"
			default:
				state = "valid locally"
			}
		}
		role := "unknown"
		if arn := values["aalogin_role_arn"]; arn != "" {
			role = roleLabel(saml.Role{RoleARN: arn})
		}
		expires, remaining := "unknown", "-"
		if !expiration.IsZero() {
			expires = expiration.Local().Format("02 Jan 15:04 MST")
			remaining = expiration.Sub(now).Round(time.Minute).String()
		}
		fmt.Fprintf(sourcesTable, "%q\t%q\t%s\t%s\t%s\n", source.Name, role, expires, remaining, state)
	}
	if err := sourcesTable.Flush(); err != nil {
		return err
	}
	profilesTable := tabwriter.NewWriter(&out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(profilesTable, "\nPROFILE\tSOURCE\tCONFIGURED ROLE / ACCOUNT")
	for _, p := range profiles {
		role := "select at login"
		if len(p.Steps) > 0 {
			role = roleLabel(saml.Role{RoleARN: p.Steps[len(p.Steps)-1].RoleARN})
		} else if p.Source.RoleARN != "" {
			role = roleLabel(saml.Role{RoleARN: p.Source.RoleARN})
		}
		fmt.Fprintf(profilesTable, "%q\t%q\t%q\n", p.Name, p.Source.Name, role)
	}
	if err := profilesTable.Flush(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err = fmt.Fprint(r.Out, out.String())
	return err
}
