package login

import (
	"context"
	"fmt"
	"strconv"

	"aalogin/internal/cli"
	"aalogin/internal/config"
)

func (r *Runner) configure(ctx context.Context, paths config.Paths, doc *config.Document, o cli.Options, prompt *cli.Prompt) error {
	p, err := doc.ConfigureProfile(o.Profile)
	if err != nil {
		return invalid(err)
	}
	if err = r.warnLegacyPassword(doc, p.Name); err != nil {
		return invalid(err)
	}
	remember := strconv.FormatBool(p.RememberMe)
	fields := []struct {
		label string
		value *string
	}{
		{"Azure tenant ID", &p.Tenant},
		{"Azure app ID URI", &p.AppID},
		{"Default username", &p.Username},
		{"Remember me (true/false)", &remember},
		{"Default role ARN", &p.RoleARN},
		{"Default duration (hours)", &p.DurationHours},
		{"AWS region", &p.Region},
	}
	if !prompt.NoPrompt {
		for _, field := range fields {
			*field.value, err = prompt.Read(ctx, field.label, *field.value, false)
			if err != nil {
				return err
			}
		}
	}
	if remember != "true" && remember != "false" {
		return invalid(fmt.Errorf("remember-me must be true or false"))
	}
	p.RememberMe = remember == "true"
	if err = p.Validate(); err != nil {
		return invalid(err)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = config.Update(ctx, paths.Config, config.ConfigSection(p.Name), map[string]string{
		"azure_tenant_id": p.Tenant, "azure_app_id_uri": p.AppID, "azure_default_username": p.Username,
		"azure_default_remember_me": remember, "azure_default_role_arn": p.RoleARN,
		"azure_default_duration_hours": p.DurationHours, "region": p.Region,
	}); err != nil {
		return err
	}
	fmt.Fprintf(r.Err, "Configured profile %s\n", p.Name)
	return nil
}
