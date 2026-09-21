# aalogin

[![CI](https://github.com/netf/aalogin/actions/workflows/ci.yml/badge.svg)](https://github.com/netf/aalogin/actions/workflows/ci.yml)

A Linux Go CLI for Microsoft Entra ID → AWS SAML federation. It reuses
`aws-azure-login` profile settings, drives an isolated Chromium session, and
exchanges the resulting SAML assertion for temporary AWS credentials.

Terminal username/password/MFA prompts, headless automation, visible-browser
login, and AWS `credential_process` are supported. No Node.js runtime, bundled
browser download, daemon, or AWS CLI is required.

This is for an **existing Entra SAML enterprise app and AWS IAM federation
setup**. It does not configure that infrastructure and is not an IAM Identity
Center / `aws sso login` replacement. Identity Center `AWSReservedSSO_` roles
cannot be assumed through this SAML flow.

## Build

Requirements:

- Linux; Linux amd64 is the verified delivery target.
- Go **1.27.0 or newer** and GNU Make for development.
- Chromium or Google Chrome for authentication and browser integration tests.
- A C toolchain for Go's race detector (`make check` / `make test-race`), not for
  the static application build.

From the repository root:

```sh
make
./bin/aalogin --version
./bin/aalogin --help
```

The default target produces `bin/aalogin` with `CGO_ENABLED=0` and version `dev`.
Dependencies are pinned in `go.mod` and `go.sum`. To embed a release version:

```sh
make build VERSION=1.0.0
```

Equivalent direct build:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags '-X main.version=1.0.0' -o bin/aalogin ./cmd/aalogin
```

Nothing is installed globally. The binary needs an installed browser at runtime.
Browser selection is `--browser`, then `CHROME_BIN`, then `chromium`,
`chromium-browser`, `google-chrome`, or `google-chrome-stable` on `PATH`.

## Quick start

Configure a profile using the tenant and app ID URI supplied by your federation
administrator, then log in:

```sh
./bin/aalogin --configure --profile work
./bin/aalogin --profile work
```

Existing valid `aws-azure-login` profiles can be used without reconfiguration.
Profile selection is nonempty `--profile`, then `AWS_PROFILE`, then `default`.
Normal login writes temporary credentials to the selected AWS credentials
section. Progress and prompts go to stderr; credentials are not printed.

| Mode | Behavior |
| --- | --- |
| `--mode cli` (default) | Headless Chromium, with terminal prompts as needed. |
| `--mode gui` | Visible Chromium; complete authentication in the browser. |
| `--mode debug` | Visible Chromium with terminal-driven form automation; no secret diagnostic dumps. |

```sh
./bin/aalogin --profile work --mode gui
./bin/aalogin --profile work --mode debug --timeout 10m
```

Visible modes require `DISPLAY` or `WAYLAND_DISPLAY`. Use GUI mode for passkeys,
CAPTCHA, unsupported federation pages, or changed Microsoft selectors. Browser
form automation is inherently sensitive to page changes; universal headless
compatibility is not promised.

## AWS profile configuration

Default files are `~/.aws/config` and `~/.aws/credentials`.
`AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` override them independently;
relative paths resolve from the invocation directory.

Example `~/.aws/config` (replace the synthetic identifiers with your own):

```ini
[profile work]
azure_tenant_id = example.onmicrosoft.com
azure_app_id_uri = urn:example:aws
azure_default_username = you@example.com
azure_default_remember_me = true
azure_default_role_arn = arn:aws:iam::123456789012:role/ExampleRole
azure_default_duration_hours = 1
region = us-east-1
```

The default profile uses `[default]`, not `[profile default]`. Credentials use
`[work]` for this example.

| Setting | Meaning |
| --- | --- |
| `azure_tenant_id` | Required tenant UUID or domain, not a URL. |
| `azure_app_id_uri` | Required app ID URI from the existing SAML setup. |
| `azure_default_username` | Default username for terminal-driven login. |
| `azure_default_password` | Legacy compatibility only; prefer an interactive prompt or environment value. |
| `azure_default_role_arn` | Default role; required for unattended selection when multiple roles are offered. |
| `azure_default_duration_hours` | Defaults to `1` when absent; decimal hours must convert to whole seconds in `900..43200` (15 minutes to 12 hours). AWS may impose a lower role limit. |
| `azure_default_remember_me` | Strict `true` / `false`; absent means `false`. |
| `region` | AWS region; may be blank. |

For tenant, app ID URI, username, password, role ARN, and duration, precedence is
**nonempty lowercase environment variable → nonempty uppercase equivalent →
profile value**. For example, `azure_default_username` takes precedence over
`AZURE_DEFAULT_USERNAME`. Remember-me is read from the profile. Region precedence
is `AWS_REGION`, `AWS_DEFAULT_REGION`, profile `region`, then `us-east-1`.

`--configure` never prompts for or writes passwords. Existing legacy password
keys are preserved with a warning. Unrelated comments, keys, nested settings,
and sections are preserved; duplicate target sections or owned keys are errors.

For noninteractive configuration:

```sh
AZURE_TENANT_ID=example.onmicrosoft.com \
AZURE_APP_ID_URI=urn:example:aws \
./bin/aalogin --configure --no-prompt --profile work
```

### Unattended login and renewal

```sh
./bin/aalogin --profile work --no-prompt
./bin/aalogin --all-profiles --no-prompt
./bin/aalogin --all-profiles --force-refresh --no-prompt
```

`--no-prompt` never reads stdin. Supply required username/password values through
profile settings or the environment, or use a remembered session that needs no
new credentials. Typed OTP challenges fail with an interaction-required error;
push approval may wait until the authentication deadline (default `5m`). Missing
values and rejected credentials fail rather than prompting or repeatedly
resubmitting a password. Interactive input requires a TTY.

Only profiles with tenant **and** app values in the config file qualify for
`--all-profiles`; environment overrides do not enroll unrelated AWS profiles.
Profiles run sequentially in sorted order and stop on the first failure, keeping
earlier successes. Complete credentials are skipped only when their expiration
is more than 11 minutes away. `--force-refresh` bypasses this check. Single-profile
login always requests fresh credentials.

A configured role missing from the assertion is an error, not permission to
silently choose another role. Requested session duration is never automatically
reduced after STS rejects it.

## AWS credential_process

Add the following to the consumer's AWS config profile, alongside its Azure
settings. Replace the executable path with an **absolute path**:

```ini
[profile work]
credential_process = /absolute/path/to/aalogin --profile work --credential-process
```

This mode emits exactly one AWS process-credentials JSON object on stdout,
implies `--no-prompt`, and requires headless CLI mode. It neither writes the
shared credentials file nor caches STS credentials. Each invocation requests new
credentials; the consuming SDK manages their expiration. Remembered browser
cookies may still be reused.

**Existing static credentials for the consumer profile take precedence.** Remove
those deliberately if switching to process credentials; aalogin never deletes
them for you. Do not log or capture the raw process output: it contains secrets.

Process mode fails on challenges requiring user interaction, including push or
number matching, without printing approval text or matching numbers. Establish a
remembered session interactively first if your tenant policy permits it.

## Security and networking

- Chromium runs as an owned, isolated process, never attached to the normal user
  browser. Temporary state is removed after login. Remembered state lives under
  `$XDG_STATE_HOME/aalogin/browser`, or `~/.local/state/aalogin/browser`, in private
  directories keyed by tenant and username. Session cookies are sensitive;
  private filesystem permissions are **not encryption**. Old
  `~/.aws/chromium` state is not imported.
- Browser password saving and response caching are disabled. Debug mode does not
  generate screenshots, HTML dumps, or assertion logs. Azure passwords and AWS
  credential secret values are scrubbed from the browser child's environment.
- Automatic credential filling is restricted to HTTPS `login.microsoftonline.com`,
  `login.live.com`, and explicitly trusted exact hosts. For an authorized ADFS
  host, use `--trusted-login-host adfs.example.com` (repeatable), or use GUI mode.
  Wildcards, schemes, ports, and paths are not accepted in this flag.
- The SAML POST is intercepted and fulfilled locally rather than forwarded to
  AWS's console endpoint. Local XML parsing selects roles; **AWS STS validates
  the assertion and its signature**. STS uses anonymous credentials, without
  loading an AWS credential chain that could recursively invoke this process.
- Config and credentials writes use private temporary files, atomic replacement,
  and sidecar locks; existing destination symlinks are followed. Locks coordinate
  aalogin writers, not unrelated programs. Authentication or STS failures leave
  credentials unchanged. A filesystem error after rename can mean the replacement
  occurred but its durability could not be confirmed.
- Proxy precedence is nonempty `https_proxy`, then `HTTPS_PROXY`; bypass precedence
  is `no_proxy`, then `NO_PROXY`. Browser and STS share this policy, including
  HTTP/HTTPS proxies and Basic proxy authentication. With no configured proxy,
  connections are direct. Invalid proxy settings fail; there is no automatic
  direct or insecure fallback.
- STS uses system trust and supports a checked `AWS_CA_BUNDLE` PEM file.
  `--no-verify-ssl` is an explicit unsafe **STS-only** opt-in. Browser TLS
  verification remains enabled. The Chromium sandbox stays enabled unless
  `--no-sandbox` is explicitly requested.

Additional compatibility switches are listed by `./bin/aalogin --help`:
`--enable-chrome-network-service`, `--enable-chrome-seamless-sso`,
`--no-disable-extensions`, and `--disable-gpu`.

Exit codes: `0` success/help/version, `2` usage/configuration error, `1`
authentication/network/persistence failure, `130` SIGINT, `143` SIGTERM.

## Development and verification

```sh
make help
make test
make check
make integration CHROME_BIN=/usr/bin/chromium
```

| Target | Purpose |
| --- | --- |
| `build` (default) | Build the static `bin/aalogin` executable; accepts `VERSION`. |
| `test` | Run ordinary Go tests; no browser required. |
| `test-race` | Run ordinary tests with the race detector. |
| `integration` | Run tagged real-Chromium fixtures, uncached; accepts `CHROME_BIN` (default `chromium`). |
| `vet` | Run `go vet ./...`. |
| `fmt` | Format Go sources under `cmd/` and `internal/`. |
| `check` | Run `vet` and `test-race`; browser fixtures remain opt-in. |
| `clean` | Remove only the generated `bin/aalogin` executable. |

`GO` and `GOFMT` can override the development tool executables. `make build`
disables CGO only for that build; race-enabled tests use the host Go environment.

Tests use synthetic profiles and local HTTP/browser fixtures, not personal AWS
files. Coverage includes preserving shared INI files and symlinks, concurrent
writers, SAML parsing, STS error handling, credential-process output, proxy
routing, MFA states, origin restrictions, remembered cookies without assertion
page replay, cancellation, and owned-browser cleanup. Integration tests use an
explicit fixture-only sandbox opt-out; production does not infer one.

**Live acceptance remains outstanding:** authorized Entra/MFA and conditional
access, real AWS role issuance and `GetCallerIdentity`, GUI login, remembered
renewal, and an SDK process-provider invocation against a real tenant have not
been validated. Passing fixtures does not establish compatibility with your
organization's policies. Use temporary copies of authorized AWS profile files
when performing that acceptance, and never print credentials or assertions.

Code is split into `cmd/aalogin` and `internal/{cli,config,browser,saml,sts,login,transport}`.
Browser acquisition and STS exchange are the fixture substitution boundaries;
there are no production endpoint or TLS test-bypass flags.

## GitHub Actions and releases

[CI](.github/workflows/ci.yml) runs on pushes to `main`, pull requests, and manual
dispatch. It checks formatting, runs `make check` (vet and race-enabled tests),
runs real-browser fixtures using the Ubuntu runner's installed Google Chrome,
and builds and smoke-tests the static Linux amd64 executable. Successful runs
retain an `aalogin-linux-amd64` build artifact for seven days. CI artifacts may
need `chmod +x aalogin` after download; release archives preserve executable mode.
The Go version comes from `go.mod`.

[Release](.github/workflows/release.yml) runs when a `vMAJOR.MINOR.PATCH` tag is
pushed. It first runs the same CI workflow against the tagged commit. Only after
those checks pass does it build a versioned binary and publish a GitHub Release
with generated notes and these assets:

- `aalogin-vMAJOR.MINOR.PATCH-linux-amd64.tar.gz` containing `aalogin`, `README.md`,
  and `LICENSE`.
- `checksums.txt` containing the archive's SHA-256 checksum.

To publish a release after reviewing the commit to tag:

```sh
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

The tag is embedded verbatim in `aalogin --version`. Only stable numeric version
tags are supported; prerelease tags are rejected. Existing releases are not
overwritten by rerunning the workflow.

After downloading both release assets into the same directory, verify before
extracting:

```sh
sha256sum --check checksums.txt
tar -xzf aalogin-v0.1.0-linux-amd64.tar.gz
./aalogin --version
```

Both workflows pin third-party actions to commit SHAs and disable persisted
checkout credentials. CI has read-only repository permissions; only the release
publishing job receives `contents: write`, and its GitHub token is exposed only
to the publication step. No AWS/Entra credentials or other repository secrets
are needed. Release publication is not a live federation acceptance test.

## License

[MIT](LICENSE). Compatibility behavior and Microsoft form selectors are adapted
from [aws-azure-login](https://github.com/aws-azure-login/aws-azure-login); its
copyright notice is retained.
