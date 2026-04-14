<p align="center">
  <img src="https://www.authelia.com/images/authelia-title.png" width="350" title="Authelia">
</p>

  [![License](https://img.shields.io/github/license/authelia/pam?logo=apache&style=flat-square&color=blue)][Apache 2.0]
  [![Discord](https://img.shields.io/discord/707844280412012608?label=discord&logo=discord&style=flat-square&color=blue)](https://discord.authelia.com)
  [![Matrix](https://img.shields.io/matrix/authelia-support:matrix.org?label=matrix&logo=matrix&style=flat-square&color=blue)](https://matrix.to/#/#support:authelia.com)

# pam_authelia

**pam_authelia** is a [PAM](https://en.wikipedia.org/wiki/Linux_PAM) module that delegates authentication —
including 2FA — to an [Authelia](https://www.authelia.com/) server. It plugs into any PAM consumer (sshd, sudo,
login, su, …) and lets you front a Linux host with the same authentication policy you're already running for your
web applications.

It supports first-factor (password) authentication, second-factor methods (TOTP, Duo Push, OAuth2 device
authorization), or any combination of the two, with a configurable method preference order.

## Architecture

`pam_authelia` is split into two binaries that communicate over a stdin/stdout pipe protocol:

```
                       ┌─────────────────────────────────────┐
                       │           sshd-session              │
                       │  ┌──────────────────────────────┐   │
                       │  │   pam_authelia.so (C shim)   │   │
                       │  │   /lib/security/             │   │
   ssh client ────────►│  │                              │   │
                       │  │   • PAM conv (prompts/info)  │   │
                       │  │   • forks helper             │   │
                       │  └──────────┬───────────────────┘   │
                       │             │ pipe                   │
                       │  ┌──────────▼───────────────────┐   │
                       │  │   pam_authelia (Go helper)   │   │
                       │  │   /usr/bin/                  │   │
                       │  │                              │   │
                       │  │   • talks HTTPS to Authelia  │   │
                       │  │   • handles 1FA / 2FA flows  │   │
                       │  └──────────┬───────────────────┘   │
                       └─────────────┼─────────────────────┬─┘
                                     │                     │
                                     ▼                     │
                            ┌─────────────────┐           │
                            │  Authelia API   │◄──────────┘
                            │  (HTTPS only)   │
                            └─────────────────┘
```

The C shim (`pam_authelia.so`) is intentionally minimal — it handles the PAM conversation function and pipes
prompts/responses to a Go helper which owns all the network I/O, JSON parsing, OAuth2 flows, and QR rendering.

## Installation

Release artifacts are built by [GoReleaser](https://goreleaser.com) on tagged commits via Buildkite and uploaded
to the [GitHub Releases page](https://github.com/authelia/pam/releases).

### Debian / Ubuntu (`.deb`)

The recommended path on glibc-based distros. The `.deb` ships:

| Path                                | Contents                              |
| ----------------------------------- | ------------------------------------- |
| `/lib/security/pam_authelia.so`     | C PAM shim (mode 0644)                |
| `/usr/bin/pam_authelia`             | Go helper invoked by the shim         |

```bash
# amd64
curl -LO https://github.com/authelia/pam/releases/latest/download/pam_authelia_<version>-1_amd64.deb
sudo dpkg -i pam_authelia_<version>-1_amd64.deb

# arm64
curl -LO https://github.com/authelia/pam/releases/latest/download/pam_authelia_<version>-1_arm64.deb
sudo dpkg -i pam_authelia_<version>-1_arm64.deb

# armhf
curl -LO https://github.com/authelia/pam/releases/latest/download/pam_authelia_<version>-1_armhf.deb
sudo dpkg -i pam_authelia_<version>-1_armhf.deb
```

The `.deb` is GPG-signed by `security@authelia.com` and accompanied by SBOMs in CycloneDX and SPDX formats for
supply-chain verification.

### Tarball (manual install)

For non-Debian distros, glibc and musl tarballs are produced for `amd64`, `arm64`, and `arm` (armhf). Each archive
contains the Go helper and the matching `.so`:

```
pam_authelia-v<version>-linux-<arch>.tar.gz             # glibc
pam_authelia-v<version>-linux-<arch>-musl.tar.gz        # musl (Alpine, etc.)
```

Manual install layout:

```bash
tar -xzf pam_authelia-v<version>-linux-amd64.tar.gz
sudo install -m 0755 pam_authelia        /usr/bin/pam_authelia
sudo install -m 0644 pam_authelia.so     /lib/security/pam_authelia.so
```

Each archive is GPG-signed (`*.tar.gz.sig`) and the release also includes `checksums.sha256` plus per-artifact
`*.cdx.json` and `*.spdx.json` SBOMs.

### From source

Requires Go 1.26+ and a C toolchain (`gcc` / `cc`) plus `libpam` development headers (`libpam0g-dev` on Debian).

```bash
git clone https://github.com/authelia/pam
cd pam

# Build the Go helper.
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o pam_authelia ./cmd/pam_authelia

# Build the C shim (produces shim/pam_authelia.so on Linux).
make -C shim

# Install both. Adjust the destination paths to match your distro.
sudo install -m 0755 pam_authelia        /usr/bin/pam_authelia
sudo install -m 0644 shim/pam_authelia.so /lib/security/pam_authelia.so
```

## sshd configuration

For PAM auth over SSH the daemon needs:

```
# /etc/ssh/sshd_config
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no          # let PAM (and pam_authelia) handle credentials
```

If you're using the OAuth2 Device Authorization flow, you may want to raise `LoginGraceTime` to give users a
little extra time to scan the QR code and approve on their phone:

```
LoginGraceTime 5m
```

Reload sshd after editing: `sudo systemctl reload sshd`.

## Module configuration

Options are passed as space-separated `key=value` arguments after the module path in your PAM service file (e.g.
`/etc/pam.d/sshd`).

| Option                  | Required | Default                   | Description                                                                              |
| ----------------------- | :------: | ------------------------- | ---------------------------------------------------------------------------------------- |
| `url=`                  |   yes    | -                         | Authelia server URL. **Must be `https://`.**                                             |
| `auth-level=`           |          | `1FA+2FA`                 | `1FA`, `2FA`, or `1FA+2FA`. See [Auth levels](#auth-levels) below.                       |
| `cookie-name=`          |          | `authelia_session`        | Session cookie name issued by Authelia. Match your `session.cookies[].name` server side. |
| `ca-cert=`              |          | system trust store        | Path to a custom CA certificate (PEM) for TLS verification.                              |
| `timeout=`              |          | `60`                      | Upper bound (seconds) on the entire PAM exchange. Raise for slow device-auth users.      |
| `binary=`               |          | `/usr/bin/pam_authelia`   | Override the Go helper binary path.                                                      |
| `method-priority=`      |          | (use Authelia preference) | Comma-separated 2FA method order. See [Method priority](#method-priority).               |
| `oauth2-client-id=`     |          | -                         | OAuth2 client ID for the device authorization flow.                                      |
| `oauth2-client-secret=` |          | -                         | OAuth2 client secret (for confidential clients).                                         |
| `oauth2-scope=`         |          | `openid,profile`          | Comma-separated scopes to request on the device authorization endpoint.                  |
| `debug`                 |          | off                       | Boolean flag - emits debug lines via syslog (`LOG_AUTH`) tagged `pam_authelia`.          |

### Auth levels

- **`1FA`** - password only. Authelia validates the password; no second factor runs.
- **`2FA`** - second factor only. The password is still required (taken from the PAM stack via `PAM_AUTHTOK`) and
  validated by Authelia silently before the 2FA challenge runs.
- **`1FA+2FA`** *(default)* - password validation followed by the user's preferred second factor, or the one chosen
  via `method-priority`.

### Method priority

`method-priority` overrides Authelia's per-user preference and tells `pam_authelia` exactly which 2FA methods to
attempt, in order. Valid values:

- **`totp`** - time-based one-time password. Requires the user to have TOTP set up in Authelia.
- **`mobile_push`** - Duo Push. Requires Duo configured in Authelia and enrolled for the user.
- **`device_authorization`** - OAuth2 RFC 8628 device authorization. Renders a scannable QR code in the terminal.
- **`user`** - resolves to the user's Authelia preference (TOTP / Duo / device-auth fallback).

The first method in the list that is *usable for the current user* wins. Listing `user` last is a sensible default
fallback.

## Example PAM configurations

All examples target `/etc/pam.d/sshd`. Adapt the module path to wherever your distro looks for PAM modules
(`/lib/security/`, `/lib/x86_64-linux-gnu/security/`, etc.).

### 1. Authelia handles the password and 2FA (no local password validation)

The most common setup. Authelia validates the user's password and runs their preferred second factor. The Linux
account doesn't need a usable shadow entry.

```
# /etc/pam.d/sshd
auth    required   pam_authelia.so url=https://auth.example.com \
                                    auth-level=1FA+2FA \
                                    cookie-name=authelia_session

@include common-account
@include common-session
```

### 2. Local password validation + Authelia 2FA

Falls back to `pam_unix` for first factor, then layers Authelia's second factor on top. Useful if you want users to
keep authenticating with their local Linux password but still enforce 2FA.

```
# /etc/pam.d/sshd
auth    required   pam_unix.so      try_first_pass
auth    required   pam_authelia.so  url=https://auth.example.com \
                                    auth-level=2FA \
                                    cookie-name=authelia_session

@include common-account
@include common-session
```

`auth-level=2FA` tells `pam_authelia` to skip its own first-factor request and pull the password from `PAM_AUTHTOK`
(set by the preceding `pam_unix` module) for the silent Authelia validation that runs before the 2FA prompt.

### 3. Passwordless via OAuth2 device authorization

The user types nothing - a QR code is rendered in the terminal, they scan it on their phone, approve the request,
and press Enter. Requires an OAuth2 client configured in Authelia with the device authorization grant type
enabled. If users find themselves running up against the default 60-second budget, you may want to raise
`timeout=` (and the matching `LoginGraceTime` in `sshd_config`).

```
# /etc/pam.d/sshd
auth    required   pam_authelia.so  url=https://auth.example.com \
                                    auth-level=2FA \
                                    cookie-name=authelia_session \
                                    oauth2-client-id=device-code \
                                    oauth2-client-secret=insecure-secret \
                                    oauth2-scope=openid,profile,email,groups \
                                    method-priority=device_authorization,user

@include common-account
@include common-session
```

The `device_authorization,user` priority list tries the device flow first and falls back to whatever the user has
configured in Authelia if the device flow fails (e.g. the OAuth2 client isn't reachable).

### 4. Prefer TOTP, fall back to device authorization

Mixed-method deployment: users with TOTP enrolled get a TOTP prompt; everyone else gets the QR code.

```
# /etc/pam.d/sshd
auth    required   pam_authelia.so  url=https://auth.example.com \
                                    auth-level=1FA+2FA \
                                    cookie-name=authelia_session \
                                    oauth2-client-id=device-code \
                                    method-priority=totp,device_authorization,user

@include common-account
@include common-session
```

### 5. Custom CA (self-signed Authelia)

If your Authelia deployment uses a private CA, point the module at the trust anchor:

```
auth    required   pam_authelia.so  url=https://auth.internal \
                                    cookie-name=authelia_session \
                                    ca-cert=/etc/ssl/certs/internal-ca.pem
```

### 6. Debug mode

Adding `debug` enables verbose logging via syslog with the `LOG_AUTH` facility, tagged `pam_authelia`:

```
auth    required   pam_authelia.so  url=https://auth.example.com debug
```

Tail the journal to follow auth activity:

```bash
sudo journalctl -u sshd -f
# or filter to just pam_authelia
sudo journalctl -t pam_authelia -f
```

## Logging

`pam_authelia` logs through the standard PAM convention — syslog with the `LOG_AUTH` facility, tagged
`pam_authelia`. On systemd hosts those messages are captured by journald and correlated with the parent service's
cgroup, so they show up in `journalctl -u sshd` interleaved with `sshd-session`, `pam_unix`, and `pam_access`
output.

Errors and authentication failures are always logged. Verbose request/response tracing requires the `debug` flag.

The Go helper never writes to stdout — that channel is reserved for the protocol pipe to the C shim. Stderr is
also unused since sshd closes it after `log_init()`.

## Building

Single-host builds are covered in [Installation > From source](#from-source). For cross-platform release
artifacts, builds run inside the `authelia/crossbuild` container via Buildkite and produce all six libc/arch
combinations (`linux-{amd64,arm,arm64}-{glibc,musl}`):

```bash
goreleaser release --clean
```

The shim is cross-compiled by `shim/build-all.sh` (invoked from GoReleaser's `before.hooks`). Output lands in
`goreleaser/`. Tagged builds are GPG-signed and accompanied by SBOMs (CycloneDX + SPDX).

### Tests and lint

```bash
go test ./...
golangci-lint run ./...
yamllint .
```

A `lefthook` config (`.lefthook.yml`) wires both linters into a `pre-commit` hook and validates Conventional
Commits format on `commit-msg`. Install lefthook with `lefthook install`.

## Security

- All Authelia API requests are HTTPS-only — `http://` URLs are rejected at config parse time.
- TLS minimum is 1.2; custom CAs are supported via `ca-cert=`.
- Verification URLs returned by the device authorization endpoint are validated to be `https://` and to point at
  the configured Authelia host before being rendered as a QR code (defends against phishing via tampered server
  responses).
- Passwords are zeroed in the C shim immediately after use via `explicit_bzero` / `memset_s`.
- Response bodies are not logged — only status codes and protocol error fields. Access tokens never reach disk.
- The C shim is built with `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, `-fPIC -fno-plt`, and full RELRO/BIND_NOW.
- Length-bounded input handling end to end: protocol lines capped at 64 KiB, prompt payloads at 16 KiB, verification
  URLs at 2 KiB.

## Contributing

Issues and pull requests are welcome at <https://github.com/authelia/pam>. Commits must follow the
[Conventional Commits](https://www.conventionalcommits.org/) format with one of the project's allowed scopes
(`authelia`, `buildkite`, `cmd`, `config`, `deps`, `golangci-lint`, `goreleaser`, `lefthook`, `protocol`, `qr`,
`shim`). The pre-commit hook will reject malformed subjects.

## License

[Apache License 2.0](LICENSE).

[Apache 2.0]: https://www.apache.org/licenses/LICENSE-2.0
