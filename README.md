# dsh-frontgate

Password gate and reverse proxy for the DeepSeek Harness Web UI. Keep `dsh`
bound to loopback and expose this plugin instead: unauthenticated visitors can
reach neither the UI nor `/api`, and the proxy handles Host/Origin and the
harness launch token, so no extra flags are needed on the `dsh` command line.

## Features

- Password login. Page requests are redirected to the login page; `/api/*`
  returns 401.
- Reverse proxy to the local harness. The launch token is exchanged on the
  server and cached, so the browser only holds the gate session cookie.
- Stateless sessions. Changing the password invalidates every issued session.
  No session table and no background timers.
- Async scrypt verification, per-IP lockout, and limits on concurrent checks,
  form size and body read time.
- Loopback only by default, optional native TLS, and a `crypto.randomUUID`
  fallback for plain-HTTP pages.

## Install

Requires Node >= 22.19 and DSH >= 0.2.2-rc.1.

One command, which also creates the profile from the web template when it does
not exist yet:

```bash
curl -fsSL https://raw.githubusercontent.com/Lornatang/dsh-frontgate/main/install.sh | bash
```

To install into another profile:

```bash
curl -fsSL https://raw.githubusercontent.com/Lornatang/dsh-frontgate/main/install.sh | bash -s -- --profile <name>
```

Or install manually:

```bash
dsh plugin --profile <name> add github:Lornatang/dsh-frontgate#v1.1.0
```

Offline: on a machine with network access unpack a checkout and run
`npm pack`, copy the tarball over, then:

```bash
dsh plugin --profile <name> add ./dsh-frontgate-1.1.0.tgz
```

Restart the profile after installing.

## Quick start

- The gate listens on `127.0.0.1:3090` and forwards to the local harness.
- With no password configured, the first start prints
  `PASSWORD: xxxx-xxxx-xxxx-xxxx` and stores only its hash.
- Set a fixed password with the `password` or `passwordHash` option below.
- Open `http://127.0.0.1:3090`.

## Configuration

Append to the profile's `cordis.patch.yml`:

```yaml
- id: frontgate
  config:
    listenHost: '0.0.0.0'
    listenPort: 30010
    password: 'change-me'
```

| Option | Default | Description |
| --- | --- | --- |
| `listenHost` | `'127.0.0.1'` | Listen address. Use `'0.0.0.0'` for remote access. |
| `listenPort` | `3090` | Listen port. Must differ from the harness port. |
| `sessionDays` | `7` | Session lifetime in days (1 to 365). |
| `title` | `'DeepSeek Harness'` | Login page title. |
| `password` | `''` | Plain-text password, hashed at startup and not written to disk. |
| `passwordHash` | `''` | `scrypt$...` hash. Takes precedence over `password`. |
| `maxAttempts` / `lockMinutes` | `5` / `5` | Failures per client before lockout, and lockout length. |
| `tlsCertFile` / `tlsKeyFile` | `''` | Set both to serve HTTPS. |
| `trustProxy` | `false` | Trust `X-Forwarded-*` from your reverse proxy. |

`DSH_FRONTGATE_PASSWORD` and `DSH_FRONTGATE_PASSWORD_HASH` are read when the
config sets neither, which keeps the password out of the patch file.

The state file `<profile>/data/dsh-frontgate.json` (mode 0600) stores the
password hash and the session signing secret. Deleting it invalidates every
issued session.

## Remote and Docker deployment

- In a container set `listenHost` to `'0.0.0.0'` and `listenPort` to the port
  mapped from the host. Map only that port, not the harness port.
- Plain HTTP is for a LAN or VPN. For public access enable
  `tlsCertFile`/`tlsKeyFile`, or terminate TLS in Caddy or Nginx and set
  `trustProxy: true`.
- If `dsh` listens on a non-loopback address the log warns that the gate can
  be bypassed. Keep it on `127.0.0.1`.

## Security notes

- Sessions are HMAC-signed with a key derived from the password hash.
- Secret comparisons are constant-time; only a scrypt hash is stored.
- The login page has no scripts and sends CSP, `no-store`, `no-referrer` and
  `X-Frame-Options`.
- The proxy target is fixed to the local harness and never taken from user
  input; upstream `Set-Cookie` headers are stripped.
- With TLS enabled, gate responses also send HSTS.

Known limits: one password for everyone, no multi-user accounts, no way to
revoke a single session, and no admin page. Configuration changes need a patch
edit and a restart.

## Development

```bash
npm test    # node --test test/e2e.mjs, 19 tests
npm pack    # prepack runs the tests
```

## License

MIT © 2026 Lornatang
