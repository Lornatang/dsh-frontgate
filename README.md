# dsh-frontgate

Password gate and reverse proxy for the DeepSeek Harness Web UI. Keep `dsh`
bound to loopback and expose this plugin instead: unauthenticated visitors can
reach neither the UI nor `/api`, and the proxy handles Host/Origin and the
harness launch token, so no extra flags are needed on the `dsh` command line.

## Features

- Password login. Page requests are redirected to the login page; `/api/*`
  returns 401. A configured password must be at least 12 characters.
- Reverse proxy to the local harness. The launch token is exchanged on the
  server and cached, so the browser only holds the gate session cookie.
- Stateless sessions. Changing the password invalidates every issued session.
  No session table and no background timers.
- Async scrypt verification, per-IP lockout, and limits on concurrent checks,
  form size, body read time, header/request deadlines and connection count.
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
dsh plugin --profile <name> add github:Lornatang/dsh-frontgate#v0.1.0
```

Offline: on a machine with network access unpack a checkout and run
`npm pack`, copy the tarball over, then:

```bash
dsh plugin --profile <name> add ./dsh-frontgate-0.1.0.tgz
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
    password: 'change-me-now'
```

| Option | Default | Description |
| --- | --- | --- |
| `listenHost` | `'127.0.0.1'` | Listen address. Use `'0.0.0.0'` for remote access. |
| `listenPort` | `3090` | Listen port. Must differ from the harness port. |
| `sessionDays` | `7` | Session lifetime in days (1 to 365). |
| `title` | `'DeepSeek Harness'` | Login page title. |
| `password` | `''` | Plain-text password (at least 12 characters), hashed at startup and not written to disk. |
| `passwordHash` | `''` | `scrypt$...` hash. Takes precedence over `password`. |
| `maxAttempts` / `lockMinutes` | `5` / `5` | Failed logins per client before answers become 429, and the window. |
| `tlsCertFile` / `tlsKeyFile` | `''` | Set both to serve HTTPS. |
| `trustProxy` | `false` | Trust `X-Forwarded-*` from your reverse proxy. |

`DSH_FRONTGATE_PASSWORD` and `DSH_FRONTGATE_PASSWORD_HASH` are read when the
config sets neither, which keeps the password out of the patch file. The
12-character minimum applies to `DSH_FRONTGATE_PASSWORD` as well; a shorter
value stops startup with an explicit error.

The state file `<profile>/data/dsh-frontgate.json` (mode 0600) stores the
password hash and the session signing secret. Deleting it invalidates every
issued session.

## Remote and Docker deployment

- In a container set `listenHost` to `'0.0.0.0'` and `listenPort` to the port
  mapped from the host. Map only that port, not the harness port.
- Plain HTTP exposes the password and the session cookie to anyone on the path.
  Use it only on a trusted LAN or VPN. For anything else enable
  `tlsCertFile`/`tlsKeyFile`, or terminate TLS in Caddy or Nginx and set
  `trustProxy: true`.
- If `dsh` listens on a non-loopback address the log warns that the gate can
  be bypassed. Keep it on `127.0.0.1`.

## Security notes

- Session cookies are HMAC-SHA256 signed with a random 32-byte secret kept in
  the state file; the secret is not derived from the password hash.
- Requests whose `Origin` names another site are refused with 403 before they
  reach the harness; WebSocket handshakes get the same check.
- Repeated failures from one client answer 429 with `Retry-After`, but a
  correct password is still verified and accepted. One client therefore cannot
  lock out every user behind a shared address. Guessing throughput is bounded
  by the scrypt cost and the scrypt concurrency cap.
- Secret comparisons are constant-time; the state file holds the scrypt hash and
  the signing secret, never the password, and is chmod 0600 on startup.
- The login page has no scripts and sends CSP, `no-store`, `no-referrer` and
  `X-Frame-Options`.
- The proxy target is fixed to the local harness and never taken from user
  input; upstream `Set-Cookie` headers are stripped. Upstream redirects that
  would leave this origin (protocol-relative or backslash forms) become `/`.
- The listener closes clients that do not finish headers within 10 seconds or a
  request within 30 seconds, and accepts at most 1024 concurrent connections.
- With TLS enabled, gate responses also send HSTS.

Known limits: one password for everyone, no multi-user accounts, no way to
revoke a single session, and no admin page. Configuration changes need a patch
edit and a restart.

## Project layout

The plugin follows the layout of the packages shipped with the harness:

| Path | Purpose |
| --- | --- |
| `src/` | TypeScript sources. Each module owns one concern: config, auth, proxy, gate handler, login page. |
| `lib/` | Build output: the bundled `index.js` and the generated `.d.ts` files. |
| `tests/` | End-to-end tests that run against the built bundle. |
| `scripts/build.mjs` | esbuild bundle plus `tsc` declaration emit. |
| `cordis.patch.yml` | Bundle patch that inserts the plugin into a profile. |

## Development

```bash
npm ci            # install the pinned dev dependencies (package-lock.json)
npm run typecheck # tsc --noEmit over src/
npm test          # build, then node --test tests/*.test.mjs (25 tests)
npm run build     # regenerate lib/index.js and lib/types/
npm pack          # prepack rebuilds and reruns the tests
```

## License

Apache-2.0
