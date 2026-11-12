# dsh-frontgate

Password protection for the DeepSeek Harness Web UI. The gate listens on its
own port and forwards authenticated traffic to the local harness.

**Requires:** Node.js 22.19+, DSH 0.2.2-rc.1+, and a Web profile.

## Install

```bash
dsh plugin --profile web add @lornatang/dsh-frontgate
```

Restart DSH, or start it with `dsh web --no-open`. If no password is configured
or saved, the first start prints a password to stderr or the service log:

```text
[dsh-frontgate] PASSWORD: xxxx-xxxx-xxxx-xxxx
```

Save it: only its hash is stored and the password is shown once. Open
<http://127.0.0.1:3090> to sign in. For an existing Web profile with another
name, replace `web` in the install and start commands.

To update, run the same install command and restart DSH. The existing
configuration and password are preserved.

If you installed an older unscoped `dsh-frontgate` package, stop DSH first,
install the scoped package, then remove the old package before restarting:

```bash
dsh plugin --profile web add @lornatang/dsh-frontgate
dsh plugin --profile web remove dsh-frontgate
```

This keeps the profile configuration and saved password. Stopping DSH during
the switch avoids loading both packages at once.

## Configuration

Edit `~/.dsh/profiles/web/cordis.patch.yml` (or use `$DSH_HOME` in place of
`~/.dsh`) and add or edit the `frontgate` entry:

```yaml
- id: frontgate
  config:
    listenHost: '0.0.0.0' # only when remote access is needed
    listenPort: 3090
    # password: 'a-password-of-at-least-12-characters'
```

Restart DSH after changes. The gate listens on `127.0.0.1:3090` by default;
its port must differ from the harness port.

| Option | Default | Purpose |
| --- | --- | --- |
| `password` / `passwordHash` | empty | Fixed password (12+ characters) or scrypt hash; the hash takes precedence. |
| `sessionDays` | `7` | Absolute session lifetime, 1–365 days. |
| `maxAttempts` / `lockMinutes` | `5` / `5` | Failed attempts and lockout duration per client IP. |
| `tlsCertFile` / `tlsKeyFile` | empty | Set both for direct HTTPS. |
| `publicOrigin` | empty | External origin when a reverse proxy terminates HTTPS. |
| `trustProxy` | `false` | Use client IPs supplied by a trusted proxy. |
| `exchangeTimeoutMs` | `5000` | Harness token exchange timeout in milliseconds. |
| `maxConnectionsPerPeer` | `64` | Simultaneous TCP connections per peer; `0` disables this limit. |
| `maxPendingLoginsPerIp` | `4` | Incomplete login forms allowed per client IP. |
| `maxHttpRequestsPerSession` | `32` | Simultaneous HTTP requests per signed-in session, including requests waiting for the harness. |
| `upstreamHeaderTimeoutMs` | `0` | Upstream response-header deadline, including queue time; `0` disables. |
| `upstreamIdleTimeoutMs` | `0` | Upstream response idle deadline; `0` disables. |
| `websocketHandshakeTimeoutMs` | `10000` | Deadline for the upstream WebSocket handshake in milliseconds. |
| `upstreamCaFile` / `upstreamServerName` | empty | CA file and optional TLS hostname for a private HTTPS harness. |
| `title` | `DeepSeek Harness` | Login page title. |

Password precedence is configured hash, configured password,
`DSH_FRONTGATE_PASSWORD_HASH`, `DSH_FRONTGATE_PASSWORD`, saved hash, then a
newly generated password. Lockout blocks all attempts from the IP, including
correct passwords, until it expires; clients behind the same NAT may share it.
Incomplete failure counts expire after the lockout window. The gate remembers
up to 1,024 clients with recent failures; when this store is full, new clients
must wait for an entry to expire instead of displacing an active lockout.

## Remote access

For Docker, set `listenHost: '0.0.0.0'` and publish the gate port, for example:

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- id: frontgate
  config:
    listenHost: '0.0.0.0'
    listenPort: 30010
```

```yaml
# Docker Compose
ports:
  - '30190:30010'
```

Restart DSH after editing its profile, then open `http://<host-ip>:30190`. The
container port in the mapping must equal `listenPort`; the external port can
be different. Leave `publicOrigin` empty and `trustProxy` disabled for direct
HTTP access. Keep the harness itself on loopback so it cannot bypass the gate.
HTTP exposes passwords and cookies; use a trusted LAN, VPN, or HTTPS.

Use a dedicated hostname or IP for the gate. Browser cookies are shared by
all ports on the same hostname or IP, so an untrusted service on another port
could receive the session cookie, even when both services use HTTPS.

For an HTTPS reverse proxy, set `publicOrigin`, for example
`https://gate.example.com`, and preserve the original `Host` header including
any non-default port (Nginx: `proxy_set_header Host $http_host;`). Restrict
direct access to the gate listener to the proxy. If `trustProxy` is enabled,
the proxy must replace client-supplied `X-Forwarded-For` with the real client
IP (Nginx: `proxy_set_header X-Forwarded-For $remote_addr;`).
`maxConnectionsPerPeer` counts the TCP peer, so proxied connections share the
proxy's limit. Adjust the limit for expected traffic and apply per-client limits
at the proxy when appropriate.

HTTPS harness certificates and hostnames are verified. For a private CA, set
`upstreamCaFile` to its PEM file; if the harness origin is an IP but its
certificate names a DNS host, also set `upstreamServerName` to that host.
Upstream HTTP response deadlines are disabled by default so long or quiet
Agent sessions can continue. Previously configured nonzero deadlines still
apply. Set appropriate timeouts if you need to limit stalled requests, and
check any reverse proxy's own timeouts as well. The separate WebSocket handshake
deadline applies until the upgrade succeeds; an established WebSocket is not
subject to it. If `upstreamHeaderTimeoutMs` is also set, the shorter deadline
applies to the handshake.

The gate admits at most 128 simultaneous upstream HTTP requests. When that
limit is reached, new requests receive 503 and may be retried; requests over
the per-session limit receive 429. Long-running streams count toward these
limits until they close.

Signing out or reaching the configured session expiry closes that session's
HTTP streams and WebSockets. Other sessions stay connected. Whether a
disconnected request stops its underlying work depends on DSH and its plugins;
allow important work to finish before signing out, changing the password, or
restarting DSH.

Authenticated HTTP responses use `Cache-Control: private, no-store`. Sign-out
also asks the browser to clear older cached content using `Clear-Site-Data`.
Browsers may ignore that request on non-local plaintext HTTP origins; clear the
browser cache manually there if protected content was cached before upgrading.

## Troubleshooting

- **No password in the log:** An existing hash or configured password is being
  reused. Set `password` and remove `passwordHash` to change it; this signs out
  existing sessions.
- **Cannot connect:** Check `listenHost`, the gate's startup log and the Docker
  port mapping. The gate port must match the container side of the mapping.
  To sign out, visit `/__gate/logout`.
- **Origin or host check fails:** Verify `publicOrigin` and the proxy's `Host`.
- **State file error:** Restore a trusted backup and ensure the file is owned
  by the DSH user with mode `0600`. If no backup exists, stop DSH and move the
  broken file aside; restart to create a new secret and invalidate sessions.
- **Profile state is locked:** Stop the other gate using this profile. Updating
  from an older version requires stopping the older process first.

The state file is `~/.dsh/profiles/<name>/data/dsh-frontgate.json`. Keep it and
its parent directories accessible only to trusted users. On Windows, use ACLs
to restrict access. Sign-out revocations persist across restarts. Each profile
allows one live gate, enforced by an OS-backed SQLite lock in the data
directory; it is released automatically on process exit, including a crash.
Use a filesystem that supports SQLite locking, and do not remove or replace
the lock file while a gate is running. The Node.js built-in `node:sqlite`
module must be enabled; some Node versions report an experimental warning.
Expired revocations are removed on sign-out, and a full or unwritable
revocation store makes sign-out fail safely.

## Development

```bash
npm ci
npm run typecheck
npm test
```

Browser tests require Chrome and OpenSSL; set `CHROME_PATH` if needed. They are
required in CI and skipped locally when Chrome is unavailable.
CI also checks login and WebSocket connectivity against DSH 0.2.2-rc.2 in an
isolated profile.

[Apache-2.0](LICENSE)
