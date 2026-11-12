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
| `sessionDays` | `7` | Session lifetime, 1–365 days. |
| `maxAttempts` / `lockMinutes` | `5` / `5` | Failed attempts and lockout duration per client IP. |
| `tlsCertFile` / `tlsKeyFile` | empty | Set both for direct HTTPS. |
| `publicOrigin` | empty | External origin when a reverse proxy terminates HTTPS. |
| `trustProxy` | `false` | Use client IPs supplied by a trusted proxy. |
| `exchangeTimeoutMs` | `5000` | Harness token exchange timeout in milliseconds. |
| `title` | `DeepSeek Harness` | Login page title. |

Password precedence is configured hash, configured password,
`DSH_FRONTGATE_PASSWORD_HASH`, `DSH_FRONTGATE_PASSWORD`, saved hash, then a
newly generated password. Lockout blocks all attempts from the IP, including
correct passwords, until it expires; clients behind the same NAT may share it.

## Remote access

For Docker, set `listenHost: '0.0.0.0'` and publish the gate port, for example:

```yaml
ports:
  - '30190:3090'
```

Then open `http://<host-ip>:30190`. Keep the harness itself on loopback so it
cannot bypass the gate. HTTP exposes passwords and cookies; use a trusted LAN,
VPN, or HTTPS.

Use a dedicated hostname or IP for the gate. Browser cookies are shared by
all ports on the same hostname or IP, so an untrusted service on another port
could receive the session cookie, even when both services use HTTPS.

For an HTTPS reverse proxy, set `publicOrigin`, for example
`https://gate.example.com`, and preserve the original `Host` header including
any non-default port (Nginx: `proxy_set_header Host $http_host;`). Restrict
direct access to the gate listener to the proxy. If `trustProxy` is enabled,
the proxy must replace client-supplied `X-Forwarded-For` with the real client
IP (Nginx: `proxy_set_header X-Forwarded-For $remote_addr;`).

## Troubleshooting

- **No password in the log:** An existing hash or configured password is being
  reused. Set `password` and remove `passwordHash` to change it; this signs out
  existing sessions.
- **Cannot connect:** Check `listenHost`, the gate's startup log and the Docker
  port mapping. To sign out, visit `/__gate/logout`.
- **Origin or host check fails:** Verify `publicOrigin` and the proxy's `Host`.
- **State file error:** Restore a trusted backup and ensure the file is owned
  by the DSH user with mode `0600`. If no backup exists, stop DSH and move the
  broken file aside; restart to create a new secret and invalidate sessions.

The state file is `~/.dsh/profiles/<name>/data/dsh-frontgate.json`. Keep it and
its parent directories accessible only to trusted users. On Windows, use ACLs
to restrict access.

## Development

```bash
npm ci
npm run typecheck
npm test
```

Browser tests require Chrome and OpenSSL; set `CHROME_PATH` if needed. They are
required in CI and skipped locally when Chrome is unavailable.

[Apache-2.0](LICENSE)
