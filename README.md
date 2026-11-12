# dsh-frontgate

Protect the DeepSeek Harness Web UI with a password. The plugin listens on a
separate port and forwards authenticated requests to your local harness.

**Requirements:** Node.js 22.19 or later, DSH 0.2.2-rc.1 or later, and a DSH
profile with the Web app.

## Quick start

1. Install into the `web` profile:

   ```bash
   dsh plugin --profile web add https://codeload.github.com/Lornatang/dsh-frontgate/tar.gz/refs/tags/v0.1.1
   ```

   DSH creates the `web` profile if necessary. For an existing profile that
   already includes the Web app, replace `web` with its name. From a checkout,
   `./install.sh --profile <name>` can also create a new custom Web profile.

2. Restart the profile if it is already running. Otherwise, start it with:

   ```bash
   dsh web --no-open
   ```

   For another profile, replace `web` with its name.

3. If no password is configured or saved, the first start prints this line to
   stderr or your service's startup log:

   ```text
   [dsh-frontgate] PASSWORD: xxxx-xxxx-xxxx-xxxx
   ```

   Save the generated password; it is shown only once. The plugin saves its
   hash, not the password itself.

4. Open [http://127.0.0.1:3090](http://127.0.0.1:3090) and sign in. This is
   the gate address, separate from the URL printed by `dsh web`.

## Update

Run the install command for the desired release and profile, then restart DSH.
Existing configuration and the saved password remain in place; the password is
not printed again. Each release uses its own tag, so the URL changes when the
version changes. Do not replace a published release tag.

For offline installation, run `npm ci` and `npm pack` in a checkout on a
connected machine, copy the resulting tarball to the DSH host, and run:

```bash
dsh plugin --profile web add /path/to/dsh-frontgate-0.1.1.tgz
```

Restart the profile after installing.

## Configure

Edit `~/.dsh/profiles/<name>/cordis.patch.yml` for your profile. If `DSH_HOME`
is set, use `$DSH_HOME/profiles/<name>/cordis.patch.yml` instead. Add or edit
the existing `frontgate` entry, for example:

```yaml
- id: frontgate
  config:
    listenHost: '0.0.0.0' # allow connections from outside the container
    listenPort: 3090
    # password: 'replace-with-a-password-of-at-least-12-characters'
```

Restart the profile after changing its configuration. Omit `listenHost` to
keep the loopback-only default. The gate port must differ from the harness
port.

| Option | Default | Purpose |
| --- | --- | --- |
| `listenHost` | `127.0.0.1` | Address the gate listens on. |
| `listenPort` | `3090` | Gate port. |
| `password` | empty | Fixed password, at least 12 characters. |
| `passwordHash` | empty | A `scrypt$...` hash; takes precedence over `password`. |
| `sessionDays` | `7` | Session lifetime, from 1 to 365 days. |
| `title` | `DeepSeek Harness` | Login page title. |
| `maxAttempts` / `lockMinutes` | `5` / `5` | Failed-attempt threshold and lockout duration per client IP. |
| `tlsCertFile` / `tlsKeyFile` | empty | Set both to serve HTTPS directly. |
| `publicOrigin` | empty | External origin, such as `https://gate.example.com`; required when a proxy terminates HTTPS. |
| `trustProxy` | `false` | Use forwarded client IPs behind a trusted proxy. |
| `exchangeTimeoutMs` | `5000` | Timeout for exchanging the harness launch token, in milliseconds. |

When neither password option is set, the DSH process checks
`DSH_FRONTGATE_PASSWORD_HASH`, then `DSH_FRONTGATE_PASSWORD`, then the saved
hash. If none is available, it generates a password. The 12-character minimum
also applies to `DSH_FRONTGATE_PASSWORD`.

## Docker and remote access

For a container, set `listenHost: '0.0.0.0'` as above and publish the gate
port. For example, this Docker Compose service fragment maps host port 30190
to gate port 3090 inside the container:

```yaml
ports:
  - '30190:3090'
```

Then open `http://<host-ip>:30190`. Changing the published port requires
updating the container configuration; changing `listenPort` requires updating
the container-side port in the mapping too.

Keep the harness itself bound to `127.0.0.1` and expose only the gate port;
otherwise clients can bypass the password. Plain HTTP exposes passwords and
cookies on the network, so use it only on a trusted LAN or VPN. For other
networks, enable the TLS options or terminate TLS with a trusted reverse proxy.

**Use a dedicated hostname or IP for the gate.** Browser cookies are shared by
all ports on the same hostname or IP. For IP access such as
`http://192.168.30.211:30190`, do not host untrusted Web services on any other
port of that IP: they could receive and reuse the gate session cookie. HTTPS
does not isolate cookies between HTTPS ports.

For an HTTPS reverse proxy, configure the browser-facing origin, including a
non-default port if present:

```yaml
- id: frontgate
  config:
    publicOrigin: 'https://gate.example.com'
    trustProxy: true
```

The proxy must preserve the original `Host` header, including any non-default
port (for Nginx, `proxy_set_header Host $http_host;`). Restrict direct access
to the gate listener so only your trusted proxy can reach it. When `trustProxy`
is enabled, the proxy must replace any client-supplied `X-Forwarded-For` with
the actual client IP, for example with this Nginx directive:
`proxy_set_header X-Forwarded-For $remote_addr;`. The plugin then sets
`Secure` on its session cookie. Configure
HSTS at the proxy if needed. Direct HTTPS with `tlsCertFile` and `tlsKeyFile`
does not require `publicOrigin`.

After `maxAttempts` failures, all login attempts from that IP are rejected for
`lockMinutes`, including attempts with the correct password. Clients behind the
same NAT may share a lockout. Lockouts are stored in memory and reset when DSH
restarts.

## Troubleshooting

- **No password in the latest startup log:** An existing password hash or a
  configured password is reused. To set a new one, configure `password` and
  restart; remove any configured `passwordHash` first because it takes
  precedence. Changing the password invalidates existing sessions.
- **Cannot connect remotely:** Check the gate's `listening on` log line,
  `listenHost`, and the Docker port mapping. The host port and container port
  can differ.
- **Need to sign out:** Visit `/__gate/logout` on the gate address.
- **State file error:** Restore the file from a trusted backup, check that it
  is owned by the DSH service user and has mode `0600`, then restart. If no
  backup exists, stop DSH and move the broken file aside before restarting;
  a new signing secret will be generated, invalidating sessions. If no
  password is configured, a new password will also be generated.
- **Origin or host check fails behind a proxy:** Check `publicOrigin` and make
  sure the proxy preserves the browser's `Host` header, including its port.

The state file `~/.dsh/profiles/<name>/data/dsh-frontgate.json` stores the
password hash and session-signing secret. With `DSH_HOME` set, it is under
`$DSH_HOME/profiles/<name>/data/` instead. Everyone shares one password; there
are no individual accounts or per-session revocation. Deleting the state file
invalidates all sessions. On Windows, restrict access to the state file and its
parent directory with operating-system ACLs; POSIX mode checks cannot verify
Windows ACLs. Keep the profile and state directories writable only by trusted
users; a user who can replace the state file or its parent directory can
compromise sessions.

## Development

```bash
npm ci
npm run typecheck
npm test
```

Sources are in `src/`; `npm run build` regenerates the bundled files in `lib/`.
The browser tests use Chrome and OpenSSL. Set `CHROME_PATH` if Chrome is not
at a standard location. They are required in CI and skipped locally when
Chrome is unavailable.

## License

[Apache-2.0](LICENSE)
