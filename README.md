---
description: "Password protection in front of a dsh Web profile: one gate port, one password, one signed session cookie, and a reverse proxy to the harness on loopback."
kind: "package-bundle"
---

# @lornatang/dsh-frontgate

English | [中文](README.zh.md)

## Summary

`dsh-frontgate` puts a password in front of the dsh Web UI. It listens on its own port, checks a password once, issues a signed session cookie, and forwards authenticated HTTP and WebSocket traffic to the harness on loopback. Add it to any Web profile to reach the GUI from a LAN, a VPN, or a container without exposing the harness itself. The state file stores only a scrypt hash, and the first start prints the generated password once. The boundary: one password per profile and no per-user accounts, and plain HTTP protects nothing on the wire.

## Table of Contents

- [Use this package](#use-this-package)
- [Understand the implementation](#understand-the-implementation)
- [Further Exploration](#further-exploration)
- [Model Experience](#model-experience)
- [Known Limitations and Deferred Work](#known-limitations-and-deferred-work)
- [Dev Note](#dev-note)

-----

<a id="use-this-package"></a>
## Use this package

The browser talks to the gate and the gate talks to the harness on loopback, so the harness listener never becomes reachable from the network. Install the layer into the Web profile whose GUI you want to protect.

### Install into a profile

```text
dsh plugin --profile web add @lornatang/dsh-frontgate
dsh plugin --profile web remove @lornatang/dsh-frontgate
```

For the GitHub-only 0.1.9 release, use `dsh plugin --profile web add https://github.com/Lornatang/dsh-frontgate/releases/download/v0.1.9/lornatang-dsh-frontgate-0.1.9.tgz` or run `install.sh` from this release. The npm registry version may be older.

The `add` command composes the layer into the profile: its `cordis.patch.yml` gains an insert entry, row id `frontgate`, whose `config` starts from the loopback defaults below. A package whose manifest omits the `dsh.bundle.patch` declaration fails this step instead of silently mounting nothing. Restart DSH after installing, then open <http://127.0.0.1:3090> and sign in.

With no configured and no saved password, the first start generates one and logs it once:

```text
[dsh-frontgate] PASSWORD: xxxx-xxxx-xxxx-xxxx
```

Save it as it appears: only its scrypt hash reaches the state file, and the plaintext is not recoverable later.

`--profile web` names the shipped Web profile; pass the name of your own Web profile in both commands. An upgrade runs the same `add` command and keeps the profile entry and the saved password. Releases before 0.1.6 published the package unscoped as `dsh-frontgate`, so add the scoped package, remove the old name, then restart once; two gates for one profile cannot run together regardless, because a profile admits one live gate.

### What you get

The layer adds no model tools and no client UI rows: it owns the transport in front of the harness. A profile with it gains a sign-in page at `/__gate/login`, the matching `POST /__gate/login`, `POST /__gate/logout` and `GET /__gate/health` routes, and one signed session cookie (`dsh_gate`) that every proxied request must carry. Unauthenticated API calls receive `401 {"error":"unauthorized"}` with a login hint; every other path redirects to the login page with a `next` target. Unknown `/__gate/*` paths are answered by the gate and never proxied.

Everything the profile already offered stays the same behind the gate: the Web GUI, the session API and the WebSocket streams are proxied to the harness origin once the cookie checks out, with hop-by-hop headers dropped and the harness launch cookie exchanged server-side.

### Configuration

The bundle ships the row below, so a profile only lists what differs from it: the profile's own entry is applied after the layer and wins.

```yaml
# $DSH_HOME/profiles/web/cordis.patch.yml
- id: frontgate
  config:
    listenHost: '0.0.0.0' # only when remote access is needed
    listenPort: 30010
    # password: 'a-password-of-at-least-12-characters'
```

The loader validates each field against `src/config.ts` and rejects an invalid value at startup instead of substituting a default. A bare `frontgate` row without `config` runs on these defaults:

| Field | Default | Meaning |
|---|---|---|
| `listenHost` | `127.0.0.1` | Interface the gate listens on. |
| `listenPort` | `3090` | Gate port; `0` picks an ephemeral port. It must differ from the harness port. |
| `sessionDays` | `7` | Absolute session lifetime, 1–365 days. |
| `title` | `DeepSeek Harness` | Title shown on the login page. |
| `password` | empty | Plain-text password, at least 12 characters; hashed at startup and never written to disk as text. |
| `passwordHash` | empty | scrypt hash; takes precedence over every other password source. |
| `tlsCertFile` / `tlsKeyFile` | empty | Set both to serve HTTPS directly from the gate. |
| `publicOrigin` | empty | Exact browser-facing origin when using a hostname, NAT, or reverse proxy, for example `https://gate.example.com`. |
| `trustProxy` | `false` | Honour `X-Forwarded-For`; enable only when the listener is restricted to a trusted proxy. |
| `maxAttempts` | `5` | Failed logins before a client IP is locked out, 1–50. |
| `lockMinutes` | `5` | Lockout duration, 1–1440 minutes. |
| `exchangeTimeoutMs` | `5000` | Deadline for the harness launch-token exchange. |
| `maxConnectionsPerPeer` | `64` | Simultaneous TCP connections per peer, 0–1024; `0` disables the limit. |
| `maxPendingLoginsPerIp` | `4` | Login forms being received from one client IP, 1–128. |
| `maxHttpRequestsPerSession` | `32` | Simultaneous HTTP requests per signed-in session, 1–128, including requests waiting for the harness. |
| `upstreamHeaderTimeoutMs` | `0` | Upstream response-header deadline including queue time; `0` disables it. |
| `upstreamIdleTimeoutMs` | `0` | Upstream response idle deadline; `0` disables it. |
| `websocketHandshakeTimeoutMs` | `10000` | Deadline for the upstream WebSocket handshake; it stops applying once the upgrade succeeds. |
| `upstreamCaFile` / `upstreamServerName` | empty | CA file and TLS identity for a private HTTPS harness reached by IP. |

### Passwords and sessions

The password is taken from, in order: `passwordHash`, `password`, `DSH_FRONTGATE_PASSWORD_HASH`, `DSH_FRONTGATE_PASSWORD`, the saved hash, then a newly generated password. A plain password must be at least 12 characters. Changing the configured password replaces the saved hash and signs out existing sessions.

After `maxAttempts` failed logins a client IP is locked out for `lockMinutes`, and the lockout rejects correct passwords too. Clients behind one NAT share the address, so a lockout there affects all of them. The gate tracks up to 1,024 clients with recent failures; when that store is full, a new client waits for an entry to expire instead of displacing an active lockout, and stale failure counts stop counting after the lockout window.

A session lasts `sessionDays` regardless of activity. The cookie is `dsh_gate`, `HttpOnly`, `SameSite=Lax`, and `Secure` whenever the public origin is HTTPS. `/__gate/logout` revokes the session, closes its HTTP streams and WebSockets, and asks the browser to clear cached content with `Clear-Site-Data`; other sessions stay connected. Revocations persist across restarts.

State lives in `$DSH_HOME/profiles/<name>/data/dsh-frontgate.json`. On POSIX systems its permissions are tightened to `0600`; on Windows, restrict access to the profile data directory with Windows ACLs. One live gate per profile is enforced by an OS-backed SQLite lock in the same directory, released automatically on process exit, including a crash; therefore the data directory must support SQLite locking and the lock file must not be removed or replaced while the gate runs. The Node.js built-in `node:sqlite` module must be enabled, which is why the package requires Node.js 22.19 or newer.

### Remote access

For Docker, bind the gate to all interfaces and publish its port; the container side of the mapping must equal `listenPort`, while the host side may differ:

```yaml
# profile patch
- id: frontgate
  config:
    listenHost: '0.0.0.0'
    listenPort: 30010
    publicOrigin: 'http://<host-ip>:30190' # replace with the actual browser-facing origin
```

```yaml
# Docker Compose
ports:
  - '30190:30010'
```

Open `http://<host-ip>:30190` afterwards. Set `publicOrigin` to that exact browser-facing origin whenever NAT, a reverse proxy, or a hostname makes it different from the gate's local address and port. With no `publicOrigin`, the gate accepts only its local socket address and port (and `localhost` for loopback). Keep `trustProxy` disabled for direct HTTP access and keep the harness itself on loopback so the gate cannot be bypassed on the host.

Behind an HTTPS reverse proxy, set `publicOrigin` to the external origin and preserve the original `Host` header, including any non-default port (Nginx: `proxy_set_header Host $http_host;`). Restrict direct access to the gate listener to the proxy. With `trustProxy` enabled the proxy must replace client-supplied `X-Forwarded-For` with the real client address (Nginx: `proxy_set_header X-Forwarded-For $remote_addr;`), because the gate otherwise trusts what the client sent. `maxConnectionsPerPeer` counts the TCP peer, so proxied traffic shares the proxy's limit; apply per-client limits at the proxy.

HTTPS harness certificates and hostnames are verified. For a private CA set `upstreamCaFile` to its PEM file; when the harness origin is an IP but its certificate names a DNS host, also set `upstreamServerName` to that host.

The gate admits at most 128 simultaneous upstream HTTP requests. Requests beyond that limit receive 503 and may be retried; requests over the per-session limit receive 429. Long-running streams count against these limits until they close. Upstream response deadlines are disabled by default so quiet Agent sessions can continue; set them when you need to bound stalled requests, and check the reverse proxy's own timeouts as well. Authenticated responses are sent with `Cache-Control: private, no-store`.

Use a dedicated hostname or IP for the gate. Browser cookies are shared by all ports on the same hostname or IP, so an untrusted service on another port of that host could receive the session cookie, even over HTTPS.

### Troubleshooting

- **No password in the log** — a saved hash or a configured password is being reused. Set `password` and clear `passwordHash` to rotate it; that signs out existing sessions.
- **Cannot connect** — check `listenHost`, the gate's startup log, and that the container port in the mapping equals `listenPort`.
- **Origin or host check fails** — verify `publicOrigin` and that the proxy forwards the original `Host`.
- **State file error** — restore a trusted backup, or stop DSH, move the damaged file aside, and restart to generate a new secret and invalidate sessions. The file must be owned by the DSH user with mode `0600`.
- **Profile state is locked** — another gate still uses this profile. Stop it; upgrading from an older version requires stopping the older process first.

-----

<a id="understand-the-implementation"></a>
## Understand the implementation

<details>
<summary>Implementation internals — click to expand</summary>

The bundle is one row: `insert` of `frontgate` with the loopback defaults, applied to the target profile. Nothing is gated by platform, because the gate is a host-side listener; the client UI it protects belongs to the harness, not to this package.

`apply` waits for the `webServer` and `connection` services, resolves the harness origin from `ctx.webServer.getOrigin()`, and refuses to start when `listenPort` collides with the harness port. TLS requires both files; a `publicOrigin` that is not HTTPS while serving TLS is rejected. Password selection, session store, gate handler, and proxy are built from these values before the listener starts.

The gate serves `/__gate/login`, `/__gate/logout`, and `/__gate/health` itself, answers `/api` with a 401 JSON body for unauthenticated callers, and redirects other unauthenticated requests to the login page with the original path as `next`. The harness index document is served with an idempotent `crypto.randomUUID` polyfill, because a plain-HTTP LAN origin is not a secure context.

The proxy drops hop-by-hop and browser headers, rewrites `Host` and `Origin` to the harness origin, and exchanges the launch cookie on the server side so the browser never sees it; the exchanged cookie is reused for 25 minutes. WebSocket upgrades are spliced at the TCP level after the handshake deadline passes. A connection counter bounds admission before requests reach the harness queue.

The state file keeps the password hash, the cookie signing secret, and the revocation list; it is written `0600` and rewritten when the password changes. The SQLite lock file next to it admits one gate per profile and is released on exit.

| Source | Contents |
|---|---|
| `cordis.patch.yml` | The layer: one insert entry, row id `frontgate`, loopback defaults. |
| `src/index.ts` | `apply`: configuration resolution, password selection, listener and TLS setup, gate and proxy wiring. |
| `src/gate.ts` | Gate routes, login and logout, redirects, `/api` rejections, admitted request forwarding. |
| `src/proxy.ts` | Header rewriting, launch-cookie exchange, WebSocket splice, upstream admission cap. |
| `src/auth.ts` | Password hashing and verification, the 12-character minimum, the `dsh_gate` cookie. |
| `src/state.ts` | The profile state file, `0600` tightening, salt reuse. |
| `src/state-lock.ts` | The `node:sqlite` lock that admits one live gate per profile. |
| `src/sessions.ts` | Session validity, expiry, revocation, stream teardown. |
| `src/polyfill.ts` | The `crypto.randomUUID` fallback injected into the harness index document. |
| `tests/*.test.mjs` | Gate, browser and install suites. |

</details>

-----

<a id="further-exploration"></a>
## Further Exploration

- [CHANGELOG.md](CHANGELOG.md) — release history and the 0.1.x upgrade notes.
- [install.sh](install.sh) — the one-command install helper used by the release workflow.
- [DeepSeek Harness configuration catalog](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/config-catalog.md) — the loader semantics this layer's row obeys.
- [Apache-2.0 license](LICENSE).

-----

<a id="model-experience"></a>
## Model Experience

None, as the gate authenticates transport connections before the harness sees them; every admitted request still travels the composed Web rows unchanged.

#### KV Cache effect

The gate adds nothing to the request prefix: it re-authenticates connections rather than rewriting conversations, so token accounting and cache behaviour match the same profile without the gate.

<a id="known-limitations-and-deferred-work"></a>
## Known Limitations and Deferred Work

These limits tell you when the gate does not fit and what it needs from the profile around it.

- **One password, no accounts** — every user behind the gate shares one identity, so the gate is a perimeter, not an authorization system; anyone with the password sees every session the profile stores.
- **Plain HTTP protects nothing on the wire** — passwords, cookies and traffic are readable by anyone on the path. Use a VPN, a trusted LAN, or TLS through `tlsCertFile` and `tlsKeyFile` or a reverse proxy.
- **Session cookies are host-scoped** — all ports on one hostname or IP share them, so an untrusted service on another port of that host can receive the cookie.
- **Lockout is per address** — clients behind one NAT share a lockout, and a hostile client can lock the shared address until the window expires.
- **One live gate per profile** — a second gate on the same profile fails on the state lock; stand up a separate profile or host instead.
- **Upstream deadlines default to off** — quiet Agent sessions survive, but a stalled request can hold an admission slot until it closes, and the gate's own limits are the only bound.
- **Certificates are verified, not bypassed** — a private CA needs `upstreamCaFile`, and an IP origin needs `upstreamServerName`; there is no insecure-skip option.
- **The gate is not a sandbox** — it protects the harness listener, not the host: keep the harness on loopback and treat the gate's password as the only barrier.

<a id="dev-note"></a>
### Dev Note

<details>
<summary>Working context for maintainers — click to expand</summary>

`npm run build` bundles `src/index.ts` into `lib/index.js` with esbuild; `npm test` builds first, then runs `node --test tests/*.test.mjs`; `npm run test:dsh` checks the profile-facing surface, and `npm run pack:verify` inspects the packed file list. `node:sqlite` fixes the minimum runtime at Node.js 22.19. Read `CHANGELOG.md` before changing the state file format, because the saved hash and signing secret must survive an upgrade.

</details>
