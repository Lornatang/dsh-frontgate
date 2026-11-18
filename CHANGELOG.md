# Changelog

## 0.1.14 - 2026-11-19

- Replace the password-derived session cookie value with a random per-install epoch persisted beside the password hash and regenerated when the password changes, so no password-derived value is signed or stored in the cookie (clears the js/insufficient-password-hash and js/clear-text-storage-of-sensitive-data findings).
- Invalidate revoked sessions by comparing epochs and keep stored credentials when a saved state already carries an epoch.

## 0.1.13 - 2026-11-19

- Append logout revocations to a small fsync'd journal instead of rewriting the whole state file per sign-out; the journal is merged back on read and compacted into the main state when it grows.
- Keep the durable-before-success ordering and the maximum revoked-session bound.

## 0.1.12 - 2026-11-19

- Stop passing an unused context to the logger resolver and stop exporting the internal origin/host matcher.
- Attach install.sh to the GitHub release, as the README already describes.

## 0.1.11 - 2026-11-18

- Refuse every `/__gate/logout` method other than `GET`, `HEAD` and `POST`.
- Key lockouts on the peer address when the first `X-Forwarded-For` hop is not
  an IP address, instead of trusting a client-supplied value.
- Cache a harness cookie only after a successful launch-token exchange, so an
  error response from the harness cannot replace every later session's cookie.
- Rewrite bare protocol-relative redirect Locations (`//host`, `/\host`) to
  `/` so they cannot leave the gate.
- Stop tracking a connection that was already destroyed, so its session entry
  and expiry timer no longer outlive it.
- Retry the state-file rename on Windows when a scanner or indexer briefly
  holds the destination, and sync the parent directory on POSIX.
- Wait up to 30 s for a cold Chrome start in the browser suite, report Chrome's
  last errors on failure, and retry once with a fresh profile.
- Resolve every dependency from `registry.npmjs.org`; the lockfile no longer
  points at a third-party mirror.
- Update TypeScript to 7.0.2, esbuild to 0.28.2 and @types/node to 26.6.6, and
  move the GitHub Actions to v7.
- Publish this release on GitHub and npm.

## 0.1.10 - 2026-11-17

- Admit new login clients when the failure store is full of partial failure
  counts by evicting the stalest partial record; live lockouts and in-flight
  checks are still never evicted, and a store full of live lockouts still
  fails closed.
- Reject stored scrypt hashes whose total work exceeds 512 MiB so a crafted
  password hash cannot burn unbounded CPU or memory on every login.
- Rewrite self-origin redirect Locations that carry only a query or fragment,
  and leave prefix-similar external authorities untouched.
- Send Strict-Transport-Security whenever the public origin is https, including
  when TLS terminates at a reverse proxy.
- Run the launch-token exchange on the owned upstream agent so shutdown
  destroys every upstream socket.
- Publish this release on GitHub and npm.

## 0.1.9 - 2026-11-15

- Close test gates before removing their state directories and exercise the correct Windows and POSIX permission behavior.
- Use a test-only TLS fixture and locate Chrome and Bash on Windows; test the installer without false-positive process failures.
- Run the complete test suite on Windows with Node.js 22 and 24 in CI.
- Publish this release on GitHub only; npm is not updated.

## 0.1.8 - 2026-11-15

- Validate the browser-facing Host against the listener or configured public origin, including WebSocket upgrades.
- Install the matching GitHub release archive and keep installer and package versions aligned.

## 0.1.7 - 2026-11-15

- Rewrite the README to the package-bundle documentation convention and add a
  Chinese translation; the package now ships `README.md` and `README.zh.md`.
- Publish `cordis.patch.yml` through the package `exports` map and include the
  Chinese README in the published files.
- Build on Windows: resolve project paths with `fileURLToPath` and invoke the
  local TypeScript compiler through the Node.js executable.

## 0.1.6 - 2026-11-13

- Allow any DSH version in the package metadata and run integration checks against the selected host.
- Keep the installer aligned with this release and make the lockout-capacity test independent of machine speed.

## 0.1.5 - 2026-11-13

- Keep the README focused on installation and everyday use.

## 0.1.4 - 2026-11-12

- Close rejected upgrade sockets, bound WebSocket handshakes and prevent one
  session or a saturated upstream pool from leaving HTTP requests queued forever.
- Disable caching of authenticated responses and ask browsers to clear older
  cached content at sign-out.
- Preserve live login lockouts when the failure store is full and expire old
  partial failure counts.

## 0.1.3 - 2026-11-12

- Close HTTP streams, as well as WebSockets, when their gate session is revoked
  or expires; leave other sessions connected.
- Filter upstream cookies and hop-by-hop headers from WebSocket handshakes and
  reject invalid upgrades. Allow only one live gate per state directory, with
  an OS-backed lock that is released when the process exits.
- Disable upstream header and idle deadlines by default for long-running and
  quiet Agent sessions. Explicitly configured deadlines still apply.
- Exercise session isolation, crash recovery, long streams, installed package
  startup and DSH 0.2.2-rc.2 connectivity in the test suite and CI.

## 0.1.2 - 2026-11-12

- Persist session revocations on sign-out, reject alternate token encodings,
  and close WebSockets on sign-out, expiry, or shutdown.
- Bound per-peer connections and incomplete logins; cancel disconnected clients
  and time out stalled upstream HTTP responses without cutting off active streams.
- Verify HTTPS harness certificates, refresh stale harness cookies after a 401,
  and return an HTTP error for oversized chunked login forms.
- Document Docker port mapping and add security, browser and proxy regression tests.

## 0.1.1 - 2026-11-12

- Publish as `@lornatang/dsh-frontgate`; install with `dsh plugin` using the
  npm package name. Document migration from the previous unscoped package.
- Compare the full browser-facing origin, including scheme and port, for login,
  authenticated requests and WebSockets. Configure `publicOrigin` when HTTPS
  is terminated by a reverse proxy; it also enables Secure session cookies.
- Enforce per-client login lockouts before password verification, and limit
  concurrent password checks from one client.
- Refuse malformed, exposed or incorrectly owned state files instead of
  silently replacing credentials; persist state through an atomic replacement.
- Bound the harness launch-token exchange and retry on later requests after a
  timeout.
- Add browser and security regression tests to CI. Document the requirement
  for a dedicated hostname or IP because browser cookies are shared by ports.

## 0.1.0 - 2026-11-10

First release.

- Fix browser login failing with `Origin check failed` when the login page's
  referrer policy caused browsers to send `Origin: null` on form submissions.
- Print a reminder to save the generated password after its hash is stored.
- Resolve the release tag to its commit when installing, so replacing a tag
  does not leave an existing installation on a cached archive.
- Create the default web profile correctly on first install.
- Password gate for the DeepSeek Harness Web UI with a signed, stateless
  session cookie (HMAC-SHA256, per-session nonce, absolute TTL).
- Session tokens embed a tag of the current password hash, so changing the
  password revokes every issued session without a session table.
- Login uses async scrypt (N=32768, r=8, p=1, 32-byte key); no synchronous
  hashing on the request path.
- Failed logins are counted per client: once the limit is reached, failures
  answer 429 with Retry-After, while a correct password is always verified and
  accepted, so a shared address cannot be locked out by one client.
- Proxied requests and WebSocket upgrades are checked against their Origin; a
  cross-site request that carries a session cookie is refused with 403.
- Host and Origin are rewritten to the harness origin; hop-by-hop headers
  dropped; upstream Set-Cookie never reaches the browser.
- The harness launch token is exchanged server-side and its cookie is injected
  per request; the browser only ever holds the gate cookie.
- WebSocket upgrades are authenticated, then spliced as raw TCP.
- Adds a crypto.randomUUID polyfill to the harness HTML (plain HTTP on a LAN IP
  is not a secure context).
- Loopback-only by default, optional native TLS with HSTS; no admin page, no
  i18n, no mutable settings file.
- A configured password (option or `DSH_FRONTGATE_PASSWORD`) must be at least
  12 characters; shorter values stop startup with an explicit error.
- Upstream redirects that would leave the origin (protocol-relative or
  backslash forms) are rewritten to `/`.
- The listener sets header and request deadlines, checks connection deadlines
  every 5 seconds, and caps concurrent connections at 1024.
- The state file (password hash and signing secret) is chmod 0600 on startup,
  including when it already existed with looser permissions.
- Options are declared as a schemastery schema; sources are TypeScript modules
  under `src/`, bundled into `lib/index.js` with generated type declarations.
- `install.sh` installs the plugin into a profile and creates the profile from
  the web template when it does not exist yet.
- `DSH_FRONTGATE_PASSWORD` and `DSH_FRONTGATE_PASSWORD_HASH` environment
  overrides keep the password out of configuration files.
