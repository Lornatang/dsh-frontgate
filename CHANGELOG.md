# Changelog

## Unreleased

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
