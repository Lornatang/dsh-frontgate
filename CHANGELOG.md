# Changelog

## 0.1.0 - 2026-11-10

First release.

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
