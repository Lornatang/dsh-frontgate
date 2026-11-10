# Changelog

## 0.1.0 - 2026-11-10

First release.

- Password gate for the DeepSeek Harness Web UI with a signed, stateless
  session cookie (HMAC-SHA256, per-session nonce, absolute TTL).
- Session tokens embed a tag of the current password hash, so changing the
  password revokes every issued session without a session table.
- Login uses async scrypt (N=32768, r=8, p=1, 32-byte key); no synchronous
  hashing on the request path.
- Per-client lockout (default 5 failures / 5 minutes), a global scrypt
  concurrency cap, a 4 KiB form limit and an 8 s body timeout.
- Host/Origin are rewritten to the harness origin; hop-by-hop headers dropped;
  upstream Set-Cookie never reaches the browser.
- The harness launch token is exchanged server-side and its cookie is injected
  per request; the browser only ever holds the gate cookie.
- WebSocket upgrades are authenticated, then spliced as raw TCP.
- Adds a crypto.randomUUID polyfill to the harness HTML (plain HTTP on a LAN IP
  is not a secure context).
- Loopback-only by default, optional native TLS with HSTS; no admin page, no
  i18n, no mutable settings file.
- Options are declared as a schemastery schema; sources are TypeScript modules
  under " + B + "src/" + B + ", bundled into " + B + "lib/index.js" + B + " with generated type
  declarations.
- " + B + "install.sh" + B + " installs the plugin into a profile and creates the profile from
  the web template when it does not exist yet.
- " + B + "DSH_FRONTGATE_PASSWORD" + B + " and " + B + "DSH_FRONTGATE_PASSWORD_HASH" + B + " environment overrides
  keep the password out of configuration files.
