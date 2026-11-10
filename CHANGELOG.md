# Changelog

## 1.1.0 - 2026-11-10

- Added `install.sh`, a one-command installer. It creates the profile from the
  web template when the profile does not exist, installs the plugin, and
  checks that the bundle was registered.
- User-facing strings, README and package metadata are English-only.
- Added `DSH_FRONTGATE_PASSWORD` and `DSH_FRONTGATE_PASSWORD_HASH` environment
  overrides for container deployments.
- Gate responses send `Strict-Transport-Security` when TLS is enabled.

## 1.0.0 - 2026-11-10

First release.

- Password gate for the DeepSeek Harness Web UI with a signed, stateless
  session cookie (HMAC-SHA256, per-session nonce, sliding-free absolute TTL).
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
- Loopback-only by default; optional native TLS; no admin page, no i18n, no
  mutable settings file, no runtime dependencies.
- Fixed relative `Location` rewriting for upstream redirects.
