# TLS test fixture

`test-cert.pem` and `test-key.pem` are public, self-signed test-only credentials. The certificate is valid for `upstream.test` and `gate.test` and is used only by the local HTTPS and browser tests. Never use this key for a real service.
