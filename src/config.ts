/**
 * Plugin configuration and its loader schema.
 *
 * The values are also the documented defaults, so a patch file that only sets
 * one option behaves exactly like the README's configuration table.
 */
import z from '@deepseek-ai/schemastery'

/** Configuration accepted through cordis.patch.yml or the loader. */
export interface Config {
  /** Interface the gate listens on. */
  listenHost: string
  /** Port the gate listens on; 0 picks an ephemeral port. */
  listenPort: number
  /** Session lifetime in days. */
  sessionDays: number
  /** Title shown on the login page. */
  title: string
  /** Plain-text password; hashed at startup and never written to disk as text. */
  password: string
  /** scrypt password hash; takes precedence over password, environment and state file. */
  passwordHash: string
  /** Optional TLS certificate; both files must be set to serve HTTPS. */
  tlsCertFile: string
  /** Optional TLS key; both files must be set to serve HTTPS. */
  tlsKeyFile: string
  /** Browser-facing origin, required when a reverse proxy terminates TLS. */
  publicOrigin: string
  /** Honour X-Forwarded-For only when the listener is restricted to a trusted proxy. */
  trustProxy: boolean
  /** Failed logins before a client is locked out. */
  maxAttempts: number
  /** Lockout duration in minutes. */
  lockMinutes: number
  /** Maximum time to exchange the harness launch token, in milliseconds. */
  exchangeTimeoutMs: number
}

/** Defaults applied by the loader and by direct calls to apply(). */
export const DEFAULTS: Config = {
  listenHost: '127.0.0.1',
  listenPort: 3090,
  sessionDays: 7,
  title: 'DeepSeek Harness',
  password: '',
  passwordHash: '',
  tlsCertFile: '',
  tlsKeyFile: '',
  publicOrigin: '',
  trustProxy: false,
  maxAttempts: 5,
  lockMinutes: 5,
  exchangeTimeoutMs: 5000,
}

/** Schemastery schema; the loader validates and fills defaults before apply(). */
export const Config: z<Config> = z.object({
  listenHost: z.string().default(DEFAULTS.listenHost),
  listenPort: z.natural().max(65535).default(DEFAULTS.listenPort),
  sessionDays: z.natural().min(1).max(365).default(DEFAULTS.sessionDays),
  title: z.string().default(DEFAULTS.title),
  password: z.string().default(DEFAULTS.password),
  passwordHash: z.string().default(DEFAULTS.passwordHash),
  tlsCertFile: z.string().default(DEFAULTS.tlsCertFile),
  tlsKeyFile: z.string().default(DEFAULTS.tlsKeyFile),
  publicOrigin: z.string().default(DEFAULTS.publicOrigin),
  trustProxy: z.boolean().default(DEFAULTS.trustProxy),
  maxAttempts: z.natural().min(1).max(50).default(DEFAULTS.maxAttempts),
  lockMinutes: z.natural().min(1).max(1440).default(DEFAULTS.lockMinutes),
  exchangeTimeoutMs: z.natural().min(100).max(60000).default(DEFAULTS.exchangeTimeoutMs),
})
