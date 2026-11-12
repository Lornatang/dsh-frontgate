/**
 * Plugin configuration and its loader schema.
 *
 * The values are also the documented defaults, so a patch file that only sets
 * one option behaves exactly like the README's configuration table.
 */
import z from '@deepseek-ai/schemastery';
/** Configuration accepted through cordis.patch.yml or the loader. */
export interface Config {
    /** Interface the gate listens on. */
    listenHost: string;
    /** Port the gate listens on; 0 picks an ephemeral port. */
    listenPort: number;
    /** Session lifetime in days. */
    sessionDays: number;
    /** Title shown on the login page. */
    title: string;
    /** Plain-text password; hashed at startup and never written to disk as text. */
    password: string;
    /** scrypt password hash; takes precedence over password, environment and state file. */
    passwordHash: string;
    /** Optional TLS certificate; both files must be set to serve HTTPS. */
    tlsCertFile: string;
    /** Optional TLS key; both files must be set to serve HTTPS. */
    tlsKeyFile: string;
    /** Browser-facing origin, required when a reverse proxy terminates TLS. */
    publicOrigin: string;
    /** Honour X-Forwarded-For only when the listener is restricted to a trusted proxy. */
    trustProxy: boolean;
    /** Failed logins before a client is locked out. */
    maxAttempts: number;
    /** Lockout duration in minutes. */
    lockMinutes: number;
    /** Maximum time to exchange the harness launch token, in milliseconds. */
    exchangeTimeoutMs: number;
    /** Maximum simultaneous TCP connections from one peer; 0 disables this limit. */
    maxConnectionsPerPeer: number;
    /** Maximum login forms being received from one client IP. */
    maxPendingLoginsPerIp: number;
    /** Deadline for upstream response headers, including time queued for a socket; 0 disables. */
    upstreamHeaderTimeoutMs: number;
    /** Maximum idle time after upstream response headers; 0 disables. */
    upstreamIdleTimeoutMs: number;
    /** Optional CA certificate for a private HTTPS harness. */
    upstreamCaFile: string;
    /** Optional TLS identity when connecting to an HTTPS harness by IP. */
    upstreamServerName: string;
}
/** Defaults applied by the loader and by direct calls to apply(). */
export declare const DEFAULTS: Config;
/** Schemastery schema; the loader validates and fills defaults before apply(). */
export declare const Config: z<Config>;
