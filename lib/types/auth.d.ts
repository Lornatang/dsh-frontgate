/** Name of the session cookie. */
export declare const COOKIE = "dsh_gate";
/** Version prefix of signed session tokens. */
export declare const TOKEN_VERSION = "v1";
/** Longest accepted token, in characters. */
export declare const MAX_TOKEN_LENGTH = 256;
/** Shortest accepted configured password, in characters. */
export declare const MIN_PASSWORD_LENGTH = 12;
/** Stored hash format: scrypt$N$r$p$saltHex$keyHex. */
export declare const HASH_RE: RegExp;
/** scrypt cost parameters used when a new hash is created. */
export interface ScryptParams {
    N?: number;
    r?: number;
    p?: number;
    keylen?: number;
}
/** Reject configured passwords that are too short to survive guessing. */
export declare function assertStrongPassword(password: string, source: string): string;
/** Hash a password with scrypt; parameters travel with the hash. */
export declare function hashPassword(password: string, params?: ScryptParams): string;
/** Check the complete persisted format and its bounded scrypt parameters. */
export declare function validPasswordHash(value: unknown): value is string;
/** Async verification: the event loop stays free while scrypt runs. */
export declare function verifyPassword(password: string, stored: unknown): Promise<boolean>;
/** Synchronous verification, used only to reuse the persisted salt at startup. */
export declare function verifyPasswordSync(password: string, stored: unknown): boolean;
/** Random password shown once when no password is configured. */
export declare function randomPassword(): string;
/** Stable, non-reversible tag of the password hash; embedded in every session. */
export declare const passwordVersion: (passwordHash: string) => string;
/** Create a signed session token: v1.issuedAt.expiresAt.nonce.passwordVersion.mac. */
export declare function signToken(secret: string, pv: string, ttlSeconds: number): string;
/** Verify signature, version, password binding and expiry in constant time. */
export declare function verifyToken(secret: string, pv: string, token: string | undefined): boolean;
/** Session cookie attributes; Secure follows the browser-facing protocol. */
export declare function sessionCookie(value: string, seconds: number, useTls: boolean): string;
/** Expired session cookie. */
export declare const clearCookie: (secure: boolean) => string;
