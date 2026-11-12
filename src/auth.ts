/**
 * Passwords, session tokens and the cookie that carries them.
 *
 * Sessions are stateless HMAC tokens bound to the current password hash, so a
 * password change invalidates every session without a session table.
 */
import { createHash, createHmac, randomBytes, scrypt, scryptSync, timingSafeEqual } from 'node:crypto'

/** Name of the session cookie. */
export const COOKIE = 'dsh_gate'
/** Version prefix of signed session tokens. */
export const TOKEN_VERSION = 'v1'
/** Longest accepted token, in characters. */
export const MAX_TOKEN_LENGTH = 256
/** Shortest accepted configured password, in characters. */
export const MIN_PASSWORD_LENGTH = 12

const SCRYPT = Object.freeze({ N: 32768, r: 8, p: 1, keylen: 32 })
const PASSWORD_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'

/** Stored hash format: scrypt$N$r$p$saltHex$keyHex. */
export const HASH_RE = /^scrypt\$\d+\$\d+\$\d+\$[0-9a-f]{32,64}\$[0-9a-f]{32,128}$/

/** scrypt cost parameters used when a new hash is created. */
export interface ScryptParams {
  N?: number
  r?: number
  p?: number
  keylen?: number
}

const scryptMaxmem = (N: number, r: number): number => Math.max(64 * 1024 * 1024, 256 * N * r)

/** Reject configured passwords that are too short to survive guessing. */
export function assertStrongPassword(password: string, source: string): string {
  const length = [...String(password)].length
  if (length < MIN_PASSWORD_LENGTH) {
    throw new Error(
      'dsh-frontgate: ' + source + ' must be at least ' + MIN_PASSWORD_LENGTH +
        ' characters; got ' + length,
    )
  }
  return String(password)
}

/** Hash a password with scrypt; parameters travel with the hash. */
export function hashPassword(password: string, params: ScryptParams = {}): string {
  const { N = SCRYPT.N, r = SCRYPT.r, p = SCRYPT.p, keylen = SCRYPT.keylen } = params
  const salt = randomBytes(16)
  const key = scryptSync(String(password), salt, keylen, { N, r, p, maxmem: scryptMaxmem(N, r) })
  return 'scrypt$' + N + '$' + r + '$' + p + '$' + salt.toString('hex') + '$' + key.toString('hex')
}

function scryptAsync(password: string, salt: Buffer, keylen: number, params: { N: number; r: number; p: number }): Promise<Buffer | undefined> {
  return new Promise((resolve) => {
    scrypt(password, salt, keylen, { ...params, maxmem: scryptMaxmem(params.N, params.r) }, (err, key) =>
      resolve(err ? undefined : key),
    )
  })
}

/** Parse the stored hash into scrypt parameters, or return undefined. */
function parseStored(stored: unknown): { N: number; r: number; p: number; salt: Buffer; want: Buffer } | undefined {
  if (typeof stored !== 'string') return undefined
  const parts = stored.split('$')
  if (parts.length !== 6 || parts[0] !== 'scrypt') return undefined
  const N = Number(parts[1])
  const r = Number(parts[2])
  const p = Number(parts[3])
  if (!Number.isInteger(N) || N < 1024 || N > 1048576 || (N & (N - 1)) !== 0) return undefined
  if (!Number.isInteger(r) || r < 1 || r > 32) return undefined
  if (!Number.isInteger(p) || p < 1 || p > 4) return undefined
  let salt: Buffer
  let want: Buffer
  try {
    salt = Buffer.from(parts[4]!, 'hex')
    want = Buffer.from(parts[5]!, 'hex')
  } catch {
    return undefined
  }
  if (salt.length < 8 || salt.length > 32 || want.length < 16 || want.length > 64) return undefined
  return { N, r, p, salt, want }
}

/** Check the complete persisted format and its bounded scrypt parameters. */
export function validPasswordHash(value: unknown): value is string {
  return typeof value === 'string' && HASH_RE.test(value) && parseStored(value) !== undefined
}

/** Async verification: the event loop stays free while scrypt runs. */
export async function verifyPassword(password: string, stored: unknown): Promise<boolean> {
  const parsed = parseStored(stored)
  if (!parsed) return false
  const { N, r, p, salt, want } = parsed
  const got = await scryptAsync(String(password), salt, want.length, { N, r, p })
  return got !== undefined && got.length === want.length && timingSafeEqual(got, want)
}

/** Synchronous verification, used only to reuse the persisted salt at startup. */
export function verifyPasswordSync(password: string, stored: unknown): boolean {
  const parsed = parseStored(stored)
  if (!parsed) return false
  const { N, r, p, salt, want } = parsed
  try {
    const got = scryptSync(String(password), salt, want.length, { N, r, p, maxmem: scryptMaxmem(N, r) })
    return got.length === want.length && timingSafeEqual(got, want)
  } catch {
    return false
  }
}

/** Random password shown once when no password is configured. */
export function randomPassword(): string {
  const bytes = randomBytes(16)
  let out = ''
  for (let i = 0; i < 16; i++) out += PASSWORD_ALPHABET[bytes[i]! & 31]
  return out.slice(0, 4) + '-' + out.slice(4, 8) + '-' + out.slice(8, 12) + '-' + out.slice(12, 16)
}

/** Stable, non-reversible tag of the password hash; embedded in every session. */
export const passwordVersion = (passwordHash: string): string =>
  createHash('sha256').update(passwordHash).digest('base64url').slice(0, 12)

/** Create a signed session token: v1.issuedAt.expiresAt.nonce.passwordVersion.mac. */
export function signToken(secret: string, pv: string, ttlSeconds: number): string {
  const now = Math.floor(Date.now() / 1000)
  const body =
    TOKEN_VERSION + '.' + now + '.' + (now + ttlSeconds) + '.' + randomBytes(16).toString('base64url') + '.' + pv
  return body + '.' + createHmac('sha256', secret).update(body).digest('base64url')
}

/** Verify signature, version, password binding and expiry in constant time. */
export function verifyToken(secret: string, pv: string, token: string | undefined): boolean {
  if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) return false
  const parts = token.split('.')
  if (parts.length !== 6) return false
  const [version, iat, exp, nonce, tokenPv, mac] = parts
  if (version !== TOKEN_VERSION || tokenPv !== pv) return false
  const now = Math.floor(Date.now() / 1000)
  const issued = Number(iat)
  const expires = Number(exp)
  if (!Number.isSafeInteger(issued) || !Number.isSafeInteger(expires)) return false
  if (expires <= now || issued > now + 300) return false
  const body = version + '.' + iat + '.' + exp + '.' + nonce + '.' + tokenPv
  const want = createHmac('sha256', secret).update(body).digest()
  let got: Buffer
  try {
    got = Buffer.from(mac!, 'base64url')
  } catch {
    return false
  }
  return got.length === want.length && timingSafeEqual(got, want)
}

/** Session cookie attributes; Secure follows the browser-facing protocol. */
export function sessionCookie(value: string, seconds: number, useTls: boolean): string {
  const attrs = [COOKIE + '=' + value, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=' + seconds]
  if (useTls) attrs.push('Secure')
  return attrs.join('; ')
}

/** Expired session cookie. */
export const clearCookie = (secure: boolean): string => sessionCookie('', 0, secure)
