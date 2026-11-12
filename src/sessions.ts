/** Persistent, bounded revocation for signed session cookies. */
import { createHash } from 'node:crypto'
import { verifyToken } from './auth.ts'
import { MAX_REVOKED_SESSIONS, readState, tightenState, writeState } from './state.ts'
import type { State } from './state.ts'

/** Store only a digest, never the bearer token itself. */
export const sessionDigest = (token: string): string => createHash('sha256').update(token).digest('base64url')

export interface SessionStore {
  valid(token: string): boolean
  /** Persist revocation before reporting logout success. */
  revoke(token: string): boolean
}

export function createSessionStore(path: string, state: State, pv: string, onRevoke: (digest: string) => void): SessionStore {
  const secret = state.secret!
  const passwordHash = state.passwordHash!
  let revoked = new Map((state.revokedSessions ?? []).map(({ digest, expires }) => [digest, expires]))

  const valid = (token: string): boolean => {
    if (!verifyToken(secret, pv, token)) return false
    const digest = sessionDigest(token)
    const expires = revoked.get(digest)
    if (expires === undefined) return true
    if (expires * 1000 > Date.now()) return false
    revoked.delete(digest)
    return true
  }

  const revoke = (token: string): boolean => {
    if (!valid(token)) return false
    // Reload so a stale instance cannot overwrite a newer password or secret.
    if (!tightenState(path)) throw new Error('state file is missing')
    const latest = readState(path, true)
    if (latest.secret !== secret || latest.passwordHash !== passwordHash) {
      throw new Error('state changed; restart the gate before signing out')
    }
    const now = Math.floor(Date.now() / 1000)
    const next = new Map<string, number>()
    for (const entry of latest.revokedSessions ?? []) if (entry.expires > now) next.set(entry.digest, entry.expires)
    for (const [digest, expires] of revoked) if (expires > now) next.set(digest, expires)
    const digest = sessionDigest(token)
    if (next.size > MAX_REVOKED_SESSIONS || (!next.has(digest) && next.size >= MAX_REVOKED_SESSIONS)) {
      throw new Error('revocation store is full')
    }
    next.set(digest, Number(token.split('.')[2]))
    writeState(path, { ...latest, revokedSessions: [...next].map(([digest, expires]) => ({ digest, expires })) })
    revoked = next
    onRevoke(digest)
    return true
  }

  return { valid, revoke }
}
