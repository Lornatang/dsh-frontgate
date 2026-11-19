/** Persistent, bounded revocation for signed session cookies. */
import { createHash } from 'node:crypto'
import { verifyToken } from './auth.ts'
import { MAX_REVOKED_SESSIONS, appendRevocation, compactRevocations, mergeRevocation, readState, revocationRecords, tightenState } from './state.ts'
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
    const now = Math.floor(Date.now() / 1000)
    const latest = readState(path, true, now)
    if (latest.secret !== secret || latest.passwordHash !== passwordHash || latest.sessionEpoch !== pv) {
      throw new Error('state changed; restart the gate before signing out')
    }
    const next = new Map((latest.revokedSessions ?? []).map(({ digest, expires }) => [digest, expires]))
    for (const [digest, expires] of revoked) mergeRevocation(next, { digest, expires }, now)
    const digest = sessionDigest(token)
    if (!next.has(digest) && next.size >= MAX_REVOKED_SESSIONS) {
      throw new Error('revocation store is full')
    }
    const expires = Number(token.split('.')[2])
    if (expires <= now) return false
    const entry = { digest, expires }
    if (!appendRevocation(path, entry)) {
      // Finish maintenance before committing a new revocation. If compaction
      // fails, the journal cannot grow further and the logout can be retried.
      compactRevocations(path, latest, revocationRecords(next))
      if (!appendRevocation(path, entry)) throw new Error('revocation journal is full after compaction')
    }
    // The fsynced append commits logout. Apply it to live requests immediately.
    mergeRevocation(next, entry, now)
    revoked = next
    onRevoke(digest)
    return true
  }

  return { valid, revoke }
}
