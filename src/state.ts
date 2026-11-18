/**
 * Per-profile state: the password hash and the cookie signing secret.
 *
 * The file sits next to the profile's cordis.patch.yml, is created with mode
 * 0600 and holds no plain-text password.
 */
import { chmodSync, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'
import { hashPassword, validPasswordHash, verifyPasswordSync } from './auth.ts'

/** Bound persistent logout revocations; expired entries are pruned on logout. */
export const MAX_REVOKED_SESSIONS = 10000

export interface RevokedSession {
  digest: string
  expires: number
}

/** Persisted state file contents. */
export interface State {
  passwordHash?: string
  secret?: string
  /** Random tag bound into signed sessions; changes with the password. */
  sessionEpoch?: string
  createdAt?: string
  revokedSessions?: RevokedSession[]
}

/** Append-only revocation journal next to the state file. */
export const MAX_REVOCATION_JOURNAL_BYTES = 256 * 1024

function revocationPath(path: string): string {
  return path + '.revocations'
}

function validRevokedSession(value: unknown): value is RevokedSession {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) &&
    typeof (value as RevokedSession).digest === 'string' && /^[A-Za-z0-9_-]{43}$/.test((value as RevokedSession).digest) &&
    Number.isSafeInteger((value as RevokedSession).expires) && (value as RevokedSession).expires > 0
}

/** Read existing state without replacing malformed or inaccessible credentials. */
export function readState(path: string, mustExist = false): State {
  let data: string
  try {
    data = readFileSync(path, 'utf8')
  } catch (err) {
    if (!mustExist && (err as NodeJS.ErrnoException).code === 'ENOENT') return {}
    throw new Error('dsh-frontgate: cannot read state file ' + path, { cause: err })
  }
  try {
    const value: unknown = JSON.parse(data)
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid state')
    const state = value as State
    if (!validPasswordHash(state.passwordHash) || typeof state.secret !== 'string' || state.secret.length < 64) {
      throw new Error('invalid credentials')
    }
    if (state.sessionEpoch !== undefined &&
        (typeof state.sessionEpoch !== 'string' || !/^[A-Za-z0-9_-]{16,43}$/.test(state.sessionEpoch))) {
      throw new Error('invalid session epoch')
    }
    if (state.revokedSessions !== undefined &&
        (!Array.isArray(state.revokedSessions) || state.revokedSessions.length > MAX_REVOKED_SESSIONS ||
         state.revokedSessions.some((entry) => !validRevokedSession(entry)))) {
      throw new Error('invalid revoked sessions')
    }
    let journal: string
    try {
      journal = readFileSync(revocationPath(path), 'utf8')
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return state
      throw new Error('dsh-frontgate: cannot read revocation journal for ' + path, { cause: err })
    }
    const merged = [...(state.revokedSessions ?? [])]
    for (const line of journal.split('\n')) {
      if (!line) continue
      let entry: unknown
      try { entry = JSON.parse(line) } catch { throw new Error('invalid revocation journal') }
      if (!validRevokedSession(entry)) throw new Error('invalid revocation journal')
      merged.push(entry)
    }
    if (merged.length > MAX_REVOKED_SESSIONS) throw new Error('invalid revocation journal')
    state.revokedSessions = merged
    return state
  } catch (err) {
    throw new Error('dsh-frontgate: invalid state file ' + path + '; restore it from a backup before restarting', { cause: err })
  }
}

/** Fail closed when a state file is a symlink or cannot be made owner-only. */
export function tightenState(path: string): boolean {
  let info
  try {
    info = lstatSync(path)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw new Error('dsh-frontgate: cannot inspect state file ' + path, { cause: err })
  }
  if (!info.isFile()) throw new Error('dsh-frontgate: state file must be a regular file: ' + path)
  // Windows does not expose POSIX permissions through chmod; its ACLs must be
  // managed by the operator. On POSIX, verify even if chmod itself fails.
  if (process.platform === 'win32') return true
  if (typeof process.geteuid === 'function' && info.uid !== process.geteuid()) {
    throw new Error('dsh-frontgate: state file must be owned by the service user: ' + path)
  }
  try {
    chmodSync(path, 0o600)
  } catch (err) {
    if ((info.mode & 0o077) !== 0) {
      throw new Error('dsh-frontgate: cannot secure state file permissions for ' + path, { cause: err })
    }
  }
  try {
    info = lstatSync(path)
  } catch (err) {
    throw new Error('dsh-frontgate: cannot inspect state file ' + path, { cause: err })
  }
  if (!info.isFile() || (info.mode & 0o077) !== 0 ||
      (typeof process.geteuid === 'function' && info.uid !== process.geteuid())) {
    throw new Error('dsh-frontgate: state file must be owner-only: ' + path)
  }
  return true
}

/** Bounded synchronous pause used by the Windows rename retry. */
function pause(ms: number): void {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
  } catch {
    const until = Date.now() + ms
    while (Date.now() < until) { /* busy wait */ }
  }
}

/**
 * Replace one state file. Windows virus scanners, indexers and backup tools
 * can hold a handle on the destination for a few milliseconds; a single
 * rename would then fail with EPERM/EACCES/EBUSY and leave the session
 * unrevokeable (logout answers 503).
 */
function renameStateFile(from: string, to: string): void {
  for (let attempt = 0; ; attempt += 1) {
    try {
      renameSync(from, to)
      return
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code
      if (process.platform !== 'win32' || attempt >= 4 || !['EPERM', 'EACCES', 'EBUSY'].includes(code ?? '')) throw err
      pause(20)
    }
  }
}

/** Make the rename durable by syncing the parent directory (POSIX only). */
function syncParent(path: string): void {
  if (process.platform === 'win32') return
  let fd: number | undefined
  try {
    fd = openSync(dirname(path), 'r')
    fsyncSync(fd)
  } catch {
    // Best effort: some filesystems refuse directory fsync.
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd) } catch { /* ignore */ }
    }
  }
}

/** Write a complete owner-only temporary file, then replace the old state. */
export function writeState(path: string, value: State): void {
  mkdirSync(dirname(path), { recursive: true })
  const temporary = path + '.' + randomBytes(12).toString('hex') + '.tmp'
  let fd: number | undefined
  let failure: unknown
  try {
    fd = openSync(temporary, 'wx', 0o600)
    writeFileSync(fd, JSON.stringify(value, null, 2) + '\n')
    fsyncSync(fd)
    closeSync(fd)
    fd = undefined
    renameStateFile(temporary, path)
    syncParent(path)
  } catch (err) {
    failure = err
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd) } catch (err) {
        if (failure === undefined) failure = err
      }
    }
    try {
      unlinkSync(temporary)
    } catch (err) {
      // Never let cleanup mask the real write failure.
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT' && failure === undefined) failure = err
    }
  }
  if (failure !== undefined) throw failure
}

/**
 * Append one revocation record and return the journal size in bytes.
 *
 * Appending and fsyncing the journal is much cheaper than rewriting the whole
 * state file (which can hold thousands of revocations) on every logout, while
 * still being durable before logout success is reported. The journal is merged
 * into the state on read and compacted back into it when it grows large.
 */
export function appendRevocation(path: string, entry: RevokedSession): number {
  const journal = revocationPath(path)
  const existed = tightenState(journal)
  const fd = openSync(journal, 'a', 0o600)
  try {
    writeFileSync(fd, JSON.stringify(entry) + '\n')
    fsyncSync(fd)
    if (!existed) syncParent(journal)
    return fstatSync(fd).size
  } finally {
    closeSync(fd)
  }
}

/** Remove the journal once its records are durable in the state file. */
export function clearRevocationJournal(path: string): void {
  const journal = revocationPath(path)
  try {
    unlinkSync(journal)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return
    throw new Error('dsh-frontgate: cannot remove revocation journal for ' + path, { cause: err })
  }
  syncParent(journal)
}

/** Fold journal records into the state file, then drop the journal. */
export function compactRevocations(path: string, base: State, entries: RevokedSession[]): void {
  writeState(path, { ...base, revokedSessions: entries })
  clearRevocationJournal(path)
}

/** Resolve the state path for the profile the plugin was loaded from. */
export function statePathFor(patchPath: string | undefined): string {
  const file =
    patchPath ?? join(process.env.DSH_HOME || join(homedir(), '.dsh'), 'profiles', 'web', 'cordis.patch.yml')
  return join(dirname(file), 'data', 'dsh-frontgate.json')
}

/** Reuse the persisted salt while the same password keeps being configured. */
export function hashFor(plain: string, state: State): string {
  return state.passwordHash && verifyPasswordSync(plain, state.passwordHash) ? state.passwordHash : hashPassword(plain)
}
