/**
 * Per-profile state: the password hash and the cookie signing secret.
 *
 * The file sits next to the profile's cordis.patch.yml, is created with mode
 * 0600 and holds no plain-text password.
 */
import { chmodSync, closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'
import { hashPassword, validPasswordHash, verifyPasswordSync } from './auth.ts'

/** Persisted state file contents. */
export interface State {
  passwordHash?: string
  secret?: string
  createdAt?: string
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

/** Write a complete owner-only temporary file, then replace the old state. */
export function writeState(path: string, value: State): void {
  mkdirSync(dirname(path), { recursive: true })
  const temporary = path + '.' + randomBytes(12).toString('hex') + '.tmp'
  let fd: number | undefined
  try {
    fd = openSync(temporary, 'wx', 0o600)
    writeFileSync(fd, JSON.stringify(value, null, 2) + '\n')
    fsyncSync(fd)
    closeSync(fd)
    fd = undefined
    renameSync(temporary, path)
  } finally {
    if (fd !== undefined) closeSync(fd)
    try { unlinkSync(temporary) } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err
    }
  }
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
