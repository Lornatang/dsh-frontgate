/**
 * Per-profile state: the password hash and the cookie signing secret.
 *
 * The file sits next to the profile's cordis.patch.yml, is created with mode
 * 0600 and holds no plain-text password.
 */
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'
import { hashPassword, verifyPasswordSync } from './auth.ts'

/** Persisted state file contents. */
export interface State {
  passwordHash?: string
  secret?: string
  createdAt?: string
}

/** Read state, treating a missing or malformed file as empty. */
export function readState(path: string): State {
  try {
    const value: unknown = JSON.parse(readFileSync(path, 'utf8'))
    return value && typeof value === 'object' ? (value as State) : {}
  } catch {
    return {}
  }
}

/** Best effort chmod; a missing file or a read-only filesystem is ignored. */
export function tightenState(path: string): void {
  try {
    chmodSync(path, 0o600)
  } catch {
    // Nothing to tighten.
  }
}

/** Write state atomically enough for one process, owner-readable only. */
export function writeState(path: string, value: State): void {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 })
  tightenState(path)
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
