/** Keep one live gate per profile without leaving a stale lock after a crash. */
import { closeSync, mkdirSync, openSync } from 'node:fs'
import { dirname } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { tightenState } from './state.ts'

/**
 * SQLite's OS lock is released by the kernel when the process exits. The
 * database is only a lock, not a replacement for the existing JSON state.
 * Use a local filesystem with working SQLite file locking for shared profiles.
 */
export function acquireStateLock(statePath: string): () => void {
  const lockPath = statePath + '.lock.sqlite'
  mkdirSync(dirname(lockPath), { recursive: true, mode: 0o700 })
  try {
    // Do not open an existing lock file outside SQLite: on POSIX, closing a
    // separate descriptor can release this process's advisory file locks.
    const fd = openSync(lockPath, 'wx', 0o600)
    closeSync(fd)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err
  }
  tightenState(lockPath)
  const database = new DatabaseSync(lockPath)
  try {
    database.exec('PRAGMA busy_timeout = 0; BEGIN EXCLUSIVE')
  } catch (err) {
    database.close()
    throw new Error('dsh-frontgate: cannot lock profile state; another gate may be running: ' + statePath, { cause: err })
  }
  let released = false
  return () => {
    if (released) return
    released = true
    database.close()
  }
}
