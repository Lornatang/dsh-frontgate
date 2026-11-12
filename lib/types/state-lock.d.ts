/**
 * SQLite's OS lock is released by the kernel when the process exits. The
 * database is only a lock, not a replacement for the existing JSON state.
 * Use a local filesystem with working SQLite file locking for shared profiles.
 */
export declare function acquireStateLock(statePath: string): () => void;
