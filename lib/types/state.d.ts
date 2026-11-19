/** Bound live, distinct logout revocations across the state and journal. */
export declare const MAX_REVOKED_SESSIONS = 10000;
export interface RevokedSession {
    digest: string;
    expires: number;
}
/** Persisted state file contents. */
export interface State {
    passwordHash?: string;
    secret?: string;
    /** Random tag bound into signed sessions; changes with the password. */
    sessionEpoch?: string;
    createdAt?: string;
    revokedSessions?: RevokedSession[];
}
/** Maximum size of the append-only revocation journal next to the state file. */
export declare const MAX_REVOCATION_JOURNAL_BYTES: number;
/** Validate every record and keep the longest live expiry for each digest. */
export declare function mergeRevocation(entries: Map<string, number>, entry: unknown, now: number): void;
export declare function revocationRecords(entries: ReadonlyMap<string, number>): RevokedSession[];
/** Read existing state without replacing malformed or inaccessible credentials. */
export declare function readState(path: string, mustExist?: boolean, now?: number): State;
/** Fail closed when a state file is a symlink or cannot be made owner-only. */
export declare function tightenState(path: string): boolean;
/** Write a complete owner-only temporary file, then replace the old state. */
export declare function writeState(path: string, value: State): void;
/**
 * Append and sync one revocation record, or return false if compaction must
 * free space before this record can be appended.
 *
 * Appending and fsyncing the journal is much cheaper than rewriting the whole
 * state file (which can hold thousands of revocations) on every logout, while
 * still being durable before logout success is reported. The journal is merged
 * into the state on read and compacted back into it when it grows large.
 */
export declare function appendRevocation(path: string, entry: RevokedSession): boolean;
/** Remove the journal once its records are durable in the state file. */
export declare function clearRevocationJournal(path: string): void;
/** Fold journal records into the state file, then drop the journal. */
export declare function compactRevocations(path: string, base: State, entries: RevokedSession[]): void;
/** Resolve the state path for the profile the plugin was loaded from. */
export declare function statePathFor(patchPath: string | undefined): string;
/** Reuse the persisted salt while the same password keeps being configured. */
export declare function hashFor(plain: string, state: State): string;
