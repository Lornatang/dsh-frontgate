/** Persisted state file contents. */
export interface State {
    passwordHash?: string;
    secret?: string;
    createdAt?: string;
}
/** Read state, treating a missing or malformed file as empty. */
export declare function readState(path: string): State;
/** Write state atomically enough for one process, owner-readable only. */
export declare function writeState(path: string, value: State): void;
/** Resolve the state path for the profile the plugin was loaded from. */
export declare function statePathFor(patchPath: string | undefined): string;
/** Reuse the persisted salt while the same password keeps being configured. */
export declare function hashFor(plain: string, state: State): string;
