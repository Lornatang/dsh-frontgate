/** Persisted state file contents. */
export interface State {
    passwordHash?: string;
    secret?: string;
    createdAt?: string;
}
/** Read existing state without replacing malformed or inaccessible credentials. */
export declare function readState(path: string, mustExist?: boolean): State;
/** Fail closed when a state file is a symlink or cannot be made owner-only. */
export declare function tightenState(path: string): boolean;
/** Write a complete owner-only temporary file, then replace the old state. */
export declare function writeState(path: string, value: State): void;
/** Resolve the state path for the profile the plugin was loaded from. */
export declare function statePathFor(patchPath: string | undefined): string;
/** Reuse the persisted salt while the same password keeps being configured. */
export declare function hashFor(plain: string, state: State): string;
