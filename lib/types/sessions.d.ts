import type { State } from './state.ts';
/** Store only a digest, never the bearer token itself. */
export declare const sessionDigest: (token: string) => string;
export interface SessionStore {
    valid(token: string): boolean;
    /** Persist revocation before reporting logout success. */
    revoke(token: string): boolean;
}
export declare function createSessionStore(path: string, state: State, pv: string, onRevoke: (digest: string) => void): SessionStore;
