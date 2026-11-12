/**
 * The gate's HTTP surface: health, login, logout, and the authenticated proxy.
 *
 * Unauthenticated API calls get 401 JSON so the UI can react; every other path
 * is redirected to the login page. Authenticated requests are handed to the
 * proxy with an exchanged harness cookie.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { LogSink } from './context.ts';
/** Values the gate needs at request time. */
export interface GateRuntime {
    title: string;
    passwordHash: string;
    secret: string;
    pv: string;
    sessionSeconds: number;
    maxAttempts: number;
    maxPendingLoginsPerIp: number;
    lockMs: number;
    trustProxy: boolean;
    useTls: boolean;
    publicOrigin: string;
    secureCookie: boolean;
}
/** Collaborators the handler delegates to. */
export interface GateOptions {
    runtime: GateRuntime;
    harnessCookie(): Promise<string>;
    validSession(token: string): boolean;
    revokeSession(token: string): boolean;
    admit(req: IncomingMessage, res: ServerResponse, token: string): boolean;
    forward(req: IncomingMessage, res: ServerResponse, cookie: string, token: string): void;
    log: LogSink;
}
/** Build the request handler for one gate instance. */
export declare function createHandler(options: GateOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void>;
