import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
/** Largest accepted login form body. */
export declare const MAX_FORM: number;
/** Longest time a login body may take to arrive. */
export declare const FORM_TIMEOUT: number;
/** Parse an integer option and clamp it into range. */
export declare const intOr: (value: unknown, fallback: number, min: number, max: number) => number;
/** Read one cookie value from a Cookie header. */
export declare function cookieValue(header: string | string[] | undefined, name: string): string;
/** Client address used for lockout accounting. */
export declare function clientIp(req: IncomingMessage, trustProxy: boolean): string;
/** Normalize an explicitly configured, browser-facing HTTP(S) origin. */
export declare function normalizePublicOrigin(value: string): string;
/** The configured public authority must match the Host preserved by a proxy. */
export declare const hostMatchesPublicOrigin: (req: IncomingMessage, publicOrigin: string, useTls: boolean) => boolean;
/** Require a valid Host, and if present an Origin with identical scheme, host and port. */
export declare function originMatchesHost(req: IncomingMessage, publicOrigin: string, useTls: boolean): boolean;
/** Login check: Origin and Fetch-Site must both look same-origin. */
export declare function sameOrigin(req: IncomingMessage, publicOrigin: string, useTls: boolean): boolean;
/** Only same-site absolute paths; rejects //evil and backslash tricks. */
export declare function safeNext(value: unknown): string;
export declare const escapeHtml: (text: unknown) => string;
/** Lock the login page and gate responses down to their own origin. */
export declare const CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
/** Headers attached to every response the gate writes itself. */
export declare const GATE_HEADERS: OutgoingHttpHeaders;
/** Keep cross-origin referrers private without suppressing the login form's Origin. */
export declare const LOGIN_REFERRER_POLICY = "same-origin";
/** Write a complete response. */
export declare function send(res: ServerResponse, status: number, headers: OutgoingHttpHeaders, body: string | Buffer): void;
export declare const html: (res: ServerResponse, status: number, body: string) => void;
export declare const json: (res: ServerResponse, status: number, payload: unknown) => void;
export declare const text: (res: ServerResponse, status: number, body: string, extra?: OutgoingHttpHeaders) => void;
export declare const redirect: (res: ServerResponse, location: string, status?: number) => void;
/** Flush a rejected upgrade, then close even if the peer keeps its write side open. */
export declare function rejectUpgrade(socket: Duplex, status: number): void;
/** Read a bounded, form-encoded login body; never trust content-length alone. */
export declare function readForm(req: IncomingMessage): Promise<string>;
export declare const isLoopbackHost: (host: string) => boolean;
/** Address form accepted by net.connect / tls.connect. */
export declare const connectHost: (hostname: string) => string;
