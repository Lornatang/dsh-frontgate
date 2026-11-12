import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import type { LogSink } from './context.ts';
/** Options needed to reach and describe the harness listener. */
export interface ProxyOptions {
    /** Origin of the harness listener, for example http://127.0.0.1:3080. */
    targetOrigin: string;
    /** Protocol the gate serves to browsers. */
    publicProto: 'http' | 'https';
    /** Honour forwarded headers from a proxy in front of the gate. */
    trustProxy: boolean;
    /** Maximum time spent exchanging a launch token, including connection time. */
    exchangeTimeoutMs: number;
    upstreamHeaderTimeoutMs: number;
    upstreamIdleTimeoutMs: number;
    websocketHandshakeTimeoutMs: number;
    upstreamCa?: Buffer;
    upstreamServerName: string;
    /** Absolute entry URL with the harness launch token attached. */
    authenticatedUrl(baseUrl: string): string;
    log: LogSink;
}
/** Proxy surface used by the request and upgrade handlers. */
export interface Proxy {
    harnessCookie(): Promise<string>;
    forward(req: IncomingMessage, res: ServerResponse, cookie: string): void;
    forwardUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, cookie: string): void;
    destroy(): void;
}
/** Build the proxy for one harness origin. */
export declare function createProxy(options: ProxyOptions): Proxy;
