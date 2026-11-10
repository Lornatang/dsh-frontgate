import type { AddressInfo } from 'node:net';
import type { Context } from '@deepseek-ai/cordis';
import { Config } from './config.ts';
/** Cordis metadata: the plugin id shown in logs and the services it waits for. */
export declare const name = "dsh-frontgate";
export declare const inject: string[];
/** Handle returned to tests and embedders; the loader ignores it. */
export interface GateHandle {
    /** Resolves once the gate is listening. */
    ready(): Promise<void>;
    /** Bound address of the gate listener. */
    address(): AddressInfo | string | null;
    /** Stop the listener and drop pooled upstream sockets. */
    stop(): void;
}
/**
 * Start the gate.
 *
 * The loader validates the configuration against Config before calling this;
 * defaults are applied again here so direct calls behave the same way.
 */
export declare function apply(ctx: Context, config?: Partial<Config>): GateHandle;
export { Config } from './config.ts';
export { hashPassword, verifyPassword } from './auth.ts';
export { injectPolyfill } from './polyfill.ts';
