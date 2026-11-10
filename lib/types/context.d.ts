/**
 * Structural view of the harness services this plugin talks to.
 *
 * The gate only runs inside the web profile, so the web server and the
 * connection service are always present. Declaring the two interfaces here
 * keeps the plugin typed without depending on the host packages at build time.
 */
import type { Context } from '@deepseek-ai/cordis';
/** Minimal surface of the harness web server used by the gate. */
export interface WebServerView {
    /** Host the harness listener is bound to, when the host service exposes it. */
    config?: {
        host?: unknown;
    };
    /** Origin the harness listener is reachable on, for example http://127.0.0.1:3080. */
    getOrigin(): string;
    /** Register an index.html transform; the returned function unregisters it. */
    tapIndex(transform: (html: string) => string): () => void;
}
/** Minimal surface of the harness connection service used by the gate. */
export interface ConnectionView {
    /** Absolute URL of the entry document with the launch token attached. */
    authenticatedUrl(baseUrl: string): string;
}
/** Profile location reported by the harness loader. */
export interface ProfileContextView {
    /** Absolute path of the profile patch file the plugin was loaded from. */
    patchPath?: string;
}
declare module '@deepseek-ai/cordis' {
    interface Context {
        webServer: WebServerView;
        connection: ConnectionView;
        profileContext?: ProfileContextView;
    }
}
/** Logger subset used by the gate; lines are written to stderr. */
export interface LogSink {
    info(message: string): void;
    warn(message: string): void;
}
/**
 * Report startup lines on stderr, which is the only channel a headless web
 * profile leaves visible: the harness routes ctx.logger to its own exporters,
 * and the web profile installs none of them, so a generated password or a
 * listen address logged there would never reach the operator.
 */
export declare function resolveLogger(ctx: Context): LogSink;
