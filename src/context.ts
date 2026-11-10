/**
 * Structural view of the harness services this plugin talks to.
 *
 * The gate only runs inside the web profile, so the web server and the
 * connection service are always present. Declaring the two interfaces here
 * keeps the plugin typed without depending on the host packages at build time.
 */

import type { Context } from '@deepseek-ai/cordis'

/** Minimal surface of the harness web server used by the gate. */
export interface WebServerView {
  /** Host the harness listener is bound to, when the host service exposes it. */
  config?: { host?: unknown }
  /** Origin the harness listener is reachable on, for example http://127.0.0.1:3080. */
  getOrigin(): string
  /** Register an index.html transform; the returned function unregisters it. */
  tapIndex(transform: (html: string) => string): () => void
}

/** Minimal surface of the harness connection service used by the gate. */
export interface ConnectionView {
  /** Absolute URL of the entry document with the launch token attached. */
  authenticatedUrl(baseUrl: string): string
}

/** Profile location reported by the harness loader. */
export interface ProfileContextView {
  /** Absolute path of the profile patch file the plugin was loaded from. */
  patchPath?: string
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    webServer: WebServerView
    connection: ConnectionView
    profileContext?: ProfileContextView
  }
}

/** Logger subset used by the gate; the console satisfies it as well. */
export interface LogSink {
  info(message: string): void
  warn(message: string): void
}

/**
 * Use the cordis logger on a real harness and fall back to the console when the
 * plugin is driven directly from tests.
 */
export function resolveLogger(ctx: Context): LogSink {
  const logger = (ctx as { logger?: Partial<LogSink> }).logger
  return typeof logger?.info === 'function' && typeof logger?.warn === 'function'
    ? (logger as LogSink)
    : console
}
