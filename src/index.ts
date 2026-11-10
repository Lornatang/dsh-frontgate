/**
 * dsh-frontgate - password gate and reverse proxy for the DeepSeek Harness Web UI.
 *
 * One password, one signed session cookie, one extra port. The plugin rewrites
 * Host and Origin so the harness accepts proxied requests, exchanges the launch
 * cookie on the server so the browser never sees it, and passes WebSocket
 * upgrades through untouched.
 */
import http from 'node:http'
import https from 'node:https'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import type { Duplex } from 'node:stream'
import type { Context } from '@deepseek-ai/cordis'
import { Config, DEFAULTS } from './config.ts'
import { COOKIE, HASH_RE, assertStrongPassword, hashPassword, passwordVersion, randomPassword, verifyToken } from './auth.ts'
import { resolveLogger } from './context.ts'
import { clientIp, cookieValue, intOr, isLoopbackHost, originMatchesHost, text } from './http.ts'
import { injectPolyfill } from './polyfill.ts'
import { createProxy } from './proxy.ts'
import { createHandler } from './gate.ts'
import { hashFor, readState, statePathFor, tightenState, writeState } from './state.ts'

/** Cordis metadata: the plugin id shown in logs and the services it waits for. */
export const name = 'dsh-frontgate'
export const inject = ['webServer', 'connection']

/** Handle returned to tests and embedders; the loader ignores it. */
export interface GateHandle {
  /** Resolves once the gate is listening. */
  ready(): Promise<void>
  /** Bound address of the gate listener. */
  address(): AddressInfo | string | null
  /** Stop the listener and drop pooled upstream sockets. */
  stop(): void
}

/**
 * Start the gate.
 *
 * The loader validates the configuration against Config before calling this;
 * defaults are applied again here so direct calls behave the same way.
 */
export function apply(ctx: Context, config: Partial<Config> = {}): GateHandle {
  const logger = resolveLogger(ctx)
  const cfg: Config = { ...DEFAULTS, ...config }
  const listenHost = String(cfg.listenHost)
  const listenPort = intOr(cfg.listenPort, DEFAULTS.listenPort, 0, 65535)
  const sessionSeconds = intOr(cfg.sessionDays, DEFAULTS.sessionDays, 1, 365) * 86400
  const maxAttempts = intOr(cfg.maxAttempts, DEFAULTS.maxAttempts, 1, 50)
  const lockMs = intOr(cfg.lockMinutes, DEFAULTS.lockMinutes, 1, 1440) * 60000

  // Per-profile state: password hash + cookie signing secret, 0600.
  const statePath = statePathFor(ctx.profileContext?.patchPath)
  const state = readState(statePath)
  tightenState(statePath)

  // Password precedence: config hash, config password, env hash, env password,
  // state file, then a generated password shown once.
  const configuredPassword = typeof cfg.password === 'string' ? cfg.password : ''
  const envPassword = typeof process.env.DSH_FRONTGATE_PASSWORD === 'string' ? process.env.DSH_FRONTGATE_PASSWORD : ''
  const envPasswordHash =
    typeof process.env.DSH_FRONTGATE_PASSWORD_HASH === 'string' && HASH_RE.test(process.env.DSH_FRONTGATE_PASSWORD_HASH)
      ? process.env.DSH_FRONTGATE_PASSWORD_HASH
      : ''
  let passwordHash = ''
  if (typeof cfg.passwordHash === 'string' && cfg.passwordHash) passwordHash = cfg.passwordHash
  else if (configuredPassword) passwordHash = hashFor(assertStrongPassword(configuredPassword, 'the "password" option'), state)
  else if (envPasswordHash) passwordHash = envPasswordHash
  else if (envPassword) passwordHash = hashFor(assertStrongPassword(envPassword, 'DSH_FRONTGATE_PASSWORD'), state)
  else if (typeof state.passwordHash === 'string' && HASH_RE.test(state.passwordHash)) passwordHash = state.passwordHash
  if (!passwordHash) {
    const generated = randomPassword()
    passwordHash = hashPassword(generated)
    logger.info('no password configured - generated a random one and saved its hash to ' + statePath)
    logger.info('PASSWORD: ' + generated)
  }

  const secret = typeof state.secret === 'string' && state.secret.length >= 64 ? state.secret : randomBytes(32).toString('hex')
  const pv = passwordVersion(passwordHash)
  if (state.passwordHash !== passwordHash || state.secret !== secret) {
    writeState(statePath, { passwordHash, secret, createdAt: state.createdAt || new Date().toISOString() })
  }

  const targetOrigin = ctx.webServer.getOrigin()
  const target = new URL(targetOrigin)
  if (listenPort !== 0 && listenPort === Number(target.port)) {
    throw new Error('dsh-frontgate: listenPort ' + listenPort + ' collides with the harness listener ' + targetOrigin)
  }

  const useTls = Boolean(cfg.tlsCertFile || cfg.tlsKeyFile)
  if (useTls && !(cfg.tlsCertFile && cfg.tlsKeyFile)) {
    throw new Error('dsh-frontgate: tlsCertFile and tlsKeyFile must be set together')
  }
  const publicProto = useTls ? 'https' : 'http'
  const tlsOptions = useTls
    ? { cert: readFileSync(String(cfg.tlsCertFile)), key: readFileSync(String(cfg.tlsKeyFile)) }
    : undefined

  const proxy = createProxy({
    targetOrigin,
    publicProto,
    trustProxy: Boolean(cfg.trustProxy),
    authenticatedUrl: (baseUrl) => ctx.connection.authenticatedUrl(baseUrl),
    log: logger,
  })

  const handler = createHandler({
    runtime: {
      title: cfg.title,
      passwordHash,
      secret,
      pv,
      sessionSeconds,
      maxAttempts,
      lockMs,
      trustProxy: Boolean(cfg.trustProxy),
      useTls,
    },
    harnessCookie: proxy.harnessCookie,
    forward: proxy.forward,
    log: logger,
  })

  const requestListener = (req: IncomingMessage, res: ServerResponse): void => {
    if (useTls) res.setHeader('strict-transport-security', 'max-age=31536000')
    handler(req, res).catch((err: unknown) => {
      logger.warn('handler error: ' + (err instanceof Error && err.stack ? err.stack : String(err)))
      if (!res.headersSent) text(res, 500, 'dsh-frontgate: internal error\n')
      else res.destroy()
    })
  }

  // Bound slow and idle clients: partial headers, half-sent requests and open
  // sockets all get a finite budget. connectionsCheckingInterval keeps the
  // deadlines from slipping a whole check period.
  const serverOptions = { connectionsCheckingInterval: 5000, headersTimeout: 10000, requestTimeout: 30000 }
  const server = tlsOptions
    ? https.createServer({ ...tlsOptions, ...serverOptions }, requestListener)
    : http.createServer(serverOptions, requestListener)
  server.maxConnections = 1024

  server.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    socket.on('error', () => socket.destroy())
    try {
      if (!sessionOf(req)) {
        socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
        return
      }
      if (!originMatchesHost(req)) {
        logger.warn('websocket blocked: cross-origin upgrade from ' + String(req.headers.origin || ''))
        socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
        return
      }
      proxy.harnessCookie()
        .then((cookie) => proxy.forwardUpgrade(req, socket, head, cookie))
        .catch((err: Error) => {
          logger.warn('websocket blocked: ' + err.message)
          socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n')
        })
    } catch (err) {
      logger.warn('upgrade error: ' + (err as Error).message)
      socket.destroy()
    }
  })
  server.on('clientError', (_err: Error, socket: Duplex) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')
    socket.destroy()
  })
  server.on('error', (err: Error) => logger.warn('listener error: ' + err.message))

  function sessionOf(req: IncomingMessage): boolean {
    const token = cookieValue(req.headers.cookie, COOKIE)
    return Boolean(token) && verifyToken(secret, pv, token)
  }

  const shutdown = (): void => {
    proxy.destroy()
    const withConnections = server as http.Server & { closeAllConnections?: () => void }
    if (typeof withConnections.closeAllConnections === 'function') withConnections.closeAllConnections()
    server.close()
  }

  ctx.effect(() => ctx.webServer.tapIndex(injectPolyfill), 'dsh-frontgate: secure-context polyfill')

  let ready: Promise<void> | undefined
  ctx.effect(() => {
    ready = new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(listenPort, listenHost, () => {
        server.removeListener('error', reject)
        const address = server.address()
        const port = address && typeof address === 'object' ? address.port : listenPort
        logger.info('listening on ' + publicProto + '://' + listenHost + ':' + port + ' -> ' + targetOrigin)
        if (!isLoopbackHost(listenHost) && !useTls) {
          logger.warn('plaintext HTTP is exposed on ' + listenHost + '; terminate TLS or use a VPN')
        }
        const bound = ctx.webServer.config?.host
        if (typeof bound === 'string' && !isLoopbackHost(bound)) {
          logger.warn('harness is bound to ' + bound + ', so it is reachable without this gate')
        }
        resolve()
      })
    })
    ready.catch((err: Error) => logger.warn('listen failed on ' + listenHost + ':' + listenPort + ': ' + err.message))
    return shutdown
  }, 'dsh-frontgate: listener')

  return {
    ready: () => ready ?? Promise.resolve(),
    address: () => server.address(),
    stop: shutdown,
  }
}

export { Config } from './config.ts'
export { hashPassword, verifyPassword } from './auth.ts'
export { injectPolyfill } from './polyfill.ts'
