/**
 * dsh-frontgate - password gate and reverse proxy for the DeepSeek Harness Web UI.
 *
 * One password, one signed session cookie, one extra port. The plugin rewrites
 * Host and Origin so the harness accepts proxied requests, exchanges the launch
 * cookie on the server so the browser never sees it, and filters the
 * WebSocket handshake before forwarding upgraded connections.
 */
import http from 'node:http'
import https from 'node:https'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { AddressInfo, Socket } from 'node:net'
import type { Duplex } from 'node:stream'
import type { Context } from '@deepseek-ai/cordis'
import { Config, DEFAULTS } from './config.ts'
import { COOKIE, assertStrongPassword, hashPassword, passwordVersion, randomPassword, validPasswordHash } from './auth.ts'
import { resolveLogger } from './context.ts'
import { cookieValue, intOr, isLoopbackHost, normalizePublicOrigin, sameOrigin, text } from './http.ts'
import { injectPolyfill } from './polyfill.ts'
import { createProxy } from './proxy.ts'
import { createHandler } from './gate.ts'
import { hashFor, readState, statePathFor, tightenState, writeState } from './state.ts'
import { acquireStateLock } from './state-lock.ts'
import { createSessionStore, sessionDigest } from './sessions.ts'

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
  const statePath = statePathFor(ctx.profileContext?.patchPath)
  const releaseStateLock = acquireStateLock(statePath)
  try {
    return start(ctx, config, statePath, releaseStateLock)
  } catch (err) {
    releaseStateLock()
    throw err
  }
}

function start(ctx: Context, config: Partial<Config>, statePath: string, releaseStateLock: () => void): GateHandle {
  const logger = resolveLogger(ctx)
  const cfg: Config = { ...DEFAULTS, ...config }
  const listenHost = String(cfg.listenHost)
  const listenPort = intOr(cfg.listenPort, DEFAULTS.listenPort, 0, 65535)
  const sessionSeconds = intOr(cfg.sessionDays, DEFAULTS.sessionDays, 1, 365) * 86400
  const maxAttempts = intOr(cfg.maxAttempts, DEFAULTS.maxAttempts, 1, 50)
  const lockMs = intOr(cfg.lockMinutes, DEFAULTS.lockMinutes, 1, 1440) * 60000
  const exchangeTimeoutMs = intOr(cfg.exchangeTimeoutMs, DEFAULTS.exchangeTimeoutMs, 100, 60000)
  const maxConnectionsPerPeer = intOr(cfg.maxConnectionsPerPeer, DEFAULTS.maxConnectionsPerPeer, 0, 1024)
  const maxPendingLoginsPerIp = intOr(cfg.maxPendingLoginsPerIp, DEFAULTS.maxPendingLoginsPerIp, 1, 128)
  const upstreamHeaderTimeoutMs = intOr(cfg.upstreamHeaderTimeoutMs, DEFAULTS.upstreamHeaderTimeoutMs, 0, 3600000)
  const upstreamIdleTimeoutMs = intOr(cfg.upstreamIdleTimeoutMs, DEFAULTS.upstreamIdleTimeoutMs, 0, 3600000)
  const useTls = Boolean(cfg.tlsCertFile || cfg.tlsKeyFile)
  if (useTls && !(cfg.tlsCertFile && cfg.tlsKeyFile)) {
    throw new Error('dsh-frontgate: tlsCertFile and tlsKeyFile must be set together')
  }
  const publicOrigin = normalizePublicOrigin(String(cfg.publicOrigin || ''))
  if (useTls && publicOrigin && !publicOrigin.startsWith('https://')) {
    throw new Error('dsh-frontgate: publicOrigin must use HTTPS when the gate serves TLS')
  }
  const publicProto = publicOrigin ? new URL(publicOrigin).protocol.slice(0, -1) as 'http' | 'https' : useTls ? 'https' : 'http'
  const tlsOptions = useTls
    ? { cert: readFileSync(String(cfg.tlsCertFile)), key: readFileSync(String(cfg.tlsKeyFile)) }
    : undefined

  // Per-profile state: password hash + cookie signing secret, 0600.
  const stateExists = tightenState(statePath)
  const state = readState(statePath, stateExists)

  // Password precedence: config hash, config password, env hash, env password,
  // state file, then a generated password shown once.
  const configuredPassword = typeof cfg.password === 'string' ? cfg.password : ''
  const envPassword = typeof process.env.DSH_FRONTGATE_PASSWORD === 'string' ? process.env.DSH_FRONTGATE_PASSWORD : ''
  const envPasswordHash = process.env.DSH_FRONTGATE_PASSWORD_HASH || ''
  if (cfg.passwordHash && !validPasswordHash(cfg.passwordHash)) {
    throw new Error('dsh-frontgate: invalid passwordHash')
  }
  if (!cfg.passwordHash && !configuredPassword && envPasswordHash && !validPasswordHash(envPasswordHash)) {
    throw new Error('dsh-frontgate: invalid DSH_FRONTGATE_PASSWORD_HASH')
  }
  let passwordHash = ''
  let generatedPassword = ''
  if (typeof cfg.passwordHash === 'string' && cfg.passwordHash) passwordHash = cfg.passwordHash
  else if (configuredPassword) passwordHash = hashFor(assertStrongPassword(configuredPassword, 'the "password" option'), state)
  else if (envPasswordHash) passwordHash = envPasswordHash
  else if (envPassword) passwordHash = hashFor(assertStrongPassword(envPassword, 'DSH_FRONTGATE_PASSWORD'), state)
  else if (validPasswordHash(state.passwordHash)) passwordHash = state.passwordHash
  if (!passwordHash) {
    generatedPassword = randomPassword()
    passwordHash = hashPassword(generatedPassword)
  }

  const passwordChanged = stateExists && state.passwordHash !== passwordHash
  const secret = !passwordChanged && typeof state.secret === 'string' && state.secret.length >= 64
    ? state.secret : randomBytes(32).toString('hex')
  const pv = passwordVersion(passwordHash)
  const persistedState = {
    passwordHash, secret, createdAt: state.createdAt || new Date().toISOString(),
    revokedSessions: passwordChanged ? [] : state.revokedSessions ?? [],
  }
  if (state.passwordHash !== passwordHash || state.secret !== secret) {
    writeState(statePath, persistedState)
  }
  if (generatedPassword) {
    logger.info('no password configured - generated a random one and saved its hash to ' + statePath)
    logger.info('PASSWORD: ' + generatedPassword)
    logger.info('save this password now; it will not be shown again')
  }

  const targetOrigin = ctx.webServer.getOrigin()
  const target = new URL(targetOrigin)
  if (listenPort !== 0 && listenPort === Number(target.port)) {
    throw new Error('dsh-frontgate: listenPort ' + listenPort + ' collides with the harness listener ' + targetOrigin)
  }

  const active = new Map<Duplex | ServerResponse, { digest: string; timer?: NodeJS.Timeout }>()
  const sessions = createSessionStore(statePath, persistedState, pv, (digest) => {
    for (const [connection, entry] of active) if (entry.digest === digest) connection.destroy()
  })

  const proxy = createProxy({
    targetOrigin,
    publicProto,
    trustProxy: Boolean(cfg.trustProxy),
    exchangeTimeoutMs,
    upstreamHeaderTimeoutMs,
    upstreamIdleTimeoutMs,
    upstreamCa: cfg.upstreamCaFile ? readFileSync(String(cfg.upstreamCaFile)) : undefined,
    upstreamServerName: String(cfg.upstreamServerName || ''),
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
      maxPendingLoginsPerIp,
      lockMs,
      trustProxy: Boolean(cfg.trustProxy),
      useTls,
      publicOrigin,
      secureCookie: publicProto === 'https',
    },
    harnessCookie: proxy.harnessCookie,
    validSession: sessions.valid,
    revokeSession: sessions.revoke,
    forward: (req, res, cookie, token) => {
      if (!track(res, token)) return
      proxy.forward(req, res, cookie)
    },
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
  const peers = new Map<string, number>()
  if (maxConnectionsPerPeer > 0) server.on('connection', (socket: Socket) => {
    const peer = String(socket.remoteAddress || 'unknown').replace(/^::ffff:/, '')
    const count = peers.get(peer) ?? 0
    if (count >= maxConnectionsPerPeer) { socket.destroy(); return }
    peers.set(peer, count + 1)
    socket.once('close', () => {
      const remaining = (peers.get(peer) ?? 1) - 1
      if (remaining <= 0) peers.delete(peer)
      else peers.set(peer, remaining)
    })
  })

  let shuttingDown = false

  function track(connection: Duplex | ServerResponse, token: string): boolean {
    const expiresAt = Number(token.split('.')[2]) * 1000
    const entry: { digest: string; timer?: NodeJS.Timeout } = { digest: sessionDigest(token) }
    active.set(connection, entry)
    const arm = (): void => {
      const remaining = expiresAt - Date.now()
      if (remaining <= 0) { connection.destroy(); return }
      // Recheck wall-clock expiry periodically so a forward clock adjustment
      // cannot leave a connection open for the rest of a multi-day timer.
      entry.timer = setTimeout(arm, Math.min(remaining, 60000))
      entry.timer.unref()
    }
    connection.once('close', () => {
      if (entry.timer) clearTimeout(entry.timer)
      active.delete(connection)
    })
    arm()
    return !connection.destroyed
  }

  server.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    socket.on('error', () => socket.destroy())
    try {
      const token = cookieValue(req.headers.cookie, COOKIE)
      if (!token || !sessions.valid(token)) {
        socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
        return
      }
      if (!sameOrigin(req, publicOrigin, useTls)) {
        logger.warn('websocket blocked: cross-origin upgrade from ' + String(req.headers.origin || ''))
        socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
        return
      }
      if (!track(socket, token)) return
      // Drain and bound early frames while the shared exchange is pending.
      // Leaving an upgrade socket paused also hides a peer's FIN, which would
      // otherwise create an orphan upstream connection after it disconnected.
      const chunks: Buffer[] = head.length ? [head] : []
      let pendingBytes = head.length
      const onEarlyData = (chunk: Buffer): void => {
        pendingBytes += chunk.length
        if (pendingBytes > 65536) { socket.destroy(); return }
        chunks.push(chunk)
      }
      const onEarlyEnd = (): void => { socket.destroy() }
      socket.on('data', onEarlyData)
      socket.once('end', onEarlyEnd)
      if (pendingBytes > 65536) { socket.destroy(); return }
      socket.resume()
      proxy.harnessCookie()
        .then((cookie) => {
          if (shuttingDown || socket.destroyed || !sessions.valid(token)) return
          socket.pause()
          socket.off('data', onEarlyData)
          socket.off('end', onEarlyEnd)
          proxy.forwardUpgrade(req, socket, Buffer.concat(chunks, pendingBytes), cookie)
        })
        .catch((err: Error) => {
          if (socket.destroyed) return
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

  const shutdown = (): void => {
    if (shuttingDown) return
    shuttingDown = true
    for (const connection of active.keys()) connection.destroy()
    proxy.destroy()
    const withConnections = server as http.Server & { closeAllConnections?: () => void }
    if (typeof withConnections.closeAllConnections === 'function') withConnections.closeAllConnections()
    server.close()
    releaseStateLock()
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
        logger.info('listening on ' + (useTls ? 'https' : 'http') + '://' + listenHost + ':' + port + ' -> ' + targetOrigin)
        if (!isLoopbackHost(listenHost) && !useTls) {
          logger.warn('plaintext HTTP is exposed on ' + listenHost + '; terminate TLS or use a VPN')
        }
        if (!isLoopbackHost(listenHost)) {
          logger.warn('use a dedicated hostname or IP: browser cookies are shared across ports')
        }
        if (cfg.trustProxy) {
          logger.warn('trustProxy is enabled; restrict access to this listener to trusted proxies; TCP peer limits apply to the proxy')
        }
        const bound = ctx.webServer.config?.host
        if (typeof bound === 'string' && !isLoopbackHost(bound)) {
          logger.warn('harness is bound to ' + bound + ', so it is reachable without this gate')
        }
        resolve()
      })
    })
    ready.catch((err: Error) => {
      logger.warn('listen failed on ' + listenHost + ':' + listenPort + ': ' + err.message)
      shutdown()
    })
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
