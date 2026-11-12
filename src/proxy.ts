/**
 * Reverse proxy towards the harness listener.
 *
 * Request headers are rewritten so the harness sees a same-origin request from
 * itself, the launch cookie is exchanged server-side and never reaches the
 * browser, and WebSocket upgrades are spliced at the TCP level.
 */
import http from 'node:http'
import https from 'node:https'
import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import { clientIp, connectHost, rejectUpgrade, text } from './http.ts'
import type { LogSink } from './context.ts'

/** How long an exchanged harness cookie is reused. */
const HARNESS_COOKIE_TTL = 25 * 60 * 1000
/** Keep admission bounded before requests reach the agent's internal queue. */
const MAX_UPSTREAM_HTTP = 128

/** Headers that describe this hop or the browser, never the upstream request. */
const REQUEST_DROP = new Set([
  'host', 'origin', 'cookie', 'connection', 'keep-alive', 'proxy-connection',
  'proxy-authenticate', 'proxy-authorization', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'x-forwarded-for',
  'x-forwarded-proto', 'x-forwarded-host',
])

/** Response headers that belong to the upstream connection, plus credentials. */
const RESPONSE_DROP = new Set([
  'set-cookie', 'connection', 'keep-alive', 'proxy-connection', 'proxy-authenticate',
  'proxy-authorization', 'transfer-encoding', 'upgrade', 'te', 'trailer',
])

/** Connection can name additional hop-by-hop headers, regardless of case. */
function connectionHeaders(value: string | string[] | undefined): Set<string> {
  return new Set((Array.isArray(value) ? value.join(',') : value || '')
    .split(',').map((part) => part.trim().toLowerCase()).filter(Boolean))
}

/** Options needed to reach and describe the harness listener. */
export interface ProxyOptions {
  /** Origin of the harness listener, for example http://127.0.0.1:3080. */
  targetOrigin: string
  /** Protocol the gate serves to browsers. */
  publicProto: 'http' | 'https'
  /** Honour forwarded headers from a proxy in front of the gate. */
  trustProxy: boolean
  /** Maximum time spent exchanging a launch token, including connection time. */
  exchangeTimeoutMs: number
  upstreamHeaderTimeoutMs: number
  upstreamIdleTimeoutMs: number
  websocketHandshakeTimeoutMs: number
  upstreamCa?: Buffer
  upstreamServerName: string
  /** Absolute entry URL with the harness launch token attached. */
  authenticatedUrl(baseUrl: string): string
  log: LogSink
}

/** Proxy surface used by the request and upgrade handlers. */
export interface Proxy {
  harnessCookie(): Promise<string>
  forward(req: IncomingMessage, res: ServerResponse, cookie: string): void
  forwardUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, cookie: string): void
  destroy(): void
}

function sendUpstreamError(res: ServerResponse): void {
  if (res.headersSent) {
    res.destroy()
    return
  }
  text(res, 502, 'dsh-frontgate: upstream unreachable\n')
}

/** Build the proxy for one harness origin. */
export function createProxy(options: ProxyOptions): Proxy {
  const { targetOrigin, publicProto, trustProxy, exchangeTimeoutMs, upstreamHeaderTimeoutMs,
    upstreamIdleTimeoutMs, websocketHandshakeTimeoutMs, upstreamCa, upstreamServerName, authenticatedUrl, log } = options
  const target = new URL(targetOrigin)
  const secureUpstream = target.protocol === 'https:'
  const transport = secureUpstream ? https : http
  const AgentClass = secureUpstream ? https.Agent : http.Agent
  const upstreamAgent = new AgentClass({ keepAlive: true, maxSockets: MAX_UPSTREAM_HTTP, keepAliveMsecs: 1000 })
  const tlsOptions = secureUpstream
    ? { ...(upstreamCa ? { ca: upstreamCa } : {}), ...(upstreamServerName ? { servername: upstreamServerName } : {}) }
    : {}
  const exchanges = new Set<http.ClientRequest>()
  let activeHttp = 0

  /** One GET / with the launch token; the response carries the harness cookie. */
  function exchangeHarnessCookie(): Promise<string> {
    const url = new URL(authenticatedUrl(targetOrigin + '/'))
    return new Promise((resolve, reject) => {
      let settled = false
      const finish = (error: Error | undefined, cookie?: string): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        exchanges.delete(req)
        if (error) reject(error)
        else resolve(cookie!)
      }
      const req = transport.request({
        host: connectHost(url.hostname),
        port: Number(url.port) || (secureUpstream ? 443 : 80),
        path: url.pathname + url.search,
        method: 'GET',
        headers: { host: target.host, accept: 'text/html' },
        ...tlsOptions,
      }, (res) => {
        res.resume()
        const lines = res.headers['set-cookie'] || []
        const cookie = lines.map((line) => line.split(';')[0]).filter(Boolean).join('; ')
        if (!cookie) finish(new Error('launch-token exchange returned ' + res.statusCode + ' without set-cookie'))
        else finish(undefined, cookie)
      })
      const timer = setTimeout(() => req.destroy(new Error('launch-token exchange timed out')), exchangeTimeoutMs)
      exchanges.add(req)
      req.on('error', (err) => finish(err))
      req.end()
    })
  }

  // Harness launch cookie, exchanged server-side; the browser never sees it.
  let harnessCache = { value: '', at: 0 }
  let harnessInflight: Promise<string> | null = null

  function invalidateHarnessCookie(cookie: string): void {
    if (harnessCache.value === cookie) harnessCache = { value: '', at: 0 }
  }

  function harnessCookie(): Promise<string> {
    if (harnessCache.value && Date.now() - harnessCache.at < HARNESS_COOKIE_TTL) return Promise.resolve(harnessCache.value)
    if (harnessInflight) return harnessInflight
    // Start in a microtask so synchronous URL/request errors cannot leave a
    // rejected promise cached after its cleanup has already run.
    harnessInflight = Promise.resolve()
      .then(exchangeHarnessCookie)
      .then((cookie) => {
        harnessCache = { value: cookie, at: Date.now() }
        return cookie
      })
      .finally(() => {
        harnessInflight = null
      })
    return harnessInflight
  }

  function upstreamHeaders(req: IncomingMessage, cookie: string): OutgoingHttpHeaders {
    const out: OutgoingHttpHeaders = {}
    const connection = connectionHeaders(req.headers.connection)
    for (const [key, value] of Object.entries(req.headers)) {
      if (!REQUEST_DROP.has(key) && !connection.has(key)) out[key] = value
    }
    out.host = target.host
    if (req.headers.origin !== undefined) out.origin = target.origin
    if (cookie) out.cookie = cookie
    out['x-forwarded-for'] = clientIp(req, trustProxy)
    out['x-forwarded-proto'] = publicProto
    out['x-forwarded-host'] = String(req.headers.host || '')
    return out
  }

  function rewriteLocation(value: string): string {
    if (!value.startsWith(targetOrigin)) return value
    const rest = value.slice(targetOrigin.length)
    if (rest === '') return '/'
    // '//host' is protocol-relative and '\\host' is treated as '//host' by
    // browsers; both would leave this origin.
    if (rest.startsWith('//') || rest.startsWith('/\\')) return '/'
    return rest.startsWith('/') ? rest : value
  }

  function forward(req: IncomingMessage, res: ServerResponse, cookie: string): void {
    if (activeHttp >= MAX_UPSTREAM_HTTP) {
      req.resume()
      text(res, 503, 'dsh-frontgate: upstream is busy\n', { 'retry-after': '1', connection: 'close' })
      return
    }
    activeHttp += 1
    res.once('close', () => { activeHttp -= 1 })
    const started = Date.now()
    let headerTimer: NodeJS.Timeout | undefined
    let idleTimer: NodeJS.Timeout | undefined
    let timedOut = false
    const clearTimers = (): void => {
      if (headerTimer) clearTimeout(headerTimer)
      if (idleTimer) clearTimeout(idleTimer)
      headerTimer = undefined
      idleTimer = undefined
    }
    const proxyReq = transport.request({
      agent: upstreamAgent,
      host: connectHost(target.hostname),
      port: Number(target.port) || (secureUpstream ? 443 : 80),
      method: req.method,
      path: req.url,
      headers: upstreamHeaders(req, cookie),
      ...tlsOptions,
    }, (proxyRes) => {
      if (headerTimer) clearTimeout(headerTimer)
      headerTimer = undefined
      if (res.destroyed) { proxyRes.destroy(); return }
      const headers: OutgoingHttpHeaders = {}
      const connection = connectionHeaders(proxyRes.headers.connection)
      for (const [key, value] of Object.entries(proxyRes.headers)) {
        if (!RESPONSE_DROP.has(key) && !connection.has(key)) headers[key] = value
      }
      // A browser must not reuse authenticated data after the gate session ends.
      headers['cache-control'] = 'private, no-store'
      const location = proxyRes.headers['location']
      if (location !== undefined && !connection.has('location')) headers.location = rewriteLocation(location)
      const status = proxyRes.statusCode || 502
      if (status === 401) invalidateHarnessCookie(cookie)
      res.writeHead(status, headers)
      const armIdle = (): void => {
        if (idleTimer) clearTimeout(idleTimer)
        if (!upstreamIdleTimeoutMs) return
        idleTimer = setTimeout(() => {
          if (proxyRes.isPaused() || res.writableNeedDrain) { armIdle(); return }
          timedOut = true
          proxyRes.destroy(new Error('upstream response idle timeout'))
        }, upstreamIdleTimeoutMs)
      }
      proxyRes.on('data', armIdle)
      proxyRes.once('end', clearTimers)
      res.on('drain', armIdle)
      armIdle()
      proxyRes.pipe(res)
      proxyRes.on('error', () => { clearTimers(); res.destroy() })
      const elapsed = Date.now() - started
      if (status >= 400 || elapsed > 1000) {
        log.info(req.method + ' ' + String(req.url || '/').split('?')[0] + ' ' + status + ' ' + elapsed + 'ms')
      }
    })
    if (upstreamHeaderTimeoutMs) {
      headerTimer = setTimeout(() => {
        timedOut = true
        proxyReq.destroy(new Error('upstream response headers timeout'))
      }, upstreamHeaderTimeoutMs)
    }
    proxyReq.on('error', (err: Error) => {
      clearTimers()
      if (res.destroyed) return
      log.warn('upstream error: ' + err.message)
      if (timedOut && !res.headersSent) return text(res, 504, 'dsh-frontgate: upstream timeout\n')
      sendUpstreamError(res)
    })
    res.on('close', () => { clearTimers(); proxyReq.destroy() })
    req.pipe(proxyReq)
  }

  /** Parse and filter the handshake before splicing a successful upgrade. */
  function forwardUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, cookie: string): void {
    const requested = req.headers.upgrade
    if (typeof requested !== 'string' || !requested.trim()) {
      rejectUpgrade(socket, 400)
      return
    }
    const headers = upstreamHeaders(req, cookie)
    headers.connection = 'Upgrade'
    headers.upgrade = requested
    const proxyReq = transport.request({
      agent: false,
      host: connectHost(target.hostname),
      port: Number(target.port) || (secureUpstream ? 443 : 80),
      method: req.method,
      path: req.url,
      headers,
      maxHeaderSize: 16384,
      ...tlsOptions,
    })
    let backend: Duplex | undefined
    let finished = false
    const pending = head.length ? [head] : []
    let pendingBytes = head.length
    const onPendingData = (chunk: Buffer): void => {
      pendingBytes += chunk.length
      if (pendingBytes > 65536) { socket.destroy(); proxyReq.destroy(); return }
      pending.push(chunk)
    }
    const onPendingEnd = (): void => { socket.destroy(); proxyReq.destroy() }
    let connectTimer: NodeJS.Timeout | undefined = setTimeout(() => fail(502, 'connect timeout'), 10000)
    const handshakeTimeout = upstreamHeaderTimeoutMs
      ? Math.min(upstreamHeaderTimeoutMs, websocketHandshakeTimeoutMs) : websocketHandshakeTimeoutMs
    let headerTimer: NodeJS.Timeout | undefined = setTimeout(() => fail(504, 'response headers timeout'), handshakeTimeout)
    const clearTimers = (): void => {
      if (connectTimer) clearTimeout(connectTimer)
      if (headerTimer) clearTimeout(headerTimer)
      connectTimer = undefined
      headerTimer = undefined
    }
    const fail = (status: number, message?: string): void => {
      if (finished) return
      finished = true
      clearTimers()
      if (message) log.warn('websocket ' + String(req.url || '/').split('?')[0] + ': ' + message)
      rejectUpgrade(socket, status)
      proxyReq.destroy()
    }
    proxyReq.on('socket', (upstreamSocket) => {
      const connected = (): void => { if (connectTimer) clearTimeout(connectTimer); connectTimer = undefined }
      upstreamSocket.once(secureUpstream ? 'secureConnect' : 'connect', connected)
    })
    proxyReq.once('response', (response) => {
      if (response.statusCode === 401) invalidateHarnessCookie(cookie)
      const status = response.statusCode === 101 ? 502 : response.statusCode || 502
      response.destroy()
      fail(status)
    })
    proxyReq.once('upgrade', (response, upstreamSocket, responseHead) => {
      if (finished || socket.destroyed) { upstreamSocket.destroy(); return }
      const accepted = response.headers.upgrade
      const connection = connectionHeaders(response.headers.connection)
      if (typeof accepted !== 'string' || accepted.trim().toLowerCase() !== requested.trim().toLowerCase() || !connection.has('upgrade')) {
        upstreamSocket.destroy()
        fail(502, 'invalid upgrade response')
        return
      }
      finished = true
      clearTimers()
      backend = upstreamSocket
      socket.pause()
      socket.off('data', onPendingData)
      socket.off('end', onPendingEnd)
      const drop = new Set([...RESPONSE_DROP, 'content-length', ...connection])
      const lines = ['HTTP/1.1 101 Switching Protocols', 'Connection: Upgrade', 'Upgrade: ' + accepted]
      for (let i = 0; i + 1 < response.rawHeaders.length; i += 2) {
        const name = response.rawHeaders[i]!
        if (!drop.has(name.toLowerCase())) lines.push(name + ': ' + response.rawHeaders[i + 1]!)
      }
      socket.write(lines.join('\r\n') + '\r\n\r\n')
      if (responseHead.length) socket.write(responseHead)
      if (pendingBytes) backend.write(Buffer.concat(pending, pendingBytes))
      let backendEnded = false
      backend.once('end', () => { backendEnded = true })
      backend.on('error', () => socket.destroy())
      backend.on('close', () => { if (!backendEnded) socket.destroy() })
      backend.pipe(socket)
      socket.pipe(backend)
    })
    proxyReq.on('error', (err: Error) => {
      if (socket.destroyed) { finished = true; clearTimers(); return }
      fail(502, err.message)
    })
    socket.on('error', () => { proxyReq.destroy(); backend?.destroy() })
    socket.once('close', () => {
      clearTimers()
      if (backend) backend.destroy()
      else proxyReq.destroy()
    })
    // Read and bound early frames while the upstream handshake is pending.
    // A paused socket would otherwise hide a client's FIN indefinitely.
    socket.on('data', onPendingData)
    socket.once('end', onPendingEnd)
    socket.resume()
    proxyReq.end()
  }

  return {
    harnessCookie,
    forward,
    forwardUpgrade,
    destroy: () => {
      for (const request of exchanges) request.destroy(new Error('proxy stopped'))
      upstreamAgent.destroy()
    },
  }
}
