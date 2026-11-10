/**
 * Reverse proxy towards the harness listener.
 *
 * Request headers are rewritten so the harness sees a same-origin request from
 * itself, the launch cookie is exchanged server-side and never reaches the
 * browser, and WebSocket upgrades are spliced at the TCP level.
 */
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import tls from 'node:tls'
import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import { clientIp, connectHost, text } from './http.ts'
import type { LogSink } from './context.ts'

/** How long an exchanged harness cookie is reused. */
const HARNESS_COOKIE_TTL = 25 * 60 * 1000

/** Headers that describe this hop or the browser, never the upstream request. */
const REQUEST_DROP = new Set([
  'host', 'origin', 'cookie', 'connection', 'keep-alive', 'proxy-connection',
  'transfer-encoding', 'upgrade', 'te', 'trailer', 'x-forwarded-for',
  'x-forwarded-proto', 'x-forwarded-host',
])

/** Response headers that belong to the upstream connection, plus credentials. */
const RESPONSE_DROP = new Set([
  'set-cookie', 'connection', 'keep-alive', 'proxy-connection',
  'transfer-encoding', 'upgrade', 'trailer',
])

/** Options needed to reach and describe the harness listener. */
export interface ProxyOptions {
  /** Origin of the harness listener, for example http://127.0.0.1:3080. */
  targetOrigin: string
  /** Protocol the gate serves to browsers. */
  publicProto: 'http' | 'https'
  /** Honour forwarded headers from a proxy in front of the gate. */
  trustProxy: boolean
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
  const { targetOrigin, publicProto, trustProxy, authenticatedUrl, log } = options
  const target = new URL(targetOrigin)
  const secureUpstream = target.protocol === 'https:'
  const transport = secureUpstream ? https : http
  const AgentClass = secureUpstream ? https.Agent : http.Agent
  const upstreamAgent = new AgentClass({ keepAlive: true, maxSockets: 128, keepAliveMsecs: 1000 })

  /** One GET / with the launch token; the response carries the harness cookie. */
  function exchangeHarnessCookie(): Promise<string> {
    const url = new URL(authenticatedUrl(targetOrigin + '/'))
    return new Promise((resolve, reject) => {
      const req = transport.request({
        host: connectHost(url.hostname),
        port: Number(url.port) || (secureUpstream ? 443 : 80),
        path: url.pathname + url.search,
        method: 'GET',
        headers: { host: target.host, accept: 'text/html' },
        ...(secureUpstream ? { rejectUnauthorized: false } : {}),
      }, (res) => {
        res.resume()
        const lines = res.headers['set-cookie'] || []
        const cookie = lines.map((line) => line.split(';')[0]).filter(Boolean).join('; ')
        if (!cookie) reject(new Error('launch-token exchange returned ' + res.statusCode + ' without set-cookie'))
        else resolve(cookie)
      })
      req.on('error', reject)
      req.end()
    })
  }

  // Harness launch cookie, exchanged server-side; the browser never sees it.
  let harnessCache = { value: '', at: 0 }
  let harnessInflight: Promise<string> | null = null

  function harnessCookie(): Promise<string> {
    if (harnessCache.value && Date.now() - harnessCache.at < HARNESS_COOKIE_TTL) return Promise.resolve(harnessCache.value)
    if (harnessInflight) return harnessInflight
    harnessInflight = (async () => {
      try {
        const cookie = await exchangeHarnessCookie()
        harnessCache = { value: cookie, at: Date.now() }
        return cookie
      } finally {
        harnessInflight = null
      }
    })()
    return harnessInflight
  }

  function upstreamHeaders(req: IncomingMessage, cookie: string): OutgoingHttpHeaders {
    const out: OutgoingHttpHeaders = {}
    for (const [key, value] of Object.entries(req.headers)) {
      if (!REQUEST_DROP.has(key)) out[key] = value
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
    return rest === '' || rest.startsWith('/') ? rest || '/' : value
  }

  function forward(req: IncomingMessage, res: ServerResponse, cookie: string): void {
    const started = Date.now()
    const proxyReq = transport.request({
      agent: upstreamAgent,
      host: connectHost(target.hostname),
      port: Number(target.port) || (secureUpstream ? 443 : 80),
      method: req.method,
      path: req.url,
      headers: upstreamHeaders(req, cookie),
      ...(secureUpstream ? { rejectUnauthorized: false } : {}),
    }, (proxyRes) => {
      const headers: OutgoingHttpHeaders = {}
      for (const [key, value] of Object.entries(proxyRes.headers)) {
        if (!RESPONSE_DROP.has(key)) headers[key] = value
      }
      const location = proxyRes.headers['location']
      if (location !== undefined) headers.location = rewriteLocation(location)
      const status = proxyRes.statusCode || 502
      res.writeHead(status, headers)
      proxyRes.pipe(res)
      proxyRes.on('error', () => res.destroy())
      const elapsed = Date.now() - started
      if (status >= 400 || elapsed > 1000) {
        log.info(req.method + ' ' + String(req.url || '/').split('?')[0] + ' ' + status + ' ' + elapsed + 'ms')
      }
    })
    proxyReq.on('error', (err: Error) => {
      log.warn('upstream error: ' + err.message)
      sendUpstreamError(res)
    })
    res.on('close', () => proxyReq.destroy())
    req.pipe(proxyReq)
  }

  /** WebSocket/upgrade: authenticate, then splice raw TCP; no HTTP parsing. */
  function forwardUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, cookie: string): void {
    const port = Number(target.port) || (secureUpstream ? 443 : 80)
    const host = connectHost(target.hostname)
    const lines = [req.method + ' ' + (req.url || '/') + ' HTTP/1.1']
    const raw = req.rawHeaders || []
    for (let i = 0; i + 1 < raw.length; i += 2) {
      const lower = raw[i]!.toLowerCase()
      if (lower === 'host' || lower === 'origin' || lower === 'cookie' || lower === 'proxy-connection') continue
      if (lower === 'x-forwarded-for' || lower === 'x-forwarded-proto' || lower === 'x-forwarded-host') continue
      if (lower === 'transfer-encoding') continue
      lines.push(raw[i]! + ': ' + raw[i + 1]!)
    }
    lines.push('Host: ' + target.host)
    if (req.headers.origin !== undefined) lines.push('Origin: ' + target.origin)
    if (cookie) lines.push('Cookie: ' + cookie)
    lines.push('X-Forwarded-For: ' + clientIp(req, trustProxy))
    lines.push('X-Forwarded-Proto: ' + publicProto)
    lines.push('X-Forwarded-Host: ' + String(req.headers.host || ''))
    lines.push('', '')
    const payload = lines.join('\r\n')

    const backend = secureUpstream ? tls.connect({ host, port, rejectUnauthorized: false }) : net.connect(port, host)
    let closed = false
    const teardown = (message?: string): void => {
      if (closed) return
      closed = true
      if (message) log.warn('websocket ' + String(req.url || '/').split('?')[0] + ': ' + message)
      socket.destroy()
      backend.destroy()
    }
    const start = (): void => {
      backend.setTimeout(0)
      backend.write(payload)
      if (head && head.length) backend.write(head)
      backend.pipe(socket)
      socket.pipe(backend)
    }
    backend.setTimeout(10000, () => teardown('connect timeout'))
    if (secureUpstream) backend.once('secureConnect', start)
    else backend.once('connect', start)
    backend.on('error', (err: Error) => teardown(err.message))
    socket.on('error', (err: Error) => teardown(err.message))
    socket.on('end', () => teardown())
    backend.on('end', () => teardown())
    socket.on('close', () => teardown())
    backend.on('close', () => teardown())
  }

  return {
    harnessCookie,
    forward,
    forwardUpgrade,
    destroy: () => upstreamAgent.destroy(),
  }
}
