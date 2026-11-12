/**
 * Request parsing and response helpers shared by the login page and the proxy.
 *
 * Everything here is deliberately small: bounded body reads, one origin check,
 * one redirect sanitizer and one set of gate headers.
 */
import type { IncomingMessage, OutgoingHttpHeaders, ServerResponse } from 'node:http'

/** Largest accepted login form body. */
export const MAX_FORM = 4 * 1024
/** Longest time a login body may take to arrive. */
export const FORM_TIMEOUT = 8 * 1000

/** Parse an integer option and clamp it into range. */
export const intOr = (value: unknown, fallback: number, min: number, max: number): number => {
  const n = Number.parseInt(String(value), 10)
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback
}

/** Read one cookie value from a Cookie header. */
export function cookieValue(header: string | string[] | undefined, name: string): string {
  if (typeof header !== 'string') return ''
  for (const part of header.split(';')) {
    const at = part.indexOf('=')
    if (at !== -1 && part.slice(0, at).trim() === name) return part.slice(at + 1).trim()
  }
  return ''
}

/** Client address used for lockout accounting. */
export function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = req.headers['x-forwarded-for']
    if (typeof forwarded === 'string' && forwarded) return (forwarded.split(',')[0] ?? '').trim().slice(0, 64)
  }
  return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '') || 'unknown'
}

/** Normalize an explicitly configured, browser-facing HTTP(S) origin. */
export function normalizePublicOrigin(value: string): string {
  if (!value) return ''
  try {
    const url = new URL(value)
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
        url.pathname !== '/' || url.search || url.hash) throw new Error('invalid origin')
    return url.origin
  } catch {
    throw new Error('dsh-frontgate: publicOrigin must be an HTTP(S) origin without a path, query, or credentials')
  }
}

/** Resolve the actual Host authority using a configured or native protocol. */
function requestOrigin(req: IncomingMessage, publicOrigin: string, useTls: boolean): string | undefined {
  const host = req.headers.host
  if (typeof host !== 'string' || !host || /[\s/@?#\\]/.test(host)) return undefined
  try {
    const protocol = publicOrigin ? new URL(publicOrigin).protocol : useTls ? 'https:' : 'http:'
    const url = new URL(protocol + '//' + host)
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) return undefined
    if (publicOrigin && url.origin !== publicOrigin) return undefined
    return url.origin
  } catch {
    return undefined
  }
}

/** The configured public authority must match the Host preserved by a proxy. */
export const hostMatchesPublicOrigin = (req: IncomingMessage, publicOrigin: string, useTls: boolean): boolean =>
  requestOrigin(req, publicOrigin, useTls) !== undefined

/** Require a valid Host, and if present an Origin with identical scheme, host and port. */
export function originMatchesHost(req: IncomingMessage, publicOrigin: string, useTls: boolean): boolean {
  const expected = requestOrigin(req, publicOrigin, useTls)
  if (!expected) return false
  const origin = req.headers.origin
  if (origin === undefined) return true
  try {
    const url = new URL(origin)
    return origin === url.origin && url.origin === expected
  } catch {
    return false
  }
}

/** Login check: Origin and Fetch-Site must both look same-origin. */
export function sameOrigin(req: IncomingMessage, publicOrigin: string, useTls: boolean): boolean {
  const site = req.headers['sec-fetch-site']
  if (site !== undefined && site !== 'same-origin' && site !== 'none') return false
  return originMatchesHost(req, publicOrigin, useTls)
}

/** Only same-site absolute paths; rejects //evil and backslash tricks. */
export function safeNext(value: unknown): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/'
  if (value.includes('\\') || /[\u0000-\u001f\u007f]/.test(value)) return '/'
  return value
}

const ENTITIES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }
export const escapeHtml = (text: unknown): string => String(text).replace(/[&<>"']/g, (ch) => ENTITIES[ch] ?? ch)

/** Lock the login page and gate responses down to their own origin. */
export const CSP =
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

/** Headers attached to every response the gate writes itself. */
export const GATE_HEADERS: OutgoingHttpHeaders = {
  'cache-control': 'no-store',
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
}

/** Keep cross-origin referrers private without suppressing the login form's Origin. */
export const LOGIN_REFERRER_POLICY = 'same-origin'

/** Write a complete response. */
export function send(res: ServerResponse, status: number, headers: OutgoingHttpHeaders, body: string | Buffer): void {
  res.writeHead(status, headers)
  res.end(body)
}

export const html = (res: ServerResponse, status: number, body: string): void =>
  send(res, status, { ...GATE_HEADERS, 'referrer-policy': LOGIN_REFERRER_POLICY, 'content-type': 'text/html; charset=utf-8' }, body)

export const json = (res: ServerResponse, status: number, payload: unknown): void =>
  send(res, status, { ...GATE_HEADERS, 'content-type': 'application/json; charset=utf-8' }, JSON.stringify(payload))

export const text = (
  res: ServerResponse,
  status: number,
  body: string,
  extra: OutgoingHttpHeaders = {},
): void => send(res, status, { ...GATE_HEADERS, 'content-type': 'text/plain; charset=utf-8', ...extra }, body)

export const redirect = (res: ServerResponse, location: string, status = 302): void =>
  send(res, status, { ...GATE_HEADERS, location }, '')

/** Read a bounded, form-encoded login body; never trust content-length alone. */
export function readForm(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0
    let settled = false
    const chunks: Buffer[] = []
    const finish = (fn: (value: string) => void, value: string): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      fn(value)
    }
    const fail = (error: Error): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(error)
    }
    const timer = setTimeout(() => {
      fail(new Error('timeout'))
      req.resume()
    }, FORM_TIMEOUT)
    req.on('data', (chunk: Buffer) => {
      if (settled) return
      size += chunk.length
      if (size > MAX_FORM) {
        fail(new Error('too large'))
        req.resume()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => finish(resolve, Buffer.concat(chunks).toString('utf8')))
    req.on('error', (err: Error) => fail(err))
    req.on('close', () => {
      if (!req.complete) fail(new Error('aborted'))
    })
  })
}

export const isLoopbackHost = (host: string): boolean =>
  host === 'localhost' || host === '::1' || /^127\./.test(host)

/** Address form accepted by net.connect / tls.connect. */
export const connectHost = (hostname: string): string => hostname.replace(/^\[/, '').replace(/\]$/, '')
