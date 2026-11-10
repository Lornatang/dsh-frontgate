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

/** Hostname without the port, IPv6 brackets preserved. */
export function hostnameOf(value: unknown): string {
  const host = String(value || '').trim().toLowerCase()
  if (host.startsWith('[')) {
    const end = host.indexOf(']')
    return end === -1 ? host : host.slice(0, end + 1)
  }
  return host.split(':')[0] ?? host
}

/** Port carried by a host[:port] authority, or '' when it has none. */
function explicitPort(authority: string): string {
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']')
    if (end === -1) return ''
    const rest = authority.slice(end + 1)
    return rest.startsWith(':') ? rest.slice(1) : ''
  }
  const at = authority.lastIndexOf(':')
  return at === -1 ? '' : authority.slice(at + 1)
}

/**
 * True when the Origin header, if present, names the same authority as Host.
 *
 * The port is compared when the Host header carries one; a Host without a port
 * stays accepted so a TLS-terminating proxy that strips the port keeps working.
 */
export function originMatchesHost(req: IncomingMessage): boolean {
  const origin = req.headers.origin
  if (origin === undefined) return true
  try {
    const url = new URL(origin)
    const host = String(req.headers.host || '').trim().toLowerCase()
    if (url.hostname.toLowerCase() !== hostnameOf(host)) return false
    const port = url.port || (url.protocol === 'https:' ? '443' : '80')
    const declared = explicitPort(host)
    return declared === '' || declared === port
  } catch {
    return false
  }
}

/** Login check: Origin and Fetch-Site must both look same-origin. */
export function sameOrigin(req: IncomingMessage): boolean {
  const site = req.headers['sec-fetch-site']
  if (site !== undefined && site !== 'same-origin' && site !== 'none') return false
  return originMatchesHost(req)
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

/** Write a complete response. */
export function send(res: ServerResponse, status: number, headers: OutgoingHttpHeaders, body: string | Buffer): void {
  res.writeHead(status, headers)
  res.end(body)
}

export const html = (res: ServerResponse, status: number, body: string): void =>
  send(res, status, { ...GATE_HEADERS, 'content-type': 'text/html; charset=utf-8' }, body)

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
      req.destroy()
    }, FORM_TIMEOUT)
    req.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > MAX_FORM) {
        fail(new Error('too large'))
        req.destroy()
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
