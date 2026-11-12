/**
 * The gate's HTTP surface: health, login, logout, and the authenticated proxy.
 *
 * Unauthenticated API calls get 401 JSON so the UI can react; every other path
 * is redirected to the login page. Authenticated requests are handed to the
 * proxy with an exchanged harness cookie.
 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import {
  COOKIE, clearCookie, sessionCookie, signToken, verifyPassword,
} from './auth.ts'
import {
  MAX_FORM, clientIp, cookieValue, hostMatchesPublicOrigin, html, json, readForm, redirect, safeNext,
  sameOrigin, text,
} from './http.ts'
import { loginPage } from './page.ts'
import type { LogSink } from './context.ts'

/** Largest number of clients remembered for lockout accounting. */
const MAX_TRACKED_CLIENTS = 1024
/** Login checks that may run scrypt at the same time. */
const CHECK_CONCURRENCY = 2

/** Values the gate needs at request time. */
export interface GateRuntime {
  title: string
  passwordHash: string
  secret: string
  pv: string
  sessionSeconds: number
  maxAttempts: number
  maxPendingLoginsPerIp: number
  lockMs: number
  trustProxy: boolean
  useTls: boolean
  publicOrigin: string
  secureCookie: boolean
}

/** Collaborators the handler delegates to. */
export interface GateOptions {
  runtime: GateRuntime
  harnessCookie(): Promise<string>
  validSession(token: string): boolean
  revokeSession(token: string): boolean
  forward(req: IncomingMessage, res: ServerResponse, cookie: string, token: string): void
  log: LogSink
}

interface Failure {
  count: number
  until: number
}

/** Build the request handler for one gate instance. */
export function createHandler(options: GateOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const { runtime, harnessCookie, validSession, revokeSession, forward, log } = options
  const { title, passwordHash, secret, pv, sessionSeconds, maxAttempts, maxPendingLoginsPerIp, lockMs, trustProxy, useTls, publicOrigin, secureCookie } = runtime

  // Login throttling: per-client lockout plus a global scrypt slot limit.
  const failures = new Map<string, Failure>()
  const clientsInFlight = new Set<string>()
  const pendingForms = new Map<string, number>()
  let checksInFlight = 0

  function lockRemaining(ip: string): number {
    const entry = failures.get(ip)
    if (!entry || !entry.until) return 0
    if (entry.until > Date.now()) return entry.until - Date.now()
    failures.delete(ip)
    return 0
  }

  function recordFailure(ip: string): void {
    let entry = failures.get(ip)
    if (!entry) {
      if (failures.size >= MAX_TRACKED_CLIENTS) {
        const oldest = failures.keys().next().value
        if (oldest !== undefined) failures.delete(oldest)
      }
      entry = { count: 0, until: 0 }
      failures.set(ip, entry)
    }
    entry.count += 1
    if (entry.count >= maxAttempts) {
      entry.count = 0
      entry.until = Date.now() + lockMs
    }
  }

  function sessionOf(req: IncomingMessage): boolean {
    const token = cookieValue(req.headers.cookie, COOKIE)
    return Boolean(token) && validSession(token)
  }

  async function handleLogin(req: IncomingMessage, res: ServerResponse, search: string): Promise<void> {
    const next = safeNext(new URLSearchParams(search).get('next') || '/')
    if (req.method === 'POST') {
      if (!sameOrigin(req, publicOrigin, useTls)) {
        req.resume()
        res.setHeader('connection', 'close')
        return html(res, 403, loginPage(title, next, 'Origin check failed.'))
      }
      const declared = Number(req.headers['content-length'] || 0)
      if (declared > MAX_FORM) {
        req.resume()
        return text(res, 413, 'request body too large\n', { connection: 'close' })
      }
      const ip = clientIp(req, trustProxy)
      const wait = lockRemaining(ip)
      if (wait > 0) {
        req.resume()
        return text(res, 429, 'too many attempts\n', { 'retry-after': String(Math.ceil(wait / 1000)), connection: 'close' })
      }
      const pending = pendingForms.get(ip) ?? 0
      if (pending >= maxPendingLoginsPerIp) {
        req.resume()
        return text(res, 429, 'too many pending logins\n', { 'retry-after': '1', connection: 'close' })
      }
      pendingForms.set(ip, pending + 1)
      let form: string
      try {
        form = await readForm(req)
      } catch (err) {
        if (res.destroyed) return
        if ((err as Error).message === 'too large') return text(res, 413, 'request body too large\n', { connection: 'close' })
        if ((err as Error).message === 'timeout') return text(res, 408, 'request timeout\n', { connection: 'close' })
        return text(res, 400, 'bad request\n', { connection: 'close' })
      } finally {
        const count = pendingForms.get(ip) ?? 1
        if (count <= 1) pendingForms.delete(ip)
        else pendingForms.set(ip, count - 1)
      }
      const remaining = lockRemaining(ip)
      if (remaining > 0) return text(res, 429, 'too many attempts\n', { 'retry-after': String(Math.ceil(remaining / 1000)) })
      if (clientsInFlight.has(ip) || checksInFlight >= CHECK_CONCURRENCY) {
        return text(res, 429, 'busy, retry shortly\n', { 'retry-after': '1' })
      }
      clientsInFlight.add(ip)
      checksInFlight += 1
      let ok = false
      try {
        ok = await verifyPassword(new URLSearchParams(form).get('password') || '', passwordHash)
      } finally {
        checksInFlight -= 1
        clientsInFlight.delete(ip)
      }
      if (!ok) {
        recordFailure(ip)
        log.info('login failed from ' + ip)
        return html(res, 401, loginPage(title, next, 'Wrong password.'))
      }
      failures.delete(ip)
      log.info('login from ' + ip)
      res.setHeader('set-cookie', sessionCookie(signToken(secret, pv, sessionSeconds), sessionSeconds, secureCookie))
      return redirect(res, next, 303)
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return text(res, 405, 'method not allowed\n', { allow: 'GET, POST' })
    }
    if (sessionOf(req)) return redirect(res, '/')
    return html(res, 200, loginPage(title, next, ''))
  }

  /** Route one request; never throws for expected paths. */
  return async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const raw = req.url || '/'
    if (!raw.startsWith('/')) return text(res, 400, 'bad request\n')
    const queryAt = raw.indexOf('?')
    const path = queryAt === -1 ? raw : raw.slice(0, queryAt)
    const search = queryAt === -1 ? '' : raw.slice(queryAt)

    if (path === '/__gate/health') return json(res, 200, { ok: true, service: 'dsh-frontgate' })
    if (!hostMatchesPublicOrigin(req, publicOrigin, useTls)) return text(res, 403, 'invalid host\n')
    if (path === '/__gate/login') return handleLogin(req, res, search)
    if (path === '/__gate/logout') {
      if (!sameOrigin(req, publicOrigin, useTls)) return text(res, 403, 'forbidden\n')
      const token = cookieValue(req.headers.cookie, COOKIE)
      if (token && validSession(token)) {
        try { revokeSession(token) } catch (err) {
          log.warn('could not revoke session: ' + (err as Error).message)
          return text(res, 503, 'could not sign out; retry later\n')
        }
      }
      res.setHeader('set-cookie', clearCookie(secureCookie))
      return redirect(res, '/__gate/login')
    }
    if (path.startsWith('/__gate/')) return text(res, 404, 'not found\n')

    const token = cookieValue(req.headers.cookie, COOKIE)
    const unauthorized = (): void => {
      if (path === '/api' || path.startsWith('/api/')) {
        return json(res, 401, { error: 'unauthorized', login: '/__gate/login' })
      }
      return redirect(res, '/__gate/login?next=' + encodeURIComponent(raw))
    }
    if (!token || !validSession(token)) return unauthorized()

    if (!sameOrigin(req, publicOrigin, useTls)) {
      log.warn('cross-origin request blocked: ' + String(req.method) + ' ' + path)
      if (path === '/api' || path.startsWith('/api/')) return json(res, 403, { error: 'forbidden' })
      return text(res, 403, 'forbidden\n')
    }

    let cookie: string
    try {
      cookie = await harnessCookie()
    } catch (err) {
      if (res.destroyed) return
      log.warn('harness cookie exchange failed: ' + (err as Error).message)
      return json(res, 503, { error: 'harness_unavailable' })
    }
    if (req.aborted || res.destroyed || !res.writable) return
    if (!validSession(token)) return unauthorized()
    forward(req, res, cookie, token)
  }
}
