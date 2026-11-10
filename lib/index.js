/**
 * dsh-frontgate - a small, hardened password gate and reverse proxy for the
 * DeepSeek Harness Web UI.
 *
 * Why another gate: @lvxianchao/dsh-guard is 1500+ lines across eight modules
 * (admin page, i18n, session store, UI badge) and verifies passwords with the
 * synchronous scrypt, which blocks the event loop while a login is checked.
 * This plugin keeps the same operational contract - one password, a signed
 * session cookie, Host/Origin rewrite, server-side harness cookie injection,
 * WebSocket pass-through - in a single dependency-free file with:
 *
 *   - async scrypt, so a login never stalls other requests;
 *   - stateless HMAC sessions bound to a hash of the current password hash, so
 *     changing the password invalidates every session without a session table;
 *   - constant-time comparisons for every secret;
 *   - per-client lockout, a global scrypt concurrency cap, small body limits
 *     and hardened login-page headers;
 *   - loopback-only by default, with optional native TLS;
 *   - no admin page, no i18n, no DOM badge, no mutable settings file.
 */
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import tls from 'node:tls'
import { createHash, createHmac, randomBytes, scrypt, scryptSync, timingSafeEqual } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'

/** Cordis metadata: the plugin id shown in logs and the services it waits for. */
export const name = 'dsh-frontgate'
export const inject = ['webServer', 'connection']

const COOKIE = 'dsh_gate'
const TOKEN_VERSION = 'v1'
const MAX_FORM = 4 * 1024
const FORM_TIMEOUT = 8 * 1000
const CHECK_CONCURRENCY = 2
const MAX_TRACKED_CLIENTS = 1024
const HARNESS_COOKIE_TTL = 25 * 60 * 1000
const SCRYPT = Object.freeze({ N: 32768, r: 8, p: 1, keylen: 32 })

const DEFAULTS = {
  /** Interface and port this gate listens on. Loopback by default. */
  listenHost: '127.0.0.1',
  listenPort: 3090,
  /** Session lifetime in days. */
  sessionDays: 7,
  /** Login page title. */
  title: 'DeepSeek Harness',
  /** Plain-text password (hashed at startup, never written to disk as text). */
  password: '',
  /** scrypt password hash; takes precedence over password and the state file. */
  passwordHash: '',
  /** Optional TLS: both files must be set to serve HTTPS. */
  tlsCertFile: '',
  tlsKeyFile: '',
  /** Honour X-Forwarded-For/Proto from a reverse proxy you control. */
  trustProxy: false,
  /** Failed logins before a client is locked out, and for how many minutes. */
  maxAttempts: 5,
  lockMinutes: 5,
}

const log = (line) => console.log('[dsh-frontgate] ' + line)
const warn = (line) => console.error('[dsh-frontgate] ' + line)

// --- state, password and token helpers --------------------------------------

const intOr = (value, fallback, min, max) => {
  const n = Number.parseInt(value, 10)
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback
}

const scryptMaxmem = (N, r) => Math.max(64 * 1024 * 1024, 256 * N * r)

const HASH_RE = /^scrypt\$\d+\$\d+\$\d+\$[0-9a-f]{32,64}\$[0-9a-f]{32,128}$/

function readState(path) {
  try {
    const value = JSON.parse(readFileSync(path, 'utf8'))
    return value && typeof value === 'object' ? value : {}
  } catch {
    return {}
  }
}

function writeState(path, value) {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 })
}

/** scrypt$N$r$p$saltHex$keyHex - parameters travel with the hash. */
export function hashPassword(password, { N = SCRYPT.N, r = SCRYPT.r, p = SCRYPT.p, keylen = SCRYPT.keylen } = {}) {
  const salt = randomBytes(16)
  const key = scryptSync(String(password), salt, keylen, { N, r, p, maxmem: scryptMaxmem(N, r) })
  return 'scrypt$' + N + '$' + r + '$' + p + '$' + salt.toString('hex') + '$' + key.toString('hex')
}

function scryptAsync(password, salt, keylen, params) {
  return new Promise((resolve) => {
    scrypt(password, salt, keylen, { ...params, maxmem: scryptMaxmem(params.N, params.r) }, (err, key) => resolve(err ? undefined : key))
  })
}

/** Async verification: the event loop stays free while scrypt runs. */
export async function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false
  const parts = stored.split('$')
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false
  const N = Number(parts[1])
  const r = Number(parts[2])
  const p = Number(parts[3])
  if (!Number.isInteger(N) || N < 1024 || N > 1048576 || (N & (N - 1)) !== 0) return false
  if (!Number.isInteger(r) || r < 1 || r > 32) return false
  if (!Number.isInteger(p) || p < 1 || p > 4) return false
  let want, salt
  try {
    salt = Buffer.from(parts[4], 'hex')
    want = Buffer.from(parts[5], 'hex')
  } catch {
    return false
  }
  if (salt.length < 8 || salt.length > 32 || want.length < 16 || want.length > 64) return false
  const got = await scryptAsync(String(password), salt, want.length, { N, r, p })
  return got !== undefined && got.length === want.length && timingSafeEqual(got, want)
}

function verifyPasswordSync(password, stored) {
  if (typeof stored !== 'string') return false
  const parts = stored.split('$')
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false
  const N = Number(parts[1])
  const r = Number(parts[2])
  const p = Number(parts[3])
  if (!Number.isInteger(N) || N < 1024 || N > 1048576 || (N & (N - 1)) !== 0) return false
  if (!Number.isInteger(r) || r < 1 || r > 32 || !Number.isInteger(p) || p < 1 || p > 4) return false
  let want, salt
  try {
    salt = Buffer.from(parts[4], 'hex')
    want = Buffer.from(parts[5], 'hex')
  } catch {
    return false
  }
  if (salt.length < 8 || salt.length > 32 || want.length < 16 || want.length > 64) return false
  try {
    const got = scryptSync(String(password), salt, want.length, { N, r, p, maxmem: scryptMaxmem(N, r) })
    return got.length === want.length && timingSafeEqual(got, want)
  } catch {
    return false
  }
}

const PASSWORD_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'

function randomPassword() {
  const bytes = randomBytes(16)
  let out = ''
  for (let i = 0; i < 16; i++) out += PASSWORD_ALPHABET[bytes[i] & 31]
  return out.slice(0, 4) + '-' + out.slice(4, 8) + '-' + out.slice(8, 12) + '-' + out.slice(12, 16)
}

/** Stable, non-reversible tag of the password hash; embedded in every session. */
const passwordVersion = (passwordHash) => createHash('sha256').update(passwordHash).digest('base64url').slice(0, 12)

function signToken(secret, pv, ttlSeconds) {
  const now = Math.floor(Date.now() / 1000)
  const body = TOKEN_VERSION + '.' + now + '.' + (now + ttlSeconds) + '.' + randomBytes(16).toString('base64url') + '.' + pv
  return body + '.' + createHmac('sha256', secret).update(body).digest('base64url')
}

function verifyToken(secret, pv, token) {
  if (typeof token !== 'string' || token.length > 256) return false
  const parts = token.split('.')
  if (parts.length !== 6) return false
  const [version, iat, exp, nonce, tokenPv, mac] = parts
  if (version !== TOKEN_VERSION || tokenPv !== pv) return false
  const now = Math.floor(Date.now() / 1000)
  const issued = Number(iat)
  const expires = Number(exp)
  if (!Number.isSafeInteger(issued) || !Number.isSafeInteger(expires)) return false
  if (expires <= now || issued > now + 300) return false
  const body = version + '.' + iat + '.' + exp + '.' + nonce + '.' + tokenPv
  const want = createHmac('sha256', secret).update(body).digest()
  let got
  try {
    got = Buffer.from(mac, 'base64url')
  } catch {
    return false
  }
  return got.length === want.length && timingSafeEqual(got, want)
}

// --- request helpers ---------------------------------------------------------

function cookieValue(header, name) {
  if (typeof header !== 'string') return ''
  for (const part of header.split(';')) {
    const at = part.indexOf('=')
    if (at !== -1 && part.slice(0, at).trim() === name) return part.slice(at + 1).trim()
  }
  return ''
}

function clientIp(req, trustProxy) {
  if (trustProxy) {
    const forwarded = req.headers['x-forwarded-for']
    if (typeof forwarded === 'string' && forwarded) return forwarded.split(',')[0].trim().slice(0, 64)
  }
  return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '') || 'unknown'
}

function hostnameOf(value) {
  const host = String(value || '').trim().toLowerCase()
  if (host.startsWith('[')) {
    const end = host.indexOf(']')
    return end === -1 ? host : host.slice(0, end + 1)
  }
  return host.split(':')[0]
}

/** Same-host login check: CSRF needs a cross-site Origin, a foreign Fetch-Site. */
function sameOrigin(req) {
  const site = req.headers['sec-fetch-site']
  if (site !== undefined && site !== 'same-origin' && site !== 'none') return false
  const origin = req.headers.origin
  if (origin === undefined) return true
  try {
    return new URL(origin).hostname.toLowerCase() === hostnameOf(req.headers.host)
  } catch {
    return false
  }
}

/** Only same-site absolute paths; rejects //evil and backslash tricks. */
function safeNext(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/'
  if (value.includes('\\') || /[\u0000-\u001f\u007f]/.test(value)) return '/'
  return value
}

const escapeHtml = (text) => String(text).replace(/[&<>"']/g, (ch) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
))

/** Lock the login page and gate responses down to their own origin. */
const CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

const GATE_HEADERS = {
  'cache-control': 'no-store',
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
}

function send(res, status, headers, body) {
  res.writeHead(status, headers)
  res.end(body)
}

const html = (res, status, body) =>
  send(res, status, { ...GATE_HEADERS, 'content-type': 'text/html; charset=utf-8' }, body)
const json = (res, status, payload) =>
  send(res, status, { ...GATE_HEADERS, 'content-type': 'application/json; charset=utf-8' }, JSON.stringify(payload))
const text = (res, status, body, extra = {}) =>
  send(res, status, { ...GATE_HEADERS, 'content-type': 'text/plain; charset=utf-8', ...extra }, body)
const redirect = (res, location, status = 302) =>
  send(res, status, { ...GATE_HEADERS, location }, '')

/** Read a bounded, form-encoded login body; never trust content-length alone. */
function readForm(req) {
  return new Promise((resolve, reject) => {
    let size = 0
    let settled = false
    const chunks = []
    const finish = (fn, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      fn(value)
    }
    const timer = setTimeout(() => {
      finish(reject, new Error('timeout'))
      req.destroy()
    }, FORM_TIMEOUT)
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_FORM) {
        finish(reject, new Error('too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => finish(resolve, Buffer.concat(chunks).toString('utf8')))
    req.on('error', (err) => finish(reject, err))
    req.on('close', () => {
      if (!req.complete) finish(reject, new Error('aborted'))
    })
  })
}

// --- pages and injection -----------------------------------------------------

function loginPage(title, next, error) {
  const action = '/__gate/login?next=' + encodeURIComponent(next)
  const message = error ? '<p class="err">' + escapeHtml(error) + '</p>' : ''
  return [
    '<!doctype html>',
    '<html lang="zh-CN"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<meta name="referrer" content="no-referrer">',
    '<title>' + escapeHtml(title) + ' - 登录</title>',
    '<style>',
    '  :root{color-scheme:dark}',
    '  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0e1014;color:#e6e8ee;font:14px/1.5 ui-sans-serif,system-ui,"Segoe UI",Roboto,"Noto Sans SC",sans-serif}',
    '  form{width:min(360px,calc(100vw - 48px));padding:28px 26px 24px;border:1px solid #262b36;border-radius:14px;background:#151922;box-shadow:0 20px 60px rgba(0,0,0,.45)}',
    '  h1{margin:0 0 6px;font-size:16px;font-weight:600}',
    '  p{margin:0 0 18px;color:#8b93a5;font-size:12.5px}',
    '  .err{padding:9px 11px;margin:0 0 14px;border-radius:8px;background:rgba(240,92,92,.12);border:1px solid rgba(240,92,92,.3);color:#ff9b9b}',
    '  input{width:100%;box-sizing:border-box;padding:10px 12px;margin:0 0 14px;border-radius:9px;border:1px solid #2c3341;background:#0f131a;color:inherit;font:inherit;outline:none}',
    '  input:focus{border-color:#3f6df0;box-shadow:0 0 0 3px rgba(63,109,240,.18)}',
    '  button{width:100%;padding:10px 12px;border:0;border-radius:9px;background:#3f6df0;color:#fff;font:inherit;font-weight:600;cursor:pointer}',
    '  button:hover{background:#4b78ff}',
    '</style></head>',
    '<body>',
    '<form method="post" action="' + action + '">',
    '  <h1>' + escapeHtml(title) + '</h1>',
    '  <p>该实例由密码网关保护，请输入访问密码。</p>',
    '  ' + message,
    '  <input type="password" name="password" placeholder="访问密码" autofocus autocomplete="current-password">',
    '  <button type="submit">进入</button>',
    '</form>',
    '</body></html>',
  ].join('\n')
}

/** http://LAN-IP is not a secure context: crypto.randomUUID needs a fallback. */
const POLYFILL = '<script data-dsh-frontgate>(function(){var c=globalThis.crypto;if(!c||typeof c.randomUUID==="function")return;c.randomUUID=function(){var b=c.getRandomValues(new Uint8Array(16));b[6]=b[6]&15|64;b[8]=b[8]&63|128;var s="";for(var i=0;i<16;i++)s+=(b[i]+256).toString(16).slice(1);return s.slice(0,8)+"-"+s.slice(8,12)+"-"+s.slice(12,16)+"-"+s.slice(16,20)+"-"+s.slice(20)}})();</script>'

export function injectPolyfill(htmlText) {
  if (typeof htmlText !== 'string' || htmlText.includes('data-dsh-frontgate')) return htmlText
  const at = htmlText.indexOf('</head>')
  return at === -1 ? htmlText : htmlText.slice(0, at) + POLYFILL + htmlText.slice(at)
}

// --- proxy plumbing ----------------------------------------------------------

const isLoopbackHost = (host) => host === 'localhost' || host === '::1' || /^127\./.test(host)

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

const connectHost = (hostname) => hostname.replace(/^\[/, '').replace(/\]$/, '')

function sendUpstreamError(res) {
  if (res.headersSent) {
    res.destroy()
    return
  }
  text(res, 502, 'dsh-frontgate: upstream unreachable\n')
}

// --- the plugin --------------------------------------------------------------

export function apply(ctx, config = {}) {
  const cfg = { ...DEFAULTS, ...config }
  const listenHost = String(cfg.listenHost)
  const listenPort = intOr(cfg.listenPort, DEFAULTS.listenPort, 0, 65535)
  const sessionSeconds = intOr(cfg.sessionDays, DEFAULTS.sessionDays, 1, 365) * 86400
  const maxAttempts = intOr(cfg.maxAttempts, DEFAULTS.maxAttempts, 1, 50)
  const lockMs = intOr(cfg.lockMinutes, DEFAULTS.lockMinutes, 1, 1440) * 60000

  // Per-profile state: password hash + cookie signing secret, 0600.
  const patchPath = ctx.profileContext?.patchPath
    ?? join(process.env.DSH_HOME || join(homedir(), '.dsh'), 'profiles', 'web', 'cordis.patch.yml')
  const statePath = join(dirname(patchPath), 'data', 'dsh-frontgate.json')
  const state = readState(statePath)

  let passwordHash = ''
  if (typeof cfg.passwordHash === 'string' && cfg.passwordHash) passwordHash = cfg.passwordHash
  else if (typeof cfg.password === 'string' && cfg.password) {
    // Reuse the persisted salt when the configured password is unchanged.
    passwordHash = state.passwordHash && verifyPasswordSync(String(cfg.password), state.passwordHash)
      ? state.passwordHash
      : hashPassword(String(cfg.password))
  } else if (typeof state.passwordHash === 'string' && HASH_RE.test(state.passwordHash)) {
    passwordHash = state.passwordHash
  }
  if (!passwordHash) {
    const generated = randomPassword()
    passwordHash = hashPassword(generated)
    log('no password configured - generated a random one and saved its hash to ' + statePath)
    log('PASSWORD: ' + generated)
  }

  const secret = typeof state.secret === 'string' && state.secret.length >= 64
    ? state.secret
    : randomBytes(32).toString('hex')
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

  const AgentClass = target.protocol === 'https:' ? https.Agent : http.Agent
  const upstreamAgent = new AgentClass({ keepAlive: true, maxSockets: 128, keepAliveMsecs: 1000 })

  // Login throttling: per-client lockout plus a global scrypt slot limit.
  const failures = new Map()
  let checksInFlight = 0

  function lockRemaining(ip) {
    const entry = failures.get(ip)
    if (!entry || !entry.until) return 0
    if (entry.until > Date.now()) return entry.until - Date.now()
    failures.delete(ip)
    return 0
  }

  function recordFailure(ip) {
    let entry = failures.get(ip)
    if (!entry) {
      if (failures.size >= MAX_TRACKED_CLIENTS) failures.delete(failures.keys().next().value)
      entry = { count: 0, until: 0 }
      failures.set(ip, entry)
    }
    entry.count += 1
    if (entry.count >= maxAttempts) {
      entry.count = 0
      entry.until = Date.now() + lockMs
    }
  }

  function sessionCookie(value) {
    const attrs = [COOKIE + '=' + value, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=' + sessionSeconds]
    if (useTls) attrs.push('Secure')
    return attrs.join('; ')
  }

  const clearCookie = () => [COOKIE + '=', 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'].join('; ')

  function sessionOf(req) {
    const token = cookieValue(req.headers.cookie, COOKIE)
    return Boolean(token) && verifyToken(secret, pv, token)
  }

  /** One GET / with the launch token; the response carries the harness cookie. */
  function exchangeHarnessCookie() {
    const secureUpstream = target.protocol === 'https:'
    const transport = secureUpstream ? https : http
    const url = new URL(ctx.connection.authenticatedUrl(targetOrigin + '/'))
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
  let harnessInflight = null
  function harnessCookie() {
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

  function upstreamHeaders(req, cookie) {
    const out = {}
    for (const [key, value] of Object.entries(req.headers)) {
      if (!REQUEST_DROP.has(key)) out[key] = value
    }
    out.host = target.host
    if (req.headers.origin !== undefined) out.origin = target.origin
    if (cookie) out.cookie = cookie
    out['x-forwarded-for'] = clientIp(req, cfg.trustProxy)
    out['x-forwarded-proto'] = publicProto
    out['x-forwarded-host'] = String(req.headers.host || '')
    return out
  }

  function rewriteLocation(value) {
    if (typeof value !== 'string' || !value.startsWith(targetOrigin)) return value
    const rest = value.slice(targetOrigin.length)
    return rest === '' || rest.startsWith('/') ? rest || '/' : value
  }

  function forward(req, res, cookie) {
    const started = Date.now()
    const secureUpstream = target.protocol === 'https:'
    const transport = secureUpstream ? https : http
    const proxyReq = transport.request({
      agent: upstreamAgent,
      host: connectHost(target.hostname),
      port: Number(target.port) || (secureUpstream ? 443 : 80),
      method: req.method,
      path: req.url,
      headers: upstreamHeaders(req, cookie),
      ...(secureUpstream ? { rejectUnauthorized: false } : {}),
    }, (proxyRes) => {
      const headers = {}
      for (const [key, value] of Object.entries(proxyRes.headers)) {
        if (!RESPONSE_DROP.has(key)) headers[key] = value
      }
      if (headers.location !== undefined) headers.location = rewriteLocation(headers.location)
      const status = proxyRes.statusCode || 502
      res.writeHead(status, headers)
      proxyRes.pipe(res)
      proxyRes.on('error', () => res.destroy())
      const elapsed = Date.now() - started
      if (status >= 400 || elapsed > 1000) {
        log(req.method + ' ' + String(req.url || '/').split('?')[0] + ' ' + status + ' ' + elapsed + 'ms')
      }
    })
    proxyReq.on('error', (err) => {
      warn('upstream error: ' + err.message)
      sendUpstreamError(res)
    })
    res.on('close', () => proxyReq.destroy())
    req.pipe(proxyReq)
  }

  /** WebSocket/upgrade: authenticate, then splice raw TCP; no HTTP parsing. */
  function forwardUpgrade(req, socket, head, cookie) {
    const secureUpstream = target.protocol === 'https:'
    const port = Number(target.port) || (secureUpstream ? 443 : 80)
    const host = connectHost(target.hostname)
    const lines = [req.method + ' ' + (req.url || '/') + ' HTTP/1.1']
    const raw = req.rawHeaders || []
    for (let i = 0; i + 1 < raw.length; i += 2) {
      const lower = raw[i].toLowerCase()
      if (lower === 'host' || lower === 'origin' || lower === 'cookie' || lower === 'proxy-connection') continue
      if (lower === 'x-forwarded-for' || lower === 'x-forwarded-proto' || lower === 'x-forwarded-host') continue
      if (lower === 'transfer-encoding') continue
      lines.push(raw[i] + ': ' + raw[i + 1])
    }
    lines.push('Host: ' + target.host)
    if (req.headers.origin !== undefined) lines.push('Origin: ' + target.origin)
    if (cookie) lines.push('Cookie: ' + cookie)
    lines.push('X-Forwarded-For: ' + clientIp(req, cfg.trustProxy))
    lines.push('X-Forwarded-Proto: ' + publicProto)
    lines.push('X-Forwarded-Host: ' + String(req.headers.host || ''))
    lines.push('', '')
    const payload = lines.join('\r\n')

    const backend = secureUpstream
      ? tls.connect({ host, port, rejectUnauthorized: false })
      : net.connect(port, host)
    let closed = false
    const teardown = (message) => {
      if (closed) return
      closed = true
      if (message) warn('websocket ' + String(req.url || '/').split('?')[0] + ': ' + message)
      socket.destroy()
      backend.destroy()
    }
    const start = () => {
      backend.setTimeout(0)
      backend.write(payload)
      if (head && head.length) backend.write(head)
      backend.pipe(socket)
      socket.pipe(backend)
    }
    backend.setTimeout(10000, () => teardown('connect timeout'))
    if (secureUpstream) backend.once('secureConnect', start)
    else backend.once('connect', start)
    backend.on('error', (err) => teardown(err.message))
    socket.on('error', (err) => teardown(err.message))
    socket.on('end', () => teardown())
    backend.on('end', () => teardown())
    socket.on('close', () => teardown())
    backend.on('close', () => teardown())
  }

  async function handleLogin(req, res, raw, search) {
    const next = safeNext(new URLSearchParams(search).get('next') || '/')
    if (req.method === 'POST') {
      if (!sameOrigin(req)) return html(res, 403, loginPage(cfg.title, next, '请求来源校验失败'))
      const declared = Number(req.headers['content-length'] || 0)
      if (declared > MAX_FORM) return text(res, 413, 'request body too large\n')
      const ip = clientIp(req, cfg.trustProxy)
      const wait = lockRemaining(ip)
      if (wait > 0) return text(res, 429, 'too many attempts\n', { 'retry-after': String(Math.ceil(wait / 1000)) })
      let form
      try {
        form = await readForm(req)
      } catch (err) {
        if (err.message === 'too large') return text(res, 413, 'request body too large\n')
        return text(res, 400, 'bad request\n')
      }
      if (checksInFlight >= CHECK_CONCURRENCY) return text(res, 429, 'busy, retry shortly\n', { 'retry-after': '1' })
      checksInFlight += 1
      let ok = false
      try {
        ok = await verifyPassword(new URLSearchParams(form).get('password') || '', passwordHash)
      } finally {
        checksInFlight -= 1
      }
      if (!ok) {
        recordFailure(ip)
        log('login failed from ' + ip)
        return html(res, 401, loginPage(cfg.title, next, '密码错误'))
      }
      failures.delete(ip)
      log('login from ' + ip)
      res.setHeader('set-cookie', sessionCookie(signToken(secret, pv, sessionSeconds)))
      return redirect(res, next, 303)
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return text(res, 405, 'method not allowed\n', { allow: 'GET, POST' })
    }
    if (sessionOf(req)) return redirect(res, '/')
    return html(res, 200, loginPage(cfg.title, next, ''))
  }

  async function handle(req, res) {
    const raw = req.url || '/'
    if (!raw.startsWith('/')) return text(res, 400, 'bad request\n')
    const queryAt = raw.indexOf('?')
    const path = queryAt === -1 ? raw : raw.slice(0, queryAt)
    const search = queryAt === -1 ? '' : raw.slice(queryAt)

    if (path === '/__gate/health') return json(res, 200, { ok: true, service: 'dsh-frontgate' })
    if (path === '/__gate/login') return handleLogin(req, res, raw, search)
    if (path === '/__gate/logout') {
      res.setHeader('set-cookie', clearCookie())
      return redirect(res, '/__gate/login')
    }
    if (path.startsWith('/__gate/')) return text(res, 404, 'not found\n')

    if (!sessionOf(req)) {
      if (path === '/api' || path.startsWith('/api/')) {
        return json(res, 401, { error: 'unauthorized', login: '/__gate/login' })
      }
      return redirect(res, '/__gate/login?next=' + encodeURIComponent(raw))
    }

    let cookie
    try {
      cookie = await harnessCookie()
    } catch (err) {
      warn('harness cookie exchange failed: ' + err.message)
      return json(res, 503, { error: 'harness_unavailable' })
    }
    forward(req, res, cookie)
  }

  const requestListener = (req, res) => {
    handle(req, res).catch((err) => {
      warn('handler error: ' + (err && err.stack ? err.stack : String(err)))
      if (!res.headersSent) text(res, 500, 'dsh-frontgate: internal error\n')
      else res.destroy()
    })
  }

  const server = useTls
    ? https.createServer(tlsOptions, requestListener)
    : http.createServer(requestListener)

  server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => socket.destroy())
    try {
      if (!sessionOf(req)) {
        socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
        return
      }
      harnessCookie()
        .then((cookie) => forwardUpgrade(req, socket, head, cookie))
        .catch((err) => {
          warn('websocket blocked: ' + err.message)
          socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n')
        })
    } catch (err) {
      warn('upgrade error: ' + err.message)
      socket.destroy()
    }
  })
  server.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')
    socket.destroy()
  })
  server.on('error', (err) => warn('listener error: ' + err.message))

  ctx.effect(() => ctx.webServer.tapIndex(injectPolyfill), 'dsh-frontgate: secure-context polyfill')

  let ready
  ctx.effect(() => {
    ready = new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(listenPort, listenHost, () => {
        server.removeListener('error', reject)
        log('listening on ' + publicProto + '://' + listenHost + ':' + server.address().port + ' -> ' + targetOrigin)
        if (!isLoopbackHost(listenHost) && !useTls) warn('plaintext HTTP is exposed on ' + listenHost + '; terminate TLS or use a VPN')
        const bound = ctx.webServer.config && ctx.webServer.config.host
        if (typeof bound === 'string' && !isLoopbackHost(bound)) {
          warn('harness is bound to ' + bound + ', so it is reachable without this gate')
        }
        resolve()
      })
    })
    ready.catch((err) => warn('listen failed on ' + listenHost + ':' + listenPort + ': ' + err.message))
    return () => {
      upstreamAgent.destroy()
      if (typeof server.closeAllConnections === 'function') server.closeAllConnections()
      server.close()
    }
  }, 'dsh-frontgate: listener')

  return {
    ready: () => ready,
    address: () => server.address(),
    stop: () => {
      upstreamAgent.destroy()
      if (typeof server.closeAllConnections === 'function') server.closeAllConnections()
      server.close()
    },
  }
}
