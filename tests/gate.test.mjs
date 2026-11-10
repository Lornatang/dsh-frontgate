import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, hashPassword, injectPolyfill } from '../lib/index.js'

const PASSWORD = 'correct horse battery staple'
const HASH = hashPassword(PASSWORD)

function startUpstream() {
  return new Promise((resolve) => {
    const seen = []
    const sockets = new Set()
    let port = 0
    const server = http.createServer((req, res) => {
      seen.push({ method: req.method, url: req.url, headers: req.headers })
      if (req.url.startsWith('/?token=')) {
        res.writeHead(303, { 'set-cookie': 'dsh-auth=launch-token; Path=/; HttpOnly', location: './' })
        return res.end()
      }
      if (req.url === '/redirect') {
        res.writeHead(302, { location: 'http://127.0.0.1:' + port + '/target' })
        return res.end()
      }
      if (req.url === '/redirect-relative') {
        res.writeHead(302, { location: 'http://127.0.0.1:' + port + '//evil.example/target' })
        return res.end()
      }
      if (req.url === '/api/sessions') {
        res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'upstream=1' })
        return res.end(JSON.stringify({
          ok: true,
          host: req.headers.host,
          cookie: req.headers.cookie || '',
          xff: req.headers['x-forwarded-for'] || '',
        }))
      }
      res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'upstream=1' })
      res.end('<!doctype html><html><head><title>app</title></head><body>app</body></html>')
    })
    server.on('upgrade', (req, socket) => {
      seen.push({ method: 'UPGRADE', url: req.url, headers: req.headers })
      socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
      socket.on('data', (chunk) => socket.write('echo:' + chunk.toString()))
      socket.on('error', () => socket.destroy())
    })
    server.on('connection', (socket) => {
      sockets.add(socket)
      socket.on('close', () => sockets.delete(socket))
    })
    server.listen(0, '127.0.0.1', () => {
      port = server.address().port
      resolve({
        port,
        seen,
        close: () => new Promise((done) => {
          for (const socket of sockets) socket.destroy()
          server.close(done)
        }),
      })
    })
  })
}

function makeCtx(upstreamPort, dir) {
  const taps = []
  const disposers = []
  const ctx = {
    profileContext: { patchPath: join(dir, 'cordis.patch.yml') },
    webServer: {
      config: { host: '127.0.0.1' },
      getOrigin: () => 'http://127.0.0.1:' + upstreamPort,
      tapIndex(fn) {
        taps.push(fn)
        return () => {
          const at = taps.indexOf(fn)
          if (at !== -1) taps.splice(at, 1)
        }
      },
    },
    connection: {
      authenticatedUrl: (base) => base + (base.includes('?') ? '&' : '?') + 'token=launch-token',
    },
    effect(fn) {
      const disposer = fn()
      if (typeof disposer === 'function') disposers.push(disposer)
      return disposer
    },
  }
  return { ctx, taps, dispose: () => { for (const fn of disposers.splice(0)) fn() } }
}

async function startGate(upstreamPort, dir, overrides = {}) {
  const made = makeCtx(upstreamPort, dir)
  const gate = apply(made.ctx, { listenPort: 0, passwordHash: HASH, title: 'Test Harness', ...overrides })
  await gate.ready()
  const port = gate.address().port
  return {
    port,
    taps: made.taps,
    dispose: () => { gate.stop(); made.dispose() },
  }
}

async function withGate(t, overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream()
  const gate = await startGate(upstream.port, dir, overrides)
  t.after(async () => {
    gate.dispose()
    await upstream.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return { upstream, gate, dir }
}

function setCookies(res) {
  if (typeof res.headers.getSetCookie === 'function') return res.headers.getSetCookie()
  const single = res.headers.get('set-cookie')
  return single ? [single] : []
}

async function request(port, path, options = {}) {
  const res = await fetch('http://127.0.0.1:' + port + path, { redirect: 'manual', ...options })
  const body = await res.text()
  return { res, body, headers: res.headers, cookies: setCookies(res) }
}

async function login(port, password = PASSWORD, next = '/', extraHeaders = {}) {
  const res = await fetch('http://127.0.0.1:' + port + '/__gate/login?next=' + encodeURIComponent(next), {
    redirect: 'manual',
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'http://127.0.0.1:' + port,
      ...extraHeaders,
    },
    body: 'password=' + encodeURIComponent(password),
  })
  const body = await res.text()
  const cookies = setCookies(res)
  return { res, body, cookies, cookie: cookies.length ? cookies[0].split(';')[0] : '' }
}

function openWebSocket(port, cookie, origin) {
  return new Promise((resolve) => {
    const socket = net.connect(port, '127.0.0.1')
    let buffer = ''
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      resolve({ socket, text: () => buffer })
    }
    socket.on('connect', () => {
      const head = [
        'GET /ws HTTP/1.1',
        'Host: 127.0.0.1:' + port,
        'Upgrade: websocket',
        'Connection: Upgrade',
        'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
        'Sec-WebSocket-Version: 13',
      ]
      if (cookie) head.push('Cookie: ' + cookie)
      if (origin) head.push('Origin: ' + origin)
      socket.write(head.join('\r\n') + '\r\n\r\n')
    })
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1')
      if (/HTTP\/1\.1 (101|401|403|503)/.test(buffer)) finish()
    })
    socket.on('error', finish)
    setTimeout(finish, 2000)
  })
}

test('health endpoint answers without a session', async (t) => {
  const { gate } = await withGate(t)
  const { res, body } = await request(gate.port, '/__gate/health')
  assert.equal(res.status, 200)
  assert.deepEqual(JSON.parse(body), { ok: true, service: 'dsh-frontgate' })
})

test('unauthenticated navigation redirects to the login page', async (t) => {
  const { gate } = await withGate(t)
  const { res, headers } = await request(gate.port, '/')
  assert.equal(res.status, 302)
  assert.equal(headers.get('location'), '/__gate/login?next=%2F')
})

test('unauthenticated api calls get 401 json', async (t) => {
  const { gate } = await withGate(t)
  const { res, body } = await request(gate.port, '/api/sessions')
  assert.equal(res.status, 401)
  assert.deepEqual(JSON.parse(body), { error: 'unauthorized', login: '/__gate/login' })
})

test('login page sends restrictive headers', async (t) => {
  const { gate } = await withGate(t)
  const { res, body } = await request(gate.port, '/__gate/login')
  assert.equal(res.status, 200)
  assert.match(res.headers.get('content-security-policy'), /default-src 'none'/)
  assert.match(res.headers.get('content-security-policy'), /form-action 'self'/)
  assert.equal(res.headers.get('cache-control'), 'no-store')
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff')
  assert.match(body, /<html lang="en">/)
  assert.match(body, /<form method="post"/)
  assert.match(body, /Sign in/)
  assert.ok(!body.includes('<script'))
})

test('wrong password is rejected without a session', async (t) => {
  const { gate } = await withGate(t)
  const { res, cookies, body } = await login(gate.port, 'wrong-password')
  assert.equal(res.status, 401)
  assert.equal(cookies.length, 0)
  assert.match(body, /Wrong password\./)
})

test('cross-site login requests are rejected', async (t) => {
  const { gate } = await withGate(t)
  const { res, cookies } = await login(gate.port, PASSWORD, '/', { origin: 'http://evil.example' })
  assert.equal(res.status, 403)
  assert.equal(cookies.length, 0)
})

test('correct password issues a session cookie', async (t) => {
  const { gate } = await withGate(t)
  const { res, cookies } = await login(gate.port)
  assert.equal(res.status, 303)
  assert.equal(res.headers.get('location'), '/')
  assert.equal(cookies.length, 1)
  assert.match(cookies[0], /^dsh_gate=v1\./)
  assert.match(cookies[0], /HttpOnly/)
  assert.match(cookies[0], /SameSite=Lax/)
  assert.match(cookies[0], /Max-Age=/)
})

test('authenticated requests are proxied with rewritten headers', async (t) => {
  const { gate, upstream } = await withGate(t)
  const { cookie } = await login(gate.port)
  assert.ok(cookie)
  const { res, body } = await request(gate.port, '/api/sessions', {
    headers: { cookie, 'x-forwarded-for': '6.6.6.6' },
  })
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('set-cookie'), null)
  const payload = JSON.parse(body)
  assert.equal(payload.ok, true)
  assert.equal(payload.host, '127.0.0.1:' + upstream.port)
  assert.equal(payload.cookie, 'dsh-auth=launch-token')
  assert.equal(payload.xff, '127.0.0.1')
  const exchange = upstream.seen.filter((entry) => entry.url.startsWith('/?token='))
  assert.equal(exchange.length, 1)
  const harnessCall = upstream.seen.filter((entry) => entry.url === '/api/sessions').pop()
  assert.equal(harnessCall.headers.host, '127.0.0.1:' + upstream.port)
  assert.ok(!String(harnessCall.headers.cookie).includes('dsh_gate'))
  const { res: second } = await request(gate.port, '/api/sessions', { headers: { cookie } })
  assert.equal(second.status, 200)
  assert.equal(upstream.seen.filter((entry) => entry.url.startsWith('/?token=')).length, 1)
})

test('upstream redirect Locations are rewritten', async (t) => {
  const { gate } = await withGate(t)
  const { cookie } = await login(gate.port)
  const { res, headers } = await request(gate.port, '/redirect', { headers: { cookie } })
  assert.equal(res.status, 302)
  assert.equal(headers.get('location'), '/target')
})

test('protocol-relative upstream Locations stay on site', async (t) => {
  const { gate } = await withGate(t)
  const { cookie } = await login(gate.port)
  const { res, headers } = await request(gate.port, '/redirect-relative', { headers: { cookie } })
  assert.equal(res.status, 302)
  assert.equal(headers.get('location'), '/')
})

test('logout clears the cookie', async (t) => {
  const { gate } = await withGate(t)
  const { res, cookies } = await request(gate.port, '/__gate/logout')
  assert.equal(res.status, 302)
  assert.equal(res.headers.get('location'), '/__gate/login')
  assert.match(cookies[0], /Max-Age=0/)
})

test('tampered session cookies are rejected', async (t) => {
  const { gate } = await withGate(t)
  const { cookie } = await login(gate.port)
  const parts = cookie.split('.')
  parts[parts.length - 1] = 'AAAA'
  const tampered = await request(gate.port, '/', { headers: { cookie: parts.join('.') } })
  assert.equal(tampered.res.status, 302)
  const missing = await request(gate.port, '/')
  assert.equal(missing.res.status, 302)
})

test('login next targets stay on site', async (t) => {
  const { gate } = await withGate(t)
  for (const next of ['//evil.example/x', 'https://evil.example', '/\\evil.example']) {
    const { res } = await login(gate.port, PASSWORD, next)
    assert.equal(res.status, 303)
    assert.equal(res.headers.get('location'), '/')
  }
})

test('repeated failures answer 429 but a correct password still signs in', async (t) => {
  const { gate } = await withGate(t, { maxAttempts: 2, lockMinutes: 1 })
  assert.equal((await login(gate.port, 'nope')).res.status, 401)
  assert.equal((await login(gate.port, 'nope')).res.status, 401)
  const locked = await login(gate.port, 'nope')
  assert.equal(locked.res.status, 429)
  assert.ok(locked.res.headers.get('retry-after'))
  // Correct passwords are verified even while the client is throttled, so a
  // shared address (Docker NAT) cannot be locked out by one client.
  assert.equal((await login(gate.port, PASSWORD)).res.status, 303)
})

test('oversized login bodies are refused', async (t) => {
  const { gate } = await withGate(t)
  const res = await fetch('http://127.0.0.1:' + gate.port + '/__gate/login', {
    redirect: 'manual',
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'http://127.0.0.1:' + gate.port,
    },
    body: 'password=' + 'a'.repeat(5000),
  })
  await res.text()
  assert.equal(res.status, 413)
})

test('websocket upgrades require a session and are spliced through', async (t) => {
  const { gate } = await withGate(t)
  const anonymous = await openWebSocket(gate.port, '')
  assert.match(anonymous.text(), /HTTP\/1\.1 401/)
  anonymous.socket.destroy()
  const { cookie } = await login(gate.port)
  assert.ok(cookie)
  const authed = await openWebSocket(gate.port, cookie)
  assert.match(authed.text(), /HTTP\/1\.1 101/)
  const echoed = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), 2000)
    authed.socket.on('data', (chunk) => {
      if (chunk.toString('latin1').includes('echo:ping')) {
        clearTimeout(timer)
        resolve(true)
      }
    })
    authed.socket.write('ping')
  })
  assert.equal(echoed, true)
  authed.socket.destroy()
})

test('randomUUID polyfill is injected once', async (t) => {
  const { gate } = await withGate(t)
  const transform = gate.taps[0]
  assert.equal(typeof transform, 'function')
  const html = '<!doctype html><html><head><title>x</title></head><body>app</body></html>'
  const once = transform(html)
  assert.match(once, /randomUUID/)
  assert.match(once, /data-dsh-frontgate/)
  assert.equal(transform(once).split('data-dsh-frontgate').length, 2)
  assert.equal(injectPolyfill(undefined), undefined)
  assert.equal(injectPolyfill('<html></html>'), '<html></html>')
})

test('changing the password revokes old sessions', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream()
  const first = await startGate(upstream.port, dir)
  t.after(async () => {
    first.dispose()
    await upstream.close()
    rmSync(dir, { recursive: true, force: true })
  })
  const { cookie } = await login(first.port)
  assert.ok(cookie)
  const rotated = hashPassword('a-brand-new-password')
  const second = await startGate(upstream.port, dir, { passwordHash: rotated })
  t.after(() => second.dispose())
  const stale = await request(second.port, '/', { headers: { cookie } })
  assert.equal(stale.res.status, 302)
  const fresh = await login(second.port, 'a-brand-new-password')
  assert.equal(fresh.res.status, 303)
  assert.ok(fresh.cookie)
})

test('password can come from the environment', async (t) => {
  process.env.DSH_FRONTGATE_PASSWORD = 'env-provided-password'
  t.after(() => { delete process.env.DSH_FRONTGATE_PASSWORD })
  const { gate } = await withGate(t, { passwordHash: '' })
  const { res, cookie } = await login(gate.port, 'env-provided-password')
  assert.equal(res.status, 303)
  assert.ok(cookie)
})

test('short configured passwords are refused', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream()
  t.after(async () => {
    await upstream.close()
    rmSync(dir, { recursive: true, force: true })
  })
  const configured = makeCtx(upstream.port, dir)
  assert.throws(
    () => apply(configured.ctx, { listenPort: 0, passwordHash: '', password: 'short' }),
    /at least 12 characters/,
  )
  process.env.DSH_FRONTGATE_PASSWORD = 'short'
  t.after(() => { delete process.env.DSH_FRONTGATE_PASSWORD })
  const fromEnv = makeCtx(upstream.port, dir)
  assert.throws(
    () => apply(fromEnv.ctx, { listenPort: 0, passwordHash: '' }),
    /DSH_FRONTGATE_PASSWORD/,
  )
  // Exactly twelve characters are accepted.
  const accepted = makeCtx(upstream.port, dir)
  const gate = apply(accepted.ctx, { listenPort: 0, passwordHash: '', password: 'twelve-chars' })
  await gate.ready()
  t.after(() => { gate.stop(); accepted.dispose() })
  const { res, cookie } = await login(gate.address().port, 'twelve-chars')
  assert.equal(res.status, 303)
  assert.ok(cookie)
})

test('cross-origin login origins with a foreign port are rejected', async (t) => {
  const { gate } = await withGate(t)
  const { res, cookies } = await login(gate.port, PASSWORD, '/', { origin: 'http://127.0.0.1:1' })
  assert.equal(res.status, 403)
  assert.equal(cookies.length, 0)
})

test('cross-origin proxy requests are refused', async (t) => {
  const { gate, upstream } = await withGate(t)
  const { cookie } = await login(gate.port)
  assert.ok(cookie)
  const cross = await request(gate.port, '/api/sessions', {
    method: 'POST',
    headers: { cookie, origin: 'http://evil.example', 'content-type': 'application/json' },
    body: '{}',
  })
  assert.equal(cross.res.status, 403)
  assert.deepEqual(JSON.parse(cross.body), { error: 'forbidden' })
  assert.equal(upstream.seen.filter((entry) => entry.method === 'POST').length, 0)
  const same = await request(gate.port, '/api/sessions', {
    method: 'POST',
    headers: { cookie, origin: 'http://127.0.0.1:' + gate.port, 'content-type': 'application/json' },
    body: '{}',
  })
  assert.equal(same.res.status, 200)
})

test('cross-origin websocket upgrades are refused', async (t) => {
  const { gate } = await withGate(t)
  const { cookie } = await login(gate.port)
  assert.ok(cookie)
  const cross = await openWebSocket(gate.port, cookie, 'http://evil.example')
  assert.match(cross.text(), /HTTP\/1\.1 403/)
  cross.socket.destroy()
  const same = await openWebSocket(gate.port, cookie, 'http://127.0.0.1:' + gate.port)
  assert.match(same.text(), /HTTP\/1\.1 101/)
  same.socket.destroy()
})

test('state file permissions are tightened on startup', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const dataDir = join(dir, 'data')
  mkdirSync(dataDir, { recursive: true })
  const statePath = join(dataDir, 'dsh-frontgate.json')
  writeFileSync(statePath, JSON.stringify({ passwordHash: HASH, secret: 'a'.repeat(64) }) + '\n')
  chmodSync(statePath, 0o644)
  const upstream = await startUpstream()
  const gate = await startGate(upstream.port, dir)
  t.after(async () => {
    gate.dispose()
    await upstream.close()
    rmSync(dir, { recursive: true, force: true })
  })
  assert.equal(statSync(statePath).mode & 0o777, 0o600)
})

test('unknown gate routes are not proxied', async (t) => {
  const { gate, upstream } = await withGate(t)
  const { res } = await request(gate.port, '/__gate/nope')
  assert.equal(res.status, 404)
  assert.equal(upstream.seen.length, 0)
})

