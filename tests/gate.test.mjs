import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { createHash, createHmac, randomBytes } from 'node:crypto'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { apply, Config, hashPassword, injectPolyfill } from '../lib/index.js'

const PASSWORD = 'correct horse battery staple'
const HASH = hashPassword(PASSWORD)

function startUpstream({ hangExchanges = 0, delayExchangeMs = 0 } = {}) {
  return new Promise((resolve) => {
    const seen = []
    const sockets = new Set()
    const liveStreams = new Set()
    let hangingUpgrades = 0
    let port = 0
    let currentCookie = 'launch-token'
    const server = http.createServer((req, res) => {
      seen.push({ method: req.method, url: req.url, headers: req.headers })
      if (req.url.startsWith('/?token=')) {
        if (hangExchanges > 0) { hangExchanges -= 1; return }
        const respond = () => {
          if (res.destroyed) return
          res.writeHead(303, { 'set-cookie': 'dsh-auth=' + currentCookie + '; Path=/; HttpOnly', location: './' })
          res.end()
        }
        if (delayExchangeMs) return setTimeout(respond, delayExchangeMs)
        return respond()
      }
      if (req.url === '/hang-headers') return
      if (req.url === '/hang-body') { res.writeHead(200); res.write('partial'); return }
      if (req.url === '/cacheable') {
        res.writeHead(200, { 'cache-control': 'private, max-age=31536000, immutable' })
        return res.end('private data')
      }
      if (req.url === '/response-hop') {
        res.writeHead(200, { connection: 'X-Private, close', 'x-private': 'secret', 'x-visible': 'ok' })
        return res.end('ok')
      }
      if (req.url === '/live-stream') {
        res.writeHead(200, { 'content-type': 'text/event-stream' })
        res.write('ready\n')
        liveStreams.add(res)
        res.once('close', () => liveStreams.delete(res))
        return
      }
      if (req.url === '/stream') {
        res.writeHead(200, { 'content-type': 'text/event-stream' })
        let count = 0
        const timer = setInterval(() => { res.write('event\n'); if (++count === 5) { clearInterval(timer); res.end() } }, 50)
        res.on('close', () => clearInterval(timer))
        return
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
        if (req.headers.cookie !== 'dsh-auth=' + currentCookie) { res.writeHead(401); return res.end() }
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
    server.on('upgrade', (req, socket, head) => {
      seen.push({ method: 'UPGRADE', url: req.url, headers: req.headers })
      if (req.headers.cookie !== 'dsh-auth=' + currentCookie) {
        socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
        return
      }
      if (req.url === '/ws-reject') {
        socket.end('HTTP/1.1 403 Forbidden\r\nSet-Cookie: dsh-auth=secret\r\nContent-Length: 6\r\n\r\nsecret')
        return
      }
      if (req.url === '/ws-invalid') {
        socket.end('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: other\r\nSet-Cookie: dsh-auth=secret\r\n\r\n')
        return
      }
      if (req.url === '/ws-hang') {
        hangingUpgrades += 1
        socket.once('close', () => { hangingUpgrades -= 1 })
        socket.once('end', () => socket.destroy())
        socket.resume()
        return
      }
      if (req.url === '/ws-finish') {
        const headers = Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
        socket.end(Buffer.concat([headers, Buffer.alloc(256 * 1024, 'a')]))
        return
      }
      if (req.url === '/ws-cookie') {
        socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, X-Private\r\n')
        setTimeout(() => {
          if (socket.destroyed) return
          socket.write('Upgrade: websocket\r\nSet-Cookie: dsh-auth=secret; HttpOnly\r\nX-Private: secret\r\nSec-WebSocket-Protocol: test\r\n\r\nwelcome')
        }, 30)
        socket.on('data', (chunk) => socket.write('echo:' + chunk.toString()))
        socket.on('error', () => socket.destroy())
        return
      }
      socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
      if (head.length) socket.write('echo:' + head.toString())
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
        socketCount: () => sockets.size,
        liveStreamCount: () => liveStreams.size,
        hangingUpgrades: () => hangingUpgrades,
        sendToStreams: (data) => { for (const stream of liveStreams) stream.write(data) },
        endOneStream: () => liveStreams.values().next().value?.end(),
        rotateCookie: () => { currentCookie = 'rotated-token' },
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

async function waitFor(predicate, timeoutMs = 3000) {
  const until = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() >= until) throw new Error('condition timed out')
    await delay(20)
  }
}

function setCookies(res) {
  if (typeof res.headers.getSetCookie === 'function') return res.headers.getSetCookie()
  const single = res.headers.get('set-cookie')
  return single ? [single] : []
}

async function request(port, path, options = {}) {
  // fetch deliberately replaces Host with the destination; raw HTTP is needed
  // to exercise a reverse proxy preserving or changing that header.
  if (options.headers?.host) {
    return new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path, method: options.method || 'GET', headers: options.headers }, (response) => {
        const chunks = []
        response.on('data', (chunk) => chunks.push(chunk))
        response.on('end', () => {
          const headers = new Headers()
          for (const [name, value] of Object.entries(response.headers)) {
            for (const item of Array.isArray(value) ? value : value === undefined ? [] : [value]) headers.append(name, item)
          }
          const res = { status: response.statusCode, headers }
          resolve({ res, body: Buffer.concat(chunks).toString(), headers, cookies: setCookies(res) })
        })
      })
      req.on('error', reject)
      req.end(options.body)
    })
  }
  const res = await fetch('http://127.0.0.1:' + port + path, { redirect: 'manual', ...options })
  const body = await res.text()
  return { res, body, headers: res.headers, cookies: setCookies(res) }
}

async function login(port, password = PASSWORD, next = '/', extraHeaders = {}) {
  const { res, body, cookies } = await request(port, '/__gate/login?next=' + encodeURIComponent(next), {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'http://127.0.0.1:' + port,
      ...extraHeaders,
    },
    body: 'password=' + encodeURIComponent(password),
  })
  return { res, body, cookies, cookie: cookies.length ? cookies[0].split(';')[0] : '' }
}

function openWebSocket(port, cookie, origin, host = '127.0.0.1:' + port, path = '/ws') {
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
        'GET ' + path + ' HTTP/1.1',
        'Host: ' + host,
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
      if (/HTTP\/1\.1 (101|401|403|502|503|504)/.test(buffer)) finish()
    })
    socket.on('error', finish)
    setTimeout(finish, 2000)
  })
}

function openStream(port, cookie) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/live-stream', headers: { cookie }, agent: false }, (res) => {
      let body = ''
      let closed = false
      res.on('data', (chunk) => { body += chunk.toString() })
      res.on('error', () => {})
      const ended = new Promise((done) => res.once('close', () => { closed = true; done() }))
      resolve({ res, body: () => body, closed: () => closed, ended })
    })
    req.on('error', reject)
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
  assert.equal(res.headers.get('referrer-policy'), 'same-origin')
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff')
  assert.match(body, /<html lang="en">/)
  assert.match(body, /<meta name="referrer" content="same-origin">/)
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
  assert.equal(res.headers.get('referrer-policy'), 'same-origin')
  assert.match(body, /<meta name="referrer" content="same-origin">/)
})

test('cross-site login requests are rejected', async (t) => {
  const { gate } = await withGate(t)
  const { res, cookies } = await login(gate.port, PASSWORD, '/', { origin: 'http://evil.example' })
  assert.equal(res.status, 403)
  assert.equal(cookies.length, 0)
})

test('null origins and cross-site form submissions remain rejected', async (t) => {
  const { gate } = await withGate(t)
  for (const headers of [{ origin: 'null', 'sec-fetch-site': 'same-origin' }, { 'sec-fetch-site': 'cross-site' }]) {
    const { res, cookies } = await login(gate.port, PASSWORD, '/', headers)
    assert.equal(res.status, 403)
    assert.equal(cookies.length, 0)
  }
})

test('correct password issues a session cookie', async (t) => {
  const { gate } = await withGate(t)
  const { res, cookies } = await login(gate.port, PASSWORD, '/', { 'sec-fetch-site': 'same-origin' })
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

test('authenticated upstream responses cannot be cached by the browser', async (t) => {
  const { gate } = await withGate(t)
  const { cookie } = await login(gate.port)
  const response = await request(gate.port, '/cacheable', { headers: { cookie } })
  assert.equal(response.body, 'private data')
  assert.equal(response.headers.get('cache-control'), 'private, no-store')
  const logout = await request(gate.port, '/__gate/logout', { headers: { cookie } })
  assert.equal(logout.headers.get('clear-site-data'), '"cache"')
})

test('upstream redirect Locations are rewritten', async (t) => {
  const { gate } = await withGate(t)
  const { cookie } = await login(gate.port)
  const { res, headers } = await request(gate.port, '/redirect', { headers: { cookie } })
  assert.equal(res.status, 302)
  assert.equal(headers.get('location'), '/target')
})

test('connection-nominated headers are removed in both proxy directions', async (t) => {
  const { gate, upstream } = await withGate(t)
  const { cookie } = await login(gate.port)
  const result = await request(gate.port, '/response-hop', {
    headers: { host: '127.0.0.1:' + gate.port, cookie, connection: 'X-Client-Only, close', 'x-client-only': 'secret' },
  })
  assert.equal(result.res.status, 200)
  assert.equal(result.headers.get('x-private'), null)
  assert.equal(result.headers.get('x-visible'), 'ok')
  assert.equal(upstream.seen.find((entry) => entry.url === '/response-hop').headers['x-client-only'], undefined)
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

test('logout revokes only that session, including across restart', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream()
  const first = await startGate(upstream.port, dir)
  let second
  t.after(async () => { first.dispose(); second?.dispose(); await upstream.close(); rmSync(dir, { recursive: true, force: true }) })
  const session1 = (await login(first.port)).cookie
  const session2 = (await login(first.port)).cookie
  assert.notEqual(session1, session2)
  const logout = await request(first.port, '/__gate/logout', { headers: { cookie: session1 } })
  assert.equal(logout.res.status, 302)
  assert.equal((await request(first.port, '/api/sessions', { headers: { cookie: session1 } })).res.status, 401)
  assert.equal((await request(first.port, '/api/sessions', { headers: { cookie: session2 } })).res.status, 200)
  const saved = readFileSync(join(dir, 'data', 'dsh-frontgate.json'), 'utf8')
  assert.ok(!saved.includes(session1))
  assert.equal(JSON.parse(saved).revokedSessions.length, 1)
  first.dispose()
  second = await startGate(upstream.port, dir)
  assert.equal((await request(second.port, '/api/sessions', { headers: { cookie: session1 } })).res.status, 401)
  assert.equal((await request(second.port, '/api/sessions', { headers: { cookie: session2 } })).res.status, 200)
})

test('a second gate cannot use the same profile or disturb the first gate', async (t) => {
  const { gate, upstream, dir } = await withGate(t)
  const firstCookie = (await login(gate.port)).cookie
  const stream = await openStream(gate.port, firstCookie)
  await waitFor(() => stream.body().includes('ready'))
  await assert.rejects(startGate(upstream.port, dir), /cannot lock profile state/)
  upstream.sendToStreams('first-still-running\n')
  await waitFor(() => stream.body().includes('first-still-running'))
  assert.equal(stream.closed(), false)
  assert.equal((await request(gate.port, '/__gate/logout', { headers: { cookie: firstCookie } })).res.status, 302)
  await Promise.race([stream.ended, delay(2000).then(() => { throw new Error('revoked stream stayed open') })])
  gate.dispose()
  const replacement = await startGate(upstream.port, dir)
  t.after(() => replacement.dispose())
  assert.equal((await request(replacement.port, '/api/sessions', { headers: { cookie: firstCookie } })).res.status, 401)
})

test('an abruptly terminated process releases the profile lock without losing sessions', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-lock-'))
  const upstream = await startUpstream()
  const initial = await startGate(upstream.port, dir)
  const { cookie } = await login(initial.port)
  initial.dispose()
  const script = `
    import { apply } from './lib/index.js'; import { join } from 'node:path'
    const port = Number(process.argv[2])
    const ctx = { profileContext: { patchPath: join(process.argv[1], 'cordis.patch.yml') },
      webServer: { getOrigin: () => 'http://127.0.0.1:' + port, tapIndex: () => () => {} },
      connection: { authenticatedUrl: url => url }, effect: fn => fn() }
    const gate = apply(ctx, { listenPort: 0, passwordHash: process.argv[3] })
    await gate.ready(); process.stdout.write('READY\\n')
  `
  const child = spawn(process.execPath, ['--input-type=module', '-e', script, dir, String(upstream.port), HASH], {
    cwd: new URL('..', import.meta.url), stdio: ['ignore', 'pipe', 'pipe'],
  })
  let output = ''
  let errors = ''
  child.stdout.on('data', (chunk) => { output += chunk.toString() })
  child.stderr.on('data', (chunk) => { errors += chunk.toString() })
  let replacement
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
    replacement?.dispose()
    await upstream.close()
    rmSync(dir, { recursive: true, force: true })
  })
  await waitFor(() => output.includes('READY') || child.exitCode !== null, 6000)
  assert.match(output, /READY/, errors)
  await assert.rejects(startGate(upstream.port, dir), /cannot lock profile state/)
  const exited = new Promise(resolve => child.once('exit', resolve))
  child.kill('SIGKILL')
  await exited
  replacement = await startGate(upstream.port, dir)
  assert.equal((await request(replacement.port, '/api/sessions', { headers: { cookie } })).res.status, 200)
})

test('a listener startup failure releases the profile lock', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-lock-failure-'))
  const upstream = await startUpstream()
  const occupied = http.createServer()
  await new Promise((resolve) => occupied.listen(0, '127.0.0.1', resolve))
  let replacement
  t.after(async () => {
    replacement?.dispose()
    await new Promise((resolve) => occupied.close(resolve))
    await upstream.close()
    rmSync(dir, { recursive: true, force: true })
  })
  const failed = apply(makeCtx(upstream.port, dir).ctx, { listenPort: occupied.address().port, passwordHash: HASH })
  await assert.rejects(failed.ready(), /EADDRINUSE/)
  replacement = await startGate(upstream.port, dir)
  assert.equal((await request(replacement.port, '/__gate/health')).res.status, 200)
})

test('alternate encodings of a revoked token cannot bypass logout', async (t) => {
  const { gate } = await withGate(t)
  const { cookie } = await login(gate.port)
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  const last = alphabet.indexOf(cookie.at(-1))
  assert.equal(last % 4, 0)
  const alternate = cookie.slice(0, -1) + alphabet[last + 1]
  assert.equal(Buffer.from(alternate.split('.').at(-1), 'base64url').toString('hex'),
    Buffer.from(cookie.split('.').at(-1), 'base64url').toString('hex'))
  assert.equal((await request(gate.port, '/__gate/logout', { headers: { cookie } })).res.status, 302)
  for (const candidate of [alternate, cookie + '=']) {
    assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie: candidate } })).res.status, 401)
  }
})

test('logout closes the same session websocket', async (t) => {
  const { gate } = await withGate(t)
  const { cookie } = await login(gate.port)
  const otherCookie = (await login(gate.port)).cookie
  const ws = await openWebSocket(gate.port, cookie)
  const other = await openWebSocket(gate.port, otherCookie)
  t.after(() => other.socket.destroy())
  assert.match(ws.text(), /HTTP\/1\.1 101/)
  assert.match(other.text(), /HTTP\/1\.1 101/)
  const closed = Promise.race([new Promise(resolve => ws.socket.once('close', () => resolve(true))), delay(2000).then(() => false)])
  assert.equal((await request(gate.port, '/__gate/logout', { headers: { cookie } })).res.status, 302)
  assert.equal(await closed, true)
  other.socket.write('other-session')
  await waitFor(() => other.text().includes('echo:other-session'))
})

test('logout closes only that session’s HTTP streams, including their upstream connections', async (t) => {
  const { gate, upstream } = await withGate(t)
  const firstCookie = (await login(gate.port)).cookie
  const secondCookie = (await login(gate.port)).cookie
  const first = await openStream(gate.port, firstCookie)
  const second = await openStream(gate.port, secondCookie)
  await waitFor(() => first.body().includes('ready') && second.body().includes('ready'))
  assert.equal((await request(gate.port, '/__gate/logout', { headers: { cookie: firstCookie } })).res.status, 302)
  await Promise.race([first.ended, delay(2000).then(() => { throw new Error('revoked stream stayed open') })])
  await waitFor(() => upstream.liveStreamCount() === 1)
  upstream.sendToStreams('after-logout\n')
  await waitFor(() => second.body().includes('after-logout'))
  assert.equal(second.closed(), false)
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie: firstCookie } })).res.status, 401)
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie: secondCookie } })).res.status, 200)
  second.res.destroy()
})

test('logout reports failure if revocation cannot be persisted', async (t) => {
  const { gate, dir } = await withGate(t)
  const { cookie } = await login(gate.port)
  writeFileSync(join(dir, 'data', 'dsh-frontgate.json'), '{broken')
  const result = await request(gate.port, '/__gate/logout', { headers: { cookie } })
  assert.equal(result.res.status, 503)
  assert.equal(result.cookies.length, 0)
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie } })).res.status, 200)
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

test('lockout rejects all passwords until the window expires, per client', async (t) => {
  const { gate } = await withGate(t, { maxAttempts: 2, lockMinutes: 1, trustProxy: true })
  assert.equal((await login(gate.port, 'nope')).res.status, 401)
  assert.equal((await login(gate.port, 'nope')).res.status, 401)
  const locked = await login(gate.port, 'nope')
  assert.equal(locked.res.status, 429)
  assert.ok(locked.res.headers.get('retry-after'))
  assert.equal((await login(gate.port, PASSWORD)).res.status, 429)
  assert.equal((await login(gate.port, PASSWORD, '/', { 'x-forwarded-for': '192.0.2.7' })).res.status, 303)
  const now = Date.now()
  t.mock.method(Date, 'now', () => now + 61000)
  assert.equal((await login(gate.port, PASSWORD)).res.status, 303)
})

test('concurrent login attempts from one client cannot bypass the lockout', async (t) => {
  const { gate } = await withGate(t, { maxAttempts: 1, lockMinutes: 1 })
  const results = await Promise.all(Array.from({ length: 6 }, () => login(gate.port, 'wrong-password')))
  assert.equal(results.filter((result) => result.res.status === 401).length, 1)
  assert.equal(results.filter((result) => result.res.status === 429).length, 5)
  assert.equal((await login(gate.port)).res.status, 429)
})

test('a full failure store preserves existing lockouts and recovers when they expire', async (t) => {
  let now = Date.now()
  t.mock.method(Date, 'now', () => now)
  const { gate } = await withGate(t, {
    passwordHash: hashPassword(PASSWORD, { N: 1024 }), maxAttempts: 1, lockMinutes: 1, trustProxy: true,
  })
  t.mock.method(process.stderr, 'write', () => true)
  const original = { 'x-forwarded-for': '198.51.100.1' }
  assert.equal((await login(gate.port, 'wrong', '/', original)).res.status, 401)
  for (let i = 0; i < 1022; i++) {
    const ip = `203.0.${Math.floor(i / 256)}.${i % 256}`
    assert.equal((await login(gate.port, 'wrong', '/', { 'x-forwarded-for': ip })).res.status, 401)
  }
  const concurrent = await Promise.all(['203.0.4.1', '203.0.4.2'].map(ip =>
    login(gate.port, 'wrong', '/', { 'x-forwarded-for': ip })))
  assert.deepEqual(concurrent.map(result => result.res.status).sort((a, b) => a - b), [401, 429])
  assert.equal((await login(gate.port, PASSWORD, '/', { 'x-forwarded-for': '192.0.2.1' })).res.status, 429)
  assert.equal((await login(gate.port, PASSWORD, '/', original)).res.status, 429)
  now += 61000
  assert.equal((await login(gate.port, PASSWORD, '/', original)).res.status, 303)
  assert.equal((await login(gate.port, PASSWORD, '/', { 'x-forwarded-for': '192.0.2.1' })).res.status, 303)
})

test('partial login failures expire after the lockout window', async (t) => {
  const { gate } = await withGate(t, { maxAttempts: 2, lockMinutes: 1 })
  assert.equal((await login(gate.port, 'wrong')).res.status, 401)
  const now = Date.now()
  t.mock.method(Date, 'now', () => now + 61000)
  assert.equal((await login(gate.port, 'wrong')).res.status, 401)
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

test('oversized chunked login returns 413 before closing the connection', async (t) => {
  const { gate } = await withGate(t)
  const status = await new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: gate.port, path: '/__gate/login', method: 'POST',
      headers: { origin: 'http://127.0.0.1:' + gate.port, 'transfer-encoding': 'chunked' },
    }, res => { res.resume(); resolve(res.statusCode) })
    req.on('error', reject)
    req.end('password=' + 'x'.repeat(5000))
  })
  assert.equal(status, 413)
})

test('slow login bodies are limited per client without blocking health checks', async (t) => {
  const { gate } = await withGate(t, { maxPendingLoginsPerIp: 2, maxConnectionsPerPeer: 16 })
  const sockets = []
  t.after(() => { for (const socket of sockets) socket.destroy() })
  for (let i = 0; i < 2; i++) {
    const socket = net.connect(gate.port, '127.0.0.1')
    sockets.push(socket)
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject) })
    socket.write(`POST /__gate/login HTTP/1.1\r\nHost: 127.0.0.1:${gate.port}\r\nOrigin: http://127.0.0.1:${gate.port}\r\nContent-Length: 1000\r\n\r\nx`)
  }
  await delay(100)
  assert.equal((await login(gate.port)).res.status, 429)
  assert.equal((await request(gate.port, '/__gate/health')).res.status, 200)
  for (const socket of sockets) socket.destroy()
  await delay(100)
  assert.equal((await login(gate.port)).res.status, 303)
})

test('partial headers cannot exhaust all server connections from one peer', async (t) => {
  const { gate } = await withGate(t, { maxConnectionsPerPeer: 2 })
  const sockets = []
  t.after(() => { for (const socket of sockets) socket.destroy() })
  for (let i = 0; i < 2; i++) {
    const socket = net.connect(gate.port, '127.0.0.1')
    sockets.push(socket)
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject) })
    socket.write('GET / HTTP/1.1\r\nHost: 127.0.0.1')
  }
  await delay(100)
  const blocked = await new Promise(resolve => {
    const req = http.get({ host: '127.0.0.1', port: gate.port, path: '/__gate/health', timeout: 1000 }, res => { res.resume(); resolve(res.statusCode) })
    req.on('error', () => resolve('closed'))
    req.on('timeout', () => { req.destroy(); resolve('timeout') })
  })
  assert.equal(blocked, 'closed')
  sockets[0].destroy()
  await delay(100)
  assert.equal((await request(gate.port, '/__gate/health')).res.status, 200)
})

test('rejected upgrades release the peer limit even if the client remains half-open', async (t) => {
  const { gate } = await withGate(t, { maxConnectionsPerPeer: 1 })
  const socket = new net.Socket({ allowHalfOpen: true })
  t.after(() => socket.destroy())
  socket.on('error', () => {})
  let response = ''
  let ended = false
  socket.on('data', chunk => { response += chunk.toString() })
  socket.on('end', () => { ended = true })
  socket.connect(gate.port, '127.0.0.1')
  await new Promise(resolve => socket.once('connect', resolve))
  socket.write(`GET /ws HTTP/1.1\r\nHost: 127.0.0.1:${gate.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n`)
  await waitFor(() => ended)
  assert.match(response, /^HTTP\/1\.1 401/)
  await delay(50)
  assert.equal((await request(gate.port, '/__gate/health')).res.status, 200)
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

test('websocket handshake filters upstream cookies and hop-by-hop headers before streaming', async (t) => {
  const { gate } = await withGate(t)
  const { cookie } = await login(gate.port)
  const ws = await openWebSocket(gate.port, cookie, undefined, undefined, '/ws-cookie')
  t.after(() => ws.socket.destroy())
  await waitFor(() => ws.text().includes('welcome'))
  const headers = ws.text().split('\r\n\r\n')[0]
  assert.match(headers, /^HTTP\/1\.1 101/)
  assert.match(headers, /Sec-WebSocket-Protocol: test/i)
  assert.doesNotMatch(headers, /Set-Cookie|dsh-auth|X-Private/i)
  ws.socket.write('ping')
  await waitFor(() => ws.text().includes('echo:ping'))
})

test('rejected, invalid and stalled websocket handshakes never expose upstream headers', async (t) => {
  const { gate } = await withGate(t, { upstreamHeaderTimeoutMs: 180 })
  const { cookie } = await login(gate.port)
  for (const [path, status] of [['/ws-reject', 403], ['/ws-invalid', 502], ['/ws-hang', 504]]) {
    const ws = await openWebSocket(gate.port, cookie, undefined, undefined, path)
    assert.match(ws.text(), new RegExp('^HTTP/1\\.1 ' + status))
    assert.doesNotMatch(ws.text(), /Set-Cookie|dsh-auth|secret/i)
    ws.socket.destroy()
  }
})

test('websocket data is flushed before a clean upstream close', async (t) => {
  const { gate } = await withGate(t)
  const { cookie } = await login(gate.port)
  const ws = await openWebSocket(gate.port, cookie, undefined, undefined, '/ws-finish')
  t.after(() => ws.socket.destroy())
  if (!ws.socket.destroyed) await Promise.race([
    new Promise((resolve) => ws.socket.once('close', resolve)),
    delay(3000).then(() => { throw new Error('websocket stayed open') }),
  ])
  assert.equal(ws.text().split('\r\n\r\n')[1].length, 256 * 1024)
})

test('an established websocket outlives the configured response deadlines', async (t) => {
  const { gate } = await withGate(t, { upstreamHeaderTimeoutMs: 120, upstreamIdleTimeoutMs: 120 })
  const { cookie } = await login(gate.port)
  const ws = await openWebSocket(gate.port, cookie)
  t.after(() => ws.socket.destroy())
  assert.match(ws.text(), /HTTP\/1\.1 101/)
  await delay(450)
  assert.equal(ws.socket.destroyed, false)
  ws.socket.write('after-silence')
  await waitFor(() => ws.text().includes('echo:after-silence'))
})

test('the independent websocket handshake deadline releases stalled upgrades only', async (t) => {
  assert.equal(Config.dict.websocketHandshakeTimeoutMs.meta.default, 10000)
  const { gate, upstream } = await withGate(t, { websocketHandshakeTimeoutMs: 150 })
  const { cookie } = await login(gate.port)
  const established = await openWebSocket(gate.port, cookie)
  t.after(() => established.socket.destroy())
  assert.match(established.text(), /^HTTP\/1\.1 101/)
  const stalled = await openWebSocket(gate.port, cookie, undefined, undefined, '/ws-hang')
  t.after(() => stalled.socket.destroy())
  assert.match(stalled.text(), /^HTTP\/1\.1 504/)
  await waitFor(() => upstream.hangingUpgrades() === 0)
  established.socket.write('still-open')
  await waitFor(() => established.text().includes('echo:still-open'))
})

test('a disconnected client does not leave a stalled websocket handshake open', async (t) => {
  const { gate, upstream } = await withGate(t)
  const { cookie } = await login(gate.port)
  const socket = net.connect(gate.port, '127.0.0.1')
  t.after(() => socket.destroy())
  socket.on('error', () => {})
  await new Promise(resolve => socket.once('connect', resolve))
  socket.write(`GET /ws-hang HTTP/1.1\r\nHost: 127.0.0.1:${gate.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nCookie: ${cookie}\r\n\r\n`)
  await waitFor(() => upstream.hangingUpgrades() === 1)
  socket.end()
  await waitFor(() => upstream.hangingUpgrades() === 0)
  assert.equal((await request(gate.port, '/__gate/health')).res.status, 200)
})

test('early websocket frames are bounded while an upstream handshake stalls', async (t) => {
  const { gate, upstream } = await withGate(t)
  const { cookie } = await login(gate.port)
  const socket = net.connect(gate.port, '127.0.0.1')
  t.after(() => socket.destroy())
  socket.on('error', () => {})
  await new Promise(resolve => socket.once('connect', resolve))
  socket.write(`GET /ws-hang HTTP/1.1\r\nHost: 127.0.0.1:${gate.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nCookie: ${cookie}\r\n\r\n`)
  await waitFor(() => upstream.hangingUpgrades() === 1)
  socket.write(Buffer.alloc(65537, 'a'))
  await waitFor(() => upstream.hangingUpgrades() === 0)
  assert.equal((await request(gate.port, '/__gate/health')).res.status, 200)
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
  first.dispose()
  const rotated = hashPassword('a-brand-new-password')
  const second = await startGate(upstream.port, dir, { passwordHash: rotated })
  t.after(() => second.dispose())
  const stale = await request(second.port, '/', { headers: { cookie } })
  assert.equal(stale.res.status, 302)
  const fresh = await login(second.port, 'a-brand-new-password')
  assert.equal(fresh.res.status, 303)
  assert.ok(fresh.cookie)
})

test('stopping the gate closes upgrades and restoring an old password cannot revive sessions', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream()
  const first = await startGate(upstream.port, dir)
  let next
  let restored
  t.after(async () => { first.dispose(); next?.dispose(); restored?.dispose(); await upstream.close(); rmSync(dir, { recursive: true, force: true }) })
  const { cookie } = await login(first.port)
  const ws = await openWebSocket(first.port, cookie)
  assert.match(ws.text(), /HTTP\/1\.1 101/)
  const closed = Promise.race([new Promise(resolve => ws.socket.once('close', () => resolve(true))), delay(2000).then(() => false)])
  first.dispose()
  assert.equal(await closed, true)
  next = await startGate(upstream.port, dir, { passwordHash: hashPassword('another-test-password') })
  assert.equal((await request(next.port, '/api/sessions', { headers: { cookie } })).res.status, 401)
  next.dispose()
  restored = await startGate(upstream.port, dir)
  assert.equal((await request(restored.port, '/api/sessions', { headers: { cookie } })).res.status, 401)
})

test('a websocket closes when its signed session expires', async (t) => {
  const { gate, dir } = await withGate(t)
  const state = JSON.parse(readFileSync(join(dir, 'data', 'dsh-frontgate.json'), 'utf8'))
  const now = Math.floor(Date.now() / 1000)
  const pv = createHash('sha256').update(HASH).digest('base64url').slice(0, 12)
  const body = ['v1', now, now + 2, randomBytes(16).toString('base64url'), pv].join('.')
  const cookie = 'dsh_gate=' + body + '.' + createHmac('sha256', state.secret).update(body).digest('base64url')
  const ws = await openWebSocket(gate.port, cookie)
  assert.match(ws.text(), /HTTP\/1\.1 101/)
  const closed = Promise.race([new Promise(resolve => ws.socket.once('close', () => resolve(true))), delay(3500).then(() => false)])
  assert.equal(await closed, true)
})

test('an HTTP stream closes at session expiry without closing another session', async (t) => {
  const { gate, upstream, dir } = await withGate(t)
  const state = JSON.parse(readFileSync(join(dir, 'data', 'dsh-frontgate.json'), 'utf8'))
  const now = Math.floor(Date.now() / 1000)
  const pv = createHash('sha256').update(HASH).digest('base64url').slice(0, 12)
  const body = ['v1', now, now + 3, randomBytes(16).toString('base64url'), pv].join('.')
  const expiring = 'dsh_gate=' + body + '.' + createHmac('sha256', state.secret).update(body).digest('base64url')
  const other = (await login(gate.port)).cookie
  const first = await openStream(gate.port, expiring)
  const second = await openStream(gate.port, other)
  await waitFor(() => first.body().includes('ready') && second.body().includes('ready'))
  await Promise.race([first.ended, delay(4500).then(() => { throw new Error('expired stream stayed open') })])
  upstream.sendToStreams('still-running\n')
  await waitFor(() => second.body().includes('still-running'))
  assert.equal(second.closed(), false)
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie: expiring } })).res.status, 401)
  second.res.destroy()
})

test('a generated password is printed once and remains valid after restart', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream()
  t.after(async () => {
    await upstream.close()
    rmSync(dir, { recursive: true, force: true })
  })

  const script = `
    import { join } from 'node:path'
    import { apply } from './lib/index.js'
    const ctx = {
      profileContext: { patchPath: join(process.argv[1], 'cordis.patch.yml') },
      webServer: { getOrigin: () => 'http://127.0.0.1:1', tapIndex: () => () => {} },
      connection: { authenticatedUrl: url => url },
      effect: fn => fn(),
    }
    const gate = apply(ctx, { listenPort: 0 })
    await gate.ready()
    gate.stop()
  `
  const env = { ...process.env }
  delete env.DSH_FRONTGATE_PASSWORD
  delete env.DSH_FRONTGATE_PASSWORD_HASH
  const start = () => spawnSync(process.execPath, ['--input-type=module', '-e', script, dir], {
    cwd: new URL('..', import.meta.url), env, encoding: 'utf8',
  })

  const first = start()
  assert.equal(first.status, 0)
  const generated = first.stderr.match(/^\[dsh-frontgate\] PASSWORD: ([a-z2-7]{4}(?:-[a-z2-7]{4}){3})$/m)?.[1]
  assert.ok(generated)
  const state = readFileSync(join(dir, 'data', 'dsh-frontgate.json'), 'utf8')
  assert.ok(!state.includes(generated))

  const second = start()
  assert.equal(second.status, 0)
  assert.doesNotMatch(second.stderr, /\[dsh-frontgate\] PASSWORD:/)
  assert.equal(readFileSync(join(dir, 'data', 'dsh-frontgate.json'), 'utf8'), state)

  const gate = await startGate(upstream.port, dir, { passwordHash: JSON.parse(state).passwordHash })
  t.after(() => gate.dispose())
  assert.equal((await login(gate.port, generated)).res.status, 303)
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

test('scheme, default port, Fetch-Site and Host are checked, ignoring forwarded proto', async (t) => {
  const { gate } = await withGate(t)
  for (const headers of [
    { origin: 'https://127.0.0.1:' + gate.port },
    { host: '127.0.0.1', origin: 'http://127.0.0.1:' + gate.port },
    { origin: 'http://127.0.0.1:' + gate.port, 'sec-fetch-site': 'same-site' },
    { origin: 'https://127.0.0.1:' + gate.port, 'x-forwarded-proto': 'https' },
  ]) {
    const result = await login(gate.port, PASSWORD, '/', headers)
    assert.equal(result.res.status, 403)
    assert.equal(result.cookies.length, 0)
  }
})

test('configured public origin validates proxy Host and marks login and logout cookies Secure', async (t) => {
  const { gate } = await withGate(t, { publicOrigin: 'https://gate.example:8443' })
  const headers = { host: 'gate.example:8443', origin: 'https://gate.example:8443' }
  const good = await login(gate.port, PASSWORD, '/', headers)
  assert.equal(good.res.status, 303)
  assert.match(good.cookies[0], /; Secure(?:;|$)/)
  const logout = await request(gate.port, '/__gate/logout', { headers })
  assert.match(logout.cookies[0], /; Secure(?:;|$)/)
  for (const bad of [
    { host: 'gate.example', origin: 'https://gate.example:8443' },
    { host: 'gate.example:8443', origin: 'http://gate.example:8443' },
    { host: 'gate.example:8443', origin: 'https://gate.example:9443' },
    { host: 'evil.example:8443', origin: 'https://evil.example:8443' },
  ]) assert.equal((await login(gate.port, PASSWORD, '/', bad)).res.status, 403)
  const spoofed = await request(gate.port, '/api/sessions', { headers: { host: 'evil.example', cookie: good.cookie } })
  assert.equal(spoofed.res.status, 403)
})

test('invalid public origins and password hashes fail before creating state', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const { ctx } = makeCtx(1, dir)
  for (const value of ['ftp://gate.example', 'https://user@gate.example', 'https://gate.example/path', 'https://gate.example?x=1']) {
    assert.throws(() => apply(ctx, { publicOrigin: value }), /publicOrigin/)
  }
  assert.throws(() => apply(ctx, { passwordHash: 'invalid' }), /invalid passwordHash/)
})

test('a timed-out harness exchange returns 503 and the next request retries', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream({ hangExchanges: 1 })
  const gate = await startGate(upstream.port, dir, { exchangeTimeoutMs: 150 })
  t.after(async () => { gate.dispose(); await upstream.close(); rmSync(dir, { recursive: true, force: true }) })
  const { cookie } = await login(gate.port)
  const options = { headers: { cookie }, signal: AbortSignal.timeout(3000) }
  const failed = await Promise.all([request(gate.port, '/api/sessions', options), request(gate.port, '/api/sessions', options)])
  assert.deepEqual(failed.map((result) => result.res.status), [503, 503])
  assert.equal(upstream.seen.filter((entry) => entry.url.startsWith('/?token=')).length, 1)
  assert.equal((await request(gate.port, '/api/sessions', options)).res.status, 200)
  assert.equal(upstream.seen.filter((entry) => entry.url.startsWith('/?token=')).length, 2)
})

test('closed clients do not create upstream requests after a delayed exchange', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream({ delayExchangeMs: 500 })
  const gate = await startGate(upstream.port, dir)
  t.after(async () => { gate.dispose(); await upstream.close(); rmSync(dir, { recursive: true, force: true }) })
  const { cookie } = await login(gate.port)
  const requests = Array.from({ length: 4 }, () => {
    const req = http.get({ host: '127.0.0.1', port: gate.port, path: '/api/sessions', headers: { cookie } })
    req.on('error', () => {})
    return req
  })
  const socket = net.connect(gate.port, '127.0.0.1')
  socket.on('error', () => {})
  await new Promise(resolve => socket.once('connect', resolve))
  socket.write(`GET /ws HTTP/1.1\r\nHost: 127.0.0.1:${gate.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nCookie: ${cookie}\r\n\r\n`)
  await waitFor(() => upstream.seen.some(entry => entry.url.startsWith('/?token=')))
  for (const req of requests) req.destroy()
  socket.destroy()
  await delay(650)
  assert.deepEqual(upstream.seen.filter(entry => entry.url === '/api/sessions' || entry.method === 'UPGRADE').map(entry => [entry.method, entry.url]), [])
  assert.ok(upstream.socketCount() <= 1)
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie } })).res.status, 200)
})

test('per-session admission includes requests waiting for a harness cookie', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream({ delayExchangeMs: 350 })
  const gate = await startGate(upstream.port, dir, { maxHttpRequestsPerSession: 1 })
  t.after(async () => { gate.dispose(); await upstream.close(); rmSync(dir, { recursive: true, force: true }) })
  const { cookie } = await login(gate.port)
  const first = request(gate.port, '/api/sessions', { headers: { cookie } })
  await waitFor(() => upstream.seen.some(entry => entry.url.startsWith('/?token=')))
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie } })).res.status, 429)
  assert.equal((await first).res.status, 200)
})

test('websocket bytes sent during a delayed exchange reach the upstream', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream({ delayExchangeMs: 300 })
  const gate = await startGate(upstream.port, dir)
  t.after(async () => { gate.dispose(); await upstream.close(); rmSync(dir, { recursive: true, force: true }) })
  const { cookie } = await login(gate.port)
  const socket = net.connect(gate.port, '127.0.0.1')
  t.after(() => socket.destroy())
  socket.on('error', () => {})
  await new Promise(resolve => socket.once('connect', resolve))
  let response = ''
  socket.on('data', chunk => { response += chunk.toString() })
  socket.write(`GET /ws HTTP/1.1\r\nHost: 127.0.0.1:${gate.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nCookie: ${cookie}\r\n\r\n`)
  await waitFor(() => upstream.seen.some(entry => entry.url.startsWith('/?token=')))
  socket.write('early')
  await waitFor(() => response.includes('echo:early'))
  assert.match(response, /HTTP\/1\.1 101/)
})

test('logout while an exchange is pending prevents forwarding the old session', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream({ delayExchangeMs: 500 })
  const gate = await startGate(upstream.port, dir)
  t.after(async () => { gate.dispose(); await upstream.close(); rmSync(dir, { recursive: true, force: true }) })
  const { cookie } = await login(gate.port)
  const pending = request(gate.port, '/api/sessions', { headers: { cookie }, signal: AbortSignal.timeout(3000) })
  await waitFor(() => upstream.seen.some(entry => entry.url.startsWith('/?token=')))
  assert.equal((await request(gate.port, '/__gate/logout', { headers: { cookie } })).res.status, 302)
  assert.equal((await pending).res.status, 401)
  assert.equal(upstream.seen.filter(entry => entry.url === '/api/sessions').length, 0)
})

test('upstream header and idle deadlines release stalled requests while streams remain active', async (t) => {
  const { gate } = await withGate(t, { upstreamHeaderTimeoutMs: 180, upstreamIdleTimeoutMs: 180 })
  const { cookie } = await login(gate.port)
  const options = { headers: { cookie }, signal: AbortSignal.timeout(3000) }
  assert.equal((await request(gate.port, '/hang-headers', options)).res.status, 504)
  const stream = await request(gate.port, '/stream', options)
  assert.equal(stream.res.status, 200)
  assert.equal(stream.body, 'event\n'.repeat(5))
  const stalled = await fetch('http://127.0.0.1:' + gate.port + '/hang-body', options)
  assert.equal(stalled.status, 200)
  await assert.rejects(stalled.text())
  assert.equal((await request(gate.port, '/api/sessions', options)).res.status, 200)
})

test('silent authenticated streams stay open with the default idle timeout', async (t) => {
  assert.equal(Config.dict.upstreamHeaderTimeoutMs.meta.default, 0)
  assert.equal(Config.dict.upstreamIdleTimeoutMs.meta.default, 0)
  const { gate, upstream } = await withGate(t)
  const { cookie } = await login(gate.port)
  const stream = await openStream(gate.port, cookie)
  await waitFor(() => stream.body().includes('ready'))
  await delay(500)
  assert.equal(stream.closed(), false)
  upstream.sendToStreams('after-silence\n')
  await waitFor(() => stream.body().includes('after-silence'))
  stream.res.destroy()
})

test('per-session HTTP limits leave capacity for another session and release on close', async (t) => {
  const { gate, upstream } = await withGate(t, { maxHttpRequestsPerSession: 2 })
  const firstCookie = (await login(gate.port)).cookie
  const secondCookie = (await login(gate.port)).cookie
  const first = await openStream(gate.port, firstCookie)
  const second = await openStream(gate.port, firstCookie)
  t.after(() => { first.res.destroy(); second.res.destroy() })
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie: firstCookie } })).res.status, 429)
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie: secondCookie } })).res.status, 200)
  first.res.destroy()
  await waitFor(() => upstream.liveStreamCount() === 1)
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie: firstCookie } })).res.status, 200)
})

test('a full upstream pool rejects new HTTP requests promptly and recovers', async (t) => {
  const { gate, upstream } = await withGate(t, { maxHttpRequestsPerSession: 128 })
  const firstCookie = (await login(gate.port)).cookie
  const secondCookie = (await login(gate.port)).cookie
  const socket = net.connect(gate.port, '127.0.0.1')
  t.after(() => socket.destroy())
  socket.on('error', () => {})
  socket.on('data', () => {})
  await new Promise(resolve => socket.once('connect', resolve))
  socket.write(Array.from({ length: 128 }, () =>
    `GET /live-stream HTTP/1.1\r\nHost: 127.0.0.1:${gate.port}\r\nCookie: ${firstCookie}\r\n\r\n`).join(''))
  await waitFor(() => upstream.liveStreamCount() === 128, 10000)
  const options = { headers: { cookie: secondCookie }, signal: AbortSignal.timeout(3000) }
  assert.equal((await request(gate.port, '/api/sessions', options)).res.status, 503)
  upstream.endOneStream()
  await waitFor(() => upstream.liveStreamCount() === 127)
  assert.equal((await request(gate.port, '/api/sessions', options)).res.status, 200)
})

test('an upstream 401 refreshes the cached cookie on the next HTTP or websocket request', async (t) => {
  const { gate, upstream } = await withGate(t)
  const { cookie } = await login(gate.port)
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie } })).res.status, 200)
  upstream.rotateCookie()
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie } })).res.status, 401)
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie } })).res.status, 200)
  assert.equal(upstream.seen.filter(entry => entry.url.startsWith('/?token=')).length, 2)
})

test('an upstream websocket 401 also invalidates the cached cookie', async (t) => {
  const { gate, upstream } = await withGate(t)
  const { cookie } = await login(gate.port)
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie } })).res.status, 200)
  upstream.rotateCookie()
  const ws = await openWebSocket(gate.port, cookie)
  assert.match(ws.text(), /HTTP\/1\.1 401/)
  ws.socket.destroy()
  assert.equal((await request(gate.port, '/api/sessions', { headers: { cookie } })).res.status, 200)
  assert.equal(upstream.seen.filter(entry => entry.url.startsWith('/?token=')).length, 2)
})

test('HTTPS upstream validates its certificate and hostname for HTTP and websockets', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-upstream-tls-'))
  const certPath = join(dir, 'cert.pem')
  const keyPath = join(dir, 'key.pem')
  const cert = spawnSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath,
    '-out', certPath, '-days', '1', '-subj', '/CN=upstream.test',
    '-addext', 'subjectAltName=DNS:upstream.test',
  ], { stdio: 'ignore' })
  assert.equal(cert.status, 0, 'openssl is required for upstream TLS tests')
  const sockets = new Set()
  const upstream = https.createServer({ key: readFileSync(keyPath), cert: readFileSync(certPath) }, (req, res) => {
    if (req.url.startsWith('/?token=')) {
      res.writeHead(303, { 'set-cookie': 'dsh-auth=secure; Path=/' })
      return res.end()
    }
    res.writeHead(req.headers.cookie === 'dsh-auth=secure' ? 200 : 401)
    res.end('secure')
  })
  upstream.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)) })
  upstream.on('upgrade', (req, socket) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    socket.on('error', () => socket.destroy())
  })
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve))
  const gates = []
  t.after(async () => {
    for (const gate of gates) gate.stop()
    for (const socket of sockets) socket.destroy()
    await new Promise(resolve => upstream.close(resolve))
    rmSync(dir, { recursive: true, force: true })
  })
  async function openGate(name, options) {
    const made = makeCtx(upstream.address().port, join(dir, name))
    made.ctx.webServer.getOrigin = () => `https://127.0.0.1:${upstream.address().port}`
    const gate = apply(made.ctx, { listenPort: 0, passwordHash: HASH, ...options })
    await gate.ready()
    gates.push(gate)
    return gate.address().port
  }
  for (const [name, options] of [
    ['untrusted', { upstreamServerName: 'upstream.test' }],
    ['wrong-name', { upstreamCaFile: certPath, upstreamServerName: 'wrong.test' }],
  ]) {
    const port = await openGate(name, options)
    const { cookie } = await login(port)
    assert.equal((await request(port, '/api/sessions', { headers: { cookie } })).res.status, 503)
  }
  const port = await openGate('trusted', { upstreamCaFile: certPath, upstreamServerName: 'upstream.test' })
  const { cookie } = await login(port)
  assert.equal((await request(port, '/api/sessions', { headers: { cookie } })).res.status, 200)
  const ws = await openWebSocket(port, cookie)
  assert.match(ws.text(), /HTTP\/1\.1 101/)
  ws.socket.destroy()
})

test('a synchronous launch URL error does not permanently cache a failed exchange', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream()
  const made = makeCtx(upstream.port, dir)
  let calls = 0
  made.ctx.connection.authenticatedUrl = (base) => {
    if (++calls === 1) throw new Error('simulated launch URL error')
    return base + '?token=launch-token'
  }
  const gate = apply(made.ctx, { listenPort: 0, passwordHash: HASH })
  await gate.ready()
  t.after(async () => { gate.stop(); made.dispose(); await upstream.close(); rmSync(dir, { recursive: true, force: true }) })
  const port = gate.address().port
  const { cookie } = await login(port)
  assert.equal((await request(port, '/api/sessions', { headers: { cookie } })).res.status, 503)
  assert.equal((await request(port, '/api/sessions', { headers: { cookie } })).res.status, 200)
  assert.equal(calls, 2)
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
  const strippedPort = await request(gate.port, '/api/sessions', {
    method: 'POST',
    headers: { cookie, host: '127.0.0.1', origin: 'http://127.0.0.1:' + gate.port },
    body: '{}',
  })
  assert.equal(strippedPort.res.status, 403)
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
  const strippedPort = await openWebSocket(gate.port, cookie, 'http://127.0.0.1:' + gate.port, '127.0.0.1')
  assert.match(strippedPort.text(), /HTTP\/1\.1 403/)
  strippedPort.socket.destroy()
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

test('malformed state is preserved instead of silently resetting credentials', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const dataDir = join(dir, 'data')
  mkdirSync(dataDir, { recursive: true })
  const path = join(dataDir, 'dsh-frontgate.json')
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const { ctx } = makeCtx(1, dir)
  for (const data of ['{"passwordHash":', '{}', JSON.stringify({ passwordHash: HASH, secret: 'short' })]) {
    writeFileSync(path, data, { mode: 0o600 })
    assert.throws(() => apply(ctx, { listenPort: 0, passwordHash: HASH }), /invalid state file/)
    assert.equal(readFileSync(path, 'utf8'), data)
  }
})

test('a state symlink is rejected', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const dataDir = join(dir, 'data')
  mkdirSync(dataDir, { recursive: true })
  const target = join(dir, 'state-target')
  writeFileSync(target, JSON.stringify({ passwordHash: HASH, secret: 'a'.repeat(64) }), { mode: 0o600 })
  symlinkSync(target, join(dataDir, 'dsh-frontgate.json'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  assert.throws(() => apply(makeCtx(1, dir).ctx, { passwordHash: HASH }), /regular file/)
})

test('permission failures reject exposed state but permit an already private file', async (t) => {
  if (process.platform === 'win32') return t.skip('POSIX mode test')
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const dataDir = join(dir, 'data')
  mkdirSync(dataDir, { recursive: true })
  const path = join(dataDir, 'dsh-frontgate.json')
  writeFileSync(path, JSON.stringify({ passwordHash: HASH, secret: 'a'.repeat(64) }))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const script = `
    import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module'; import { join } from 'node:path'
    fs.chmodSync = () => { const error = new Error('permission denied'); error.code = 'EPERM'; throw error }
    syncBuiltinESMExports()
    const { apply } = await import('./lib/index.js')
    const ctx = { profileContext: { patchPath: join(process.argv[1], 'cordis.patch.yml') },
      webServer: { getOrigin: () => 'http://127.0.0.1:1', tapIndex: () => () => {} },
      connection: { authenticatedUrl: url => url }, effect: fn => fn() }
    try { const gate = apply(ctx, { listenPort: 0 }); await gate.ready(); gate.stop() }
    catch (error) { console.error(error.message); process.exitCode = 1 }
  `
  const start = () => spawnSync(process.execPath, ['--input-type=module', '-e', script, dir], {
    cwd: new URL('..', import.meta.url), encoding: 'utf8',
  })
  chmodSync(path, 0o644)
  const exposed = start()
  assert.equal(exposed.status, 1)
  assert.match(exposed.stderr, /cannot secure state file permissions/)
  chmodSync(path, 0o600)
  assert.equal(start().status, 0)
})

test('failed atomic replacement leaves the original state intact', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const dataDir = join(dir, 'data')
  mkdirSync(dataDir, { recursive: true })
  const path = join(dataDir, 'dsh-frontgate.json')
  const original = JSON.stringify({ passwordHash: HASH, secret: 'a'.repeat(64) })
  writeFileSync(path, original, { mode: 0o600 })
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const script = `
    import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module'; import { join } from 'node:path'
    fs.renameSync = () => { throw new Error('simulated rename failure') }; syncBuiltinESMExports()
    const { apply } = await import('./lib/index.js')
    const ctx = { profileContext: { patchPath: join(process.argv[1], 'cordis.patch.yml') },
      webServer: { getOrigin: () => 'http://127.0.0.1:1', tapIndex: () => () => {} },
      connection: { authenticatedUrl: url => url }, effect: fn => fn() }
    try { apply(ctx, { password: 'a-new-strong-password' }) } catch (error) { console.error(error.message); process.exitCode = 1 }
  `
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script, dir], {
    cwd: new URL('..', import.meta.url), encoding: 'utf8',
  })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /simulated rename failure/)
  assert.equal(readFileSync(path, 'utf8'), original)
  assert.deepEqual(readdirSync(dataDir).sort(), ['dsh-frontgate.json', 'dsh-frontgate.json.lock.sqlite'])
})

test('a valid session survives a restart with the same state', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-'))
  const upstream = await startUpstream()
  const first = await startGate(upstream.port, dir)
  const { cookie } = await login(first.port)
  first.dispose()
  const second = await startGate(upstream.port, dir)
  t.after(async () => { second.dispose(); await upstream.close(); rmSync(dir, { recursive: true, force: true }) })
  assert.equal((await request(second.port, '/api/sessions', { headers: { cookie } })).res.status, 200)
})

test('unknown gate routes are not proxied', async (t) => {
  const { gate, upstream } = await withGate(t)
  const { res } = await request(gate.port, '/__gate/nope')
  assert.equal(res.status, 404)
  assert.equal(upstream.seen.length, 0)
})

