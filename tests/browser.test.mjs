import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import https from 'node:https'
import { createHash } from 'node:crypto'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { apply } from '../lib/index.js'

const chromePath = process.env.CHROME_PATH || [
  '/usr/bin/google-chrome', '/usr/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].find((path) => existsSync(path))
const browserOptions = { timeout: 30000, skip: !chromePath && !process.env.CI ? 'Chrome not installed' : false }
const password = 'browser-test-password'
const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const close = (server) => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve) })

function startGate(dir, upstream, extra = {}) {
  const ctx = {
    profileContext: { patchPath: join(dir, 'cordis.patch.yml') },
    webServer: { getOrigin: () => `http://127.0.0.1:${upstream.address().port}`, tapIndex: () => () => {} },
    connection: { authenticatedUrl: (base) => `${base}?token=mock` },
    effect: (fn) => fn(),
  }
  return apply(ctx, { listenPort: 0, password, ...extra })
}

function makeUpstream({ upgradeCookie = false } = {}) {
  let postReceived = false
  let upgradeReceived = false
  const sockets = new Set()
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/?token=')) {
      res.writeHead(303, { 'set-cookie': 'dsh-auth=mock; Path=/' })
      return res.end()
    }
    if (req.method === 'POST') postReceived = true
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<!doctype html><title>Mock harness</title><p>Signed in</p>')
  })
  server.on('upgrade', (req, socket) => {
    upgradeReceived = true
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    const accept = createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
    const cookie = upgradeCookie ? 'Set-Cookie: upstream_leak=secret; HttpOnly; Path=/\r\n' : ''
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' + cookie + 'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n')
  })
  return {
    server,
    postReceived: () => postReceived,
    upgradeReceived: () => upgradeReceived,
    close: async () => { for (const socket of sockets) socket.destroy(); await close(server) },
  }
}

async function startBrowser(dir) {
  assert.ok(chromePath && existsSync(chromePath), 'Chrome is required in CI; set CHROME_PATH')
  const chrome = spawn(chromePath, [
    '--headless=new', '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--no-proxy-server',
    '--ignore-certificate-errors', '--host-resolver-rules=MAP gate.test 127.0.0.1',
    '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0',
    `--user-data-dir=${join(dir, 'chrome')}`, 'about:blank',
  ], { stdio: 'ignore' })
  try {
    let port
    for (let i = 0; i < 150; i++) {
      try {
        const candidate = Number(readFileSync(join(dir, 'chrome', 'DevToolsActivePort'), 'utf8').split('\n')[0])
        if (Number.isInteger(candidate) && candidate > 0) { port = candidate; break }
      } catch {}
      await delay(100)
    }
    assert.ok(port, 'Chrome debugging endpoint unavailable')
    const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json()
    const socket = new WebSocket(target.webSocketDebuggerUrl)
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true })
      socket.addEventListener('error', reject, { once: true })
    })
    const pending = new Map()
    const events = new Map()
    let id = 0
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(event.data)
      if (message.id && pending.has(message.id)) {
        const { resolve, reject } = pending.get(message.id)
        pending.delete(message.id)
        if (message.error) reject(new Error(message.error.message))
        else resolve(message.result)
      }
      if (message.method && events.has(message.method)) {
        const resolve = events.get(message.method)
        events.delete(message.method)
        resolve(message.params)
      }
    })
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const next = ++id
      pending.set(next, { resolve, reject })
      socket.send(JSON.stringify({ id: next, method, params }))
    })
    const loaded = () => new Promise((resolve) => events.set('Page.loadEventFired', resolve))
    const wait = async (promise) => {
      let timer
      try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('browser timeout')), 10000) })]) }
      finally { clearTimeout(timer) }
    }
    await send('Page.enable')
    return {
      async navigate(url) { const done = loaded(); await send('Page.navigate', { url }); await wait(done) },
      async cookies() { return (await send('Network.getAllCookies')).cookies },
      async evaluate(expression) {
        const result = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
        if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails))
        return result.result.value
      },
      async submit(expression) { const done = loaded(); await send('Runtime.evaluate', { expression }); await wait(done) },
      async close() { socket.close(); chrome.kill('SIGTERM'); await delay(250) },
    }
  } catch (error) {
    chrome.kill('SIGTERM')
    throw error
  }
}

test('browser login succeeds and cross-port form and WebSocket attacks are refused', browserOptions, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-browser-'))
  const upstream = makeUpstream()
  await listen(upstream.server)
  const gate = startGate(dir, upstream.server)
  await gate.ready()
  const port = gate.address().port
  let cookieReachedOtherPort = false
  const attacker = http.createServer((req, res) => {
    cookieReachedOtherPort ||= /(?:^|;\s*)dsh_gate=/.test(req.headers.cookie || '')
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(`<!doctype html><form method="POST" action="http://127.0.0.1:${port}/api/mutate"><input name="action" value="test"></form>`)
  })
  await listen(attacker)
  let browser
  t.after(async () => {
    await browser?.close()
    gate.stop()
    await close(attacker)
    await upstream.close()
    rmSync(dir, { recursive: true, force: true, maxRetries: 3 })
  })
  browser = await startBrowser(dir)
  await browser.navigate(`http://127.0.0.1:${port}/__gate/login`)
  await browser.submit(`document.querySelector('input[name="password"]').value=${JSON.stringify(password)}; document.querySelector('form').requestSubmit()`)
  assert.match(await browser.evaluate('document.body.innerText'), /Signed in/)
  await browser.navigate(`http://127.0.0.1:${attacker.address().port}/`)
  // This deliberately demonstrates why a separate host/IP is required.
  assert.equal(cookieReachedOtherPort, true)
  const wsOpened = await browser.evaluate(`new Promise(resolve => { const ws = new WebSocket('ws://127.0.0.1:${port}/ws'); ws.onopen = () => { ws.close(); resolve(true) }; ws.onerror = () => resolve(false) })`)
  assert.equal(wsOpened, false)
  await browser.submit("document.querySelector('form').requestSubmit()")
  assert.match(await browser.evaluate('document.body.innerText'), /forbidden/)
  assert.equal(upstream.postReceived(), false)
  assert.equal(upstream.upgradeReceived(), false)
})

test('browser websocket stays open without receiving an upstream cookie', browserOptions, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-browser-upgrade-'))
  const upstream = makeUpstream({ upgradeCookie: true })
  await listen(upstream.server)
  const gate = startGate(dir, upstream.server)
  await gate.ready()
  const port = gate.address().port
  let browser
  t.after(async () => {
    await browser?.close()
    gate.stop()
    await upstream.close()
    rmSync(dir, { recursive: true, force: true, maxRetries: 3 })
  })
  browser = await startBrowser(dir)
  await browser.navigate(`http://127.0.0.1:${port}/__gate/login`)
  await browser.submit(`document.querySelector('input[name="password"]').value=${JSON.stringify(password)}; document.querySelector('form').requestSubmit()`)
  const stayedOpen = await browser.evaluate(`new Promise(resolve => {
    const ws = new WebSocket('ws://127.0.0.1:${port}/ws')
    ws.onopen = () => setTimeout(() => { const open = ws.readyState === WebSocket.OPEN; ws.close(); resolve(open) }, 300)
    ws.onerror = () => resolve(false)
  })`)
  assert.equal(stayedOpen, true)
  assert.equal(upstream.upgradeReceived(), true)
  const cookies = await browser.cookies()
  assert.equal(cookies.some((cookie) => cookie.name === 'dsh_gate'), true)
  assert.equal(cookies.some((cookie) => cookie.name === 'upstream_leak'), false)
})

test('logout clears an older cached protected file in a trustworthy browser origin', browserOptions, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-browser-cache-'))
  const upstream = makeUpstream()
  await listen(upstream.server)
  const oldGate = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'private, max-age=31536000, immutable' })
    res.end('previously cached private data')
  })
  await listen(oldGate)
  const port = oldGate.address().port
  const origin = `http://127.0.0.1:${port}`
  const file = origin + '/api/file?path=%2Ftmp%2Fprivate.txt&v=1'
  let browser
  let gate
  t.after(async () => {
    await browser?.close()
    gate?.stop()
    if (oldGate.listening) await close(oldGate)
    await upstream.close()
    rmSync(dir, { recursive: true, force: true, maxRetries: 3 })
  })
  browser = await startBrowser(dir)
  await browser.navigate(file)
  assert.match(await browser.evaluate('document.body.innerText'), /previously cached private data/)
  await close(oldGate)
  gate = startGate(dir, upstream.server, { listenPort: port })
  await gate.ready()
  await browser.navigate(origin + '/__gate/login')
  await browser.submit(`document.querySelector('input[name="password"]').value=${JSON.stringify(password)}; document.querySelector('form').requestSubmit()`)
  await browser.navigate(origin + '/__gate/logout')
  await browser.navigate(file)
  assert.match(await browser.evaluate('document.body.innerText'), /unauthorized/)
})

test('browser login succeeds when the external and listener ports differ', browserOptions, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-browser-port-'))
  const upstream = makeUpstream()
  await listen(upstream.server)
  const gate = startGate(dir, upstream.server, { listenHost: '0.0.0.0' })
  await gate.ready()
  const proxy = http.createServer((req, res) => {
    const target = http.request({ host: '127.0.0.1', port: gate.address().port, path: req.url, method: req.method, headers: req.headers }, response => {
      res.writeHead(response.statusCode, response.headers)
      response.pipe(res)
    })
    target.on('error', () => res.destroy())
    req.pipe(target)
  })
  await listen(proxy)
  let browser
  t.after(async () => {
    await browser?.close()
    gate.stop()
    await close(proxy)
    await upstream.close()
    rmSync(dir, { recursive: true, force: true, maxRetries: 3 })
  })
  browser = await startBrowser(dir)
  await browser.navigate(`http://127.0.0.1:${proxy.address().port}/__gate/login`)
  await browser.submit(`document.querySelector('input[name="password"]').value=${JSON.stringify(password)}; document.querySelector('form').requestSubmit()`)
  assert.match(await browser.evaluate('document.body.innerText'), /Signed in/)
})

test('HTTPS-terminating proxy issues a Secure cookie that is not sent over HTTP', browserOptions, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-browser-tls-'))
  const cert = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-days', '1', '-subj', '/CN=gate.test'], { stdio: 'ignore' })
  assert.equal(cert.status, 0, 'openssl is required for the HTTPS test')
  const upstream = makeUpstream()
  await listen(upstream.server)
  let gate
  let loginCookie = ''
  const proxy = https.createServer({ key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) }, (req, res) => {
    const target = http.request({ host: '127.0.0.1', port: gate.address().port, path: req.url, method: req.method, headers: req.headers }, (response) => {
      if (req.method === 'POST' && req.url.startsWith('/__gate/login')) loginCookie = (response.headers['set-cookie'] || [])[0] || ''
      res.writeHead(response.statusCode, response.headers)
      response.pipe(res)
    })
    target.on('error', () => res.destroy())
    req.pipe(target)
  })
  await listen(proxy)
  gate = startGate(dir, upstream.server, { publicOrigin: `https://gate.test:${proxy.address().port}` })
  await gate.ready()
  let cookieReachedHttp = false
  const other = http.createServer((req, res) => {
    cookieReachedHttp ||= /(?:^|;\s*)dsh_gate=/.test(req.headers.cookie || '')
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<!doctype html><title>HTTP service</title>')
  })
  await listen(other)
  let browser
  t.after(async () => {
    await browser?.close()
    gate.stop()
    await close(proxy)
    await close(other)
    await upstream.close()
    rmSync(dir, { recursive: true, force: true, maxRetries: 3 })
  })
  browser = await startBrowser(dir)
  await browser.navigate(`https://gate.test:${proxy.address().port}/__gate/login`)
  await browser.submit(`document.querySelector('input[name="password"]').value=${JSON.stringify(password)}; document.querySelector('form').requestSubmit()`)
  assert.match(await browser.evaluate('document.body.innerText'), /Signed in/)
  assert.match(loginCookie, /; Secure(?:;|$)/)
  await browser.navigate(`http://gate.test:${other.address().port}/`)
  assert.equal(cookieReachedHttp, false)
})
