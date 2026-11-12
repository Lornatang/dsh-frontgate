import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import { tmpdir } from 'node:os'
import { delimiter, join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

const install = process.env.DSH_TEST_INSTALL_DIR
assert.ok(install, 'Set DSH_TEST_INSTALL_DIR to a directory containing the DSH and pnpm installations')
const root = fileURLToPath(new URL('..', import.meta.url))
const temp = mkdtempSync(join(tmpdir(), 'frontgate-dsh-integration-'))
const home = join(temp, 'home')
const dshHome = join(temp, 'dsh-home')
const dsh = join(install, 'node_modules', '.bin', 'dsh')
const password = 'integration-test-password'
const env = {
  HOME: home,
  DSH_HOME: dshHome,
  DSH_FRONTGATE_PASSWORD: password,
  PATH: join(install, 'node_modules', '.bin') + delimiter + process.env.PATH,
}
let server
let output = ''
try {
  mkdirSync(home, { recursive: true })
  assert.equal(execFileSync(dsh, ['--version'], { env, cwd: temp, encoding: 'utf8' }).trim(), '0.2.2-rc.2')
  const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', temp], {
    cwd: root, encoding: 'utf8',
  }))[0]
  execFileSync(dsh, ['plugin', '--profile', 'web', 'add', join(temp, packed.filename), '--registry=https://registry.npmjs.org/'], {
    env, cwd: temp, timeout: 120000, stdio: 'pipe',
  })
  const profile = join(dshHome, 'profiles', 'web')
  const profilePackage = JSON.parse(readFileSync(join(profile, 'package.json'), 'utf8'))
  assert.match(profilePackage.dependencies['@lornatang/dsh-frontgate'], /^file:/)
  assert.deepEqual(
    readFileSync(join(profile, 'node_modules', '@lornatang', 'dsh-frontgate', 'lib', 'index.js')),
    readFileSync(join(root, 'lib', 'index.js')),
    'DSH must load the package built in this workspace',
  )
  writeFileSync(join(profile, 'cordis.patch.yml'),
    "- id: frontgate\n  config:\n    listenHost: '127.0.0.1'\n    listenPort: 0\n")
  server = spawn(dsh, ['web', '--no-open', '--port', '0'], { env, cwd: temp, stdio: ['ignore', 'pipe', 'pipe'] })
  server.stdout.on('data', (chunk) => { output += chunk.toString() })
  server.stderr.on('data', (chunk) => { output += chunk.toString() })
  const started = Date.now()
  let port
  while (Date.now() - started < 60000) {
    port = Number(output.match(/\[dsh-frontgate\] listening on http:\/\/127\.0\.0\.1:(\d+)/)?.[1])
    if (port && output.includes('dsh web:')) break
    if (server.exitCode !== null || server.signalCode !== null) throw new Error('DSH exited during startup')
    await delay(100)
  }
  assert.ok(port && output.includes('dsh web:'), 'DSH and frontgate did not start')
  assert.equal(/dsh: warning: \d+ entr(?:y|ies) did not activate/i.test(output), false, 'a DSH plugin did not activate')
  const origin = 'http://127.0.0.1:' + port
  const login = await fetch(origin + '/__gate/login', {
    method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(10000),
    headers: { origin, 'content-type': 'application/x-www-form-urlencoded' },
    body: 'password=' + encodeURIComponent(password),
  })
  assert.equal(login.status, 303)
  const cookie = login.headers.getSetCookie()[0].split(';')[0]
  const page = await fetch(origin + '/', { headers: { cookie }, redirect: 'manual', signal: AbortSignal.timeout(10000) })
  assert.equal(page.status, 200)
  assert.match(await page.text(), /<html/i)
  assert.equal(page.headers.getSetCookie().length, 0)
  const filePath = join(temp, 'frontgate-cache-check.txt')
  writeFileSync(filePath, 'frontgate integration data')
  const file = await fetch(origin + '/api/file?path=' + encodeURIComponent(filePath), {
    headers: { cookie }, signal: AbortSignal.timeout(10000),
  })
  assert.equal(file.status, 200)
  assert.equal(file.headers.get('cache-control'), 'private, no-store')
  assert.equal(await file.text(), 'frontgate integration data')
  const websocket = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: '/api/remote.mux', timeout: 10000, headers: {
      origin, cookie, connection: 'Upgrade', upgrade: 'websocket',
      'sec-websocket-version': '13', 'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
    } })
    req.once('upgrade', (response, socket) => resolve({ response, socket }))
    req.once('response', (response) => { response.resume(); reject(new Error('DSH upgrade returned ' + response.statusCode)) })
    req.once('error', reject)
    req.once('timeout', () => req.destroy(new Error('DSH upgrade timed out')))
    req.end()
  })
  try {
    assert.equal(websocket.response.statusCode, 101)
    assert.equal(websocket.response.headers['set-cookie'], undefined)
    websocket.socket.on('error', () => {})
    websocket.socket.on('data', () => {})
    await delay(5000)
    assert.equal(websocket.socket.destroyed, false, 'DSH websocket closed during idle observation')
  } finally { websocket.socket.destroy() }
  const logout = await fetch(origin + '/__gate/logout', {
    headers: { cookie }, redirect: 'manual', signal: AbortSignal.timeout(10000),
  })
  assert.equal(logout.status, 302)
  assert.equal(logout.headers.get('clear-site-data'), '"cache"')
  const revokedFile = await fetch(file.url, { headers: { cookie }, signal: AbortSignal.timeout(10000) })
  assert.equal(revokedFile.status, 401)
  process.stdout.write('DSH 0.2.2-rc.2 login, file cache, logout and idle WebSocket checks passed.\n')
} catch (error) {
  // Never print the launch URL or generated credentials on a failed run.
  const safe = output.split('\n').filter((line) => line.startsWith('[dsh-frontgate]') && !line.includes('PASSWORD:'))
  if (safe.length) process.stderr.write(safe.join('\n') + '\n')
  throw error
} finally {
  if (server && server.exitCode === null && server.signalCode === null) {
    const exited = new Promise((resolve) => server.once('exit', resolve))
    server.kill('SIGTERM')
    await Promise.race([exited, delay(5000)])
    if (server.exitCode === null && server.signalCode === null) { server.kill('SIGKILL'); await exited }
  }
  rmSync(temp, { recursive: true, force: true })
}
