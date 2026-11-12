import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const root = new URL('..', import.meta.url)
const manifest = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'))
const packageRef = manifest.name + '@' + manifest.version

test('the DSH bundle loads the published package name', () => {
  const patch = readFileSync(new URL('cordis.patch.yml', root), 'utf8')
  assert.ok(patch.includes("name: '" + manifest.name + "'"))
  assert.equal(manifest.dsh.bundle.patch, './cordis.patch.yml')
})

function installer(t) {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-install-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const bin = join(dir, 'bin')
  const dshHome = join(dir, 'dsh')
  const calls = join(dir, 'calls.jsonl')
  mkdirSync(bin)
  writeFileSync(join(bin, 'dsh'), `#!/usr/bin/env node
    const fs = require('node:fs')
    const path = require('node:path')
    const args = process.argv.slice(2)
    fs.appendFileSync(process.env.TEST_CALLS, JSON.stringify(args) + '\\n')
    if (args[0] === 'plugin' && process.env.TEST_FAIL_INSTALL) process.exit(23)
    const profile = args[0] === 'plugin' ? args[2] : args[0]
    const profileDir = path.join(process.env.DSH_HOME, 'profiles', profile)
    fs.mkdirSync(profileDir, { recursive: true })
    const file = path.join(profileDir, 'package.json')
    const pkg = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {
      dsh: { profile: { bundles: ['@deepseek-ai/dsh-web-app'] } },
    }
    if (args[0] === 'plugin' && !pkg.dsh.profile.bundles.includes('@lornatang/dsh-frontgate')) {
      pkg.dsh.profile.bundles.push('@lornatang/dsh-frontgate')
    }
    fs.writeFileSync(file, JSON.stringify(pkg))
  `, { mode: 0o755 })
  return {
    dshHome,
    calls: () => readFileSync(calls, 'utf8').trim().split('\n').map(JSON.parse),
    run: (args = [], env = {}) => spawnSync('bash', [new URL('../install.sh', import.meta.url).pathname, ...args], {
      encoding: 'utf8',
      env: { ...process.env, PATH: bin + ':' + process.env.PATH, DSH_HOME: dshHome, DSH_FRONTGATE_PROFILE: 'web', TEST_CALLS: calls, ...env },
    }),
  }
}

test('default install and update use the package version and preserve state', (t) => {
  const setup = installer(t)
  const first = setup.run()
  assert.equal(first.status, 0, first.stderr)
  const data = join(setup.dshHome, 'profiles', 'web', 'data')
  mkdirSync(data)
  const state = join(data, 'dsh-frontgate.json')
  writeFileSync(state, 'existing state')
  const second = setup.run()
  assert.equal(second.status, 0, second.stderr)
  assert.equal(readFileSync(state, 'utf8'), 'existing state')
  assert.deepEqual(setup.calls(), [
    ['plugin', '--profile', 'web', 'add', packageRef],
    ['plugin', '--profile', 'web', 'add', packageRef],
  ])
  assert.ok(readFileSync(new URL('README.md', root), 'utf8').includes('add ' + manifest.name))
})

test('a new custom profile is initialized from the web template once', (t) => {
  const setup = installer(t)
  assert.equal(setup.run(['--profile', 'my-web']).status, 0)
  assert.equal(setup.run([], { DSH_FRONTGATE_PROFILE: 'my-web' }).status, 0)
  assert.deepEqual(setup.calls(), [
    ['my-web', '--from-default-profile', 'web', '--help'],
    ['plugin', '--profile', 'my-web', 'add', packageRef],
    ['plugin', '--profile', 'my-web', 'add', packageRef],
  ])
})

test('an incomplete custom profile is not replaced', (t) => {
  const setup = installer(t)
  const profile = join(setup.dshHome, 'profiles', 'my-web')
  mkdirSync(profile, { recursive: true })
  const patch = join(profile, 'cordis.patch.yml')
  writeFileSync(patch, 'existing configuration')
  const result = setup.run(['--profile', 'my-web'])
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /exists without package.json/)
  assert.equal(readFileSync(patch, 'utf8'), 'existing configuration')
})

test('legacy packages are not silently installed alongside the scoped package', (t) => {
  const setup = installer(t)
  const profile = join(setup.dshHome, 'profiles', 'web')
  mkdirSync(profile, { recursive: true })
  const file = join(profile, 'package.json')
  const original = JSON.stringify({ dependencies: { 'dsh-frontgate': '0.1.1' } })
  writeFileSync(file, original)
  const result = setup.run()
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /legacy dsh-frontgate detected/)
  assert.equal(readFileSync(file, 'utf8'), original)
})

test('installer returns failure when DSH cannot install the archive', (t) => {
  const setup = installer(t)
  const result = setup.run([], { TEST_FAIL_INSTALL: '1' })
  assert.equal(result.status, 23)
  assert.doesNotMatch(result.stdout, /is installed/)
})

test('invalid profile arguments are refused', (t) => {
  const setup = installer(t)
  for (const args of [['--profile'], ['--profile', '../outside'], ['--profile', '..'], ['--profile', '--help'], ['--unknown']]) {
    assert.notEqual(setup.run(args).status, 0)
  }
})
