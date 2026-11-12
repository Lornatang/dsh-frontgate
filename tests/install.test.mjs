import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

test('installer creates the web profile and resolves the current tag on each update', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'frontgate-install-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const bin = join(dir, 'bin')
  const dshHome = join(dir, 'dsh')
  const calls = join(dir, 'calls.jsonl')
  mkdirSync(bin)

  writeFileSync(join(bin, 'git'), `#!/usr/bin/env node
    console.log('a'.repeat(40) + '\\trefs/tags/v0.1.0')
    console.log(process.env.TEST_COMMIT + '\\trefs/tags/v0.1.0^{}')
  `, { mode: 0o755 })
  writeFileSync(join(bin, 'dsh'), `#!/usr/bin/env node
    const fs = require('node:fs')
    const path = require('node:path')
    const args = process.argv.slice(2)
    fs.appendFileSync(process.env.TEST_CALLS, JSON.stringify(args) + '\\n')
    const profile = args[0] === 'plugin' ? args[2] : args[0]
    const profileDir = path.join(process.env.DSH_HOME, 'profiles', profile)
    fs.mkdirSync(profileDir, { recursive: true })
    const file = path.join(profileDir, 'package.json')
    const pkg = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {
      dsh: { profile: { bundles: ['@deepseek-ai/dsh-web-app'] } },
    }
    if (args[0] === 'plugin' && !pkg.dsh.profile.bundles.includes('dsh-frontgate')) {
      pkg.dsh.profile.bundles.push('dsh-frontgate')
    }
    fs.writeFileSync(file, JSON.stringify(pkg))
  `, { mode: 0o755 })

  const run = (commit) => spawnSync('bash', [new URL('../install.sh', import.meta.url).pathname], {
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: bin + ':' + process.env.PATH,
      DSH_HOME: dshHome,
      DSH_FRONTGATE_PROFILE: 'web',
      TEST_CALLS: calls,
      TEST_COMMIT: commit,
    },
  })

  const firstCommit = 'b'.repeat(40)
  const first = run(firstCommit)
  assert.equal(first.status, 0, first.stderr)
  const savedState = join(dshHome, 'profiles', 'web', 'data', 'dsh-frontgate.json')
  mkdirSync(join(dshHome, 'profiles', 'web', 'data'))
  writeFileSync(savedState, 'existing state')

  const secondCommit = 'c'.repeat(40)
  const second = run(secondCommit)
  assert.equal(second.status, 0, second.stderr)
  assert.equal(readFileSync(savedState, 'utf8'), 'existing state')

  const entries = readFileSync(calls, 'utf8').trim().split('\n').map(JSON.parse)
  assert.deepEqual(entries[0], ['web', '--help'])
  assert.deepEqual(entries.filter(args => args[0] === 'plugin').map(args => args[4]), [
    'https://codeload.github.com/Lornatang/dsh-frontgate/tar.gz/' + firstCommit,
    'https://codeload.github.com/Lornatang/dsh-frontgate/tar.gz/' + secondCommit,
  ])
})
