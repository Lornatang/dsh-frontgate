import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const temp = mkdtempSync(join(tmpdir(), 'frontgate-package-'))
try {
  const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', temp], {
    cwd: root, encoding: 'utf8',
  }))[0]
  assert.ok(packed.files.some((entry) => entry.path === 'lib/index.js'), 'built entry point missing from package')
  assert.ok(packed.files.some((entry) => entry.path === 'cordis.patch.yml'), 'DSH patch missing from package')
  writeFileSync(join(temp, 'package.json'), '{"name":"frontgate-package-smoke-test","private":true,"type":"module"}\n')
  execFileSync('npm', ['install', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', join(temp, packed.filename)], {
    cwd: temp, stdio: 'inherit',
  })
  const smoke = `
    import assert from 'node:assert/strict'
    import { apply, Config } from '@lornatang/dsh-frontgate'
    import { join } from 'node:path'
    const ctx = {
      profileContext: { patchPath: join(process.cwd(), 'cordis.patch.yml') },
      webServer: { getOrigin: () => 'http://127.0.0.1:3080', tapIndex: () => () => {} },
      connection: { authenticatedUrl: url => url }, effect: fn => fn(),
    }
    assert.equal(Config.dict.upstreamIdleTimeoutMs.meta.default, 0)
    const gate = apply(ctx, { listenPort: 0, password: 'package-test-password' })
    try {
      await gate.ready()
      const res = await fetch('http://127.0.0.1:' + gate.address().port + '/__gate/health')
      assert.equal(res.status, 200)
      assert.equal((await res.json()).service, 'dsh-frontgate')
    } finally { gate.stop() }
  `
  execFileSync(process.execPath, ['--input-type=module', '-e', smoke], { cwd: temp, stdio: 'inherit' })
  process.stdout.write('Installed package smoke test passed.\n')
} finally {
  rmSync(temp, { recursive: true, force: true })
}
