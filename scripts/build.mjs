import { build } from 'esbuild'
import { execFileSync } from 'node:child_process'
import { mkdirSync, rmSync } from 'node:fs'

const root = new URL('..', import.meta.url)
rmSync(new URL('lib', root), { recursive: true, force: true })

await build({
  entryPoints: [new URL('src/index.ts', root).pathname],
  outfile: new URL('lib/index.js', root).pathname,
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node22',
  sourcemap: false,
  legalComments: 'none',
  external: ['@deepseek-ai/cordis', '@deepseek-ai/schemastery'],
  logLevel: 'warning',
})

mkdirSync(new URL('lib/types', root), { recursive: true })
execFileSync('tsc', ['-p', new URL('tsconfig.json', root).pathname], { stdio: 'inherit', cwd: new URL('..', root).pathname })
