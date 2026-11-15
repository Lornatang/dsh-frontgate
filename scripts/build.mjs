import { build } from 'esbuild'
import { execFileSync } from 'node:child_process'
import { mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const resolve = (path) => join(root, path)

rmSync(resolve('lib'), { recursive: true, force: true })

await build({
  entryPoints: [resolve('src/index.ts')],
  outfile: resolve('lib/index.js'),
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node22',
  sourcemap: false,
  legalComments: 'none',
  external: ['@deepseek-ai/cordis', '@deepseek-ai/schemastery'],
  logLevel: 'warning',
})

mkdirSync(resolve('lib/types'), { recursive: true })
execFileSync(process.execPath, [resolve('node_modules/typescript/bin/tsc'), '-p', resolve('tsconfig.json')], { stdio: 'inherit', cwd: root })
