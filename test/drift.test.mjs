// doctor_drift: 源码改了 ≠ 运行时改了。
//
// 这些测试都在临时目录里造「源 vs profile 里的拷贝」，不碰真实 profile。
// 每条「必须红」的旁边都有一条「必须绿」的对照 —— 只有红没有绿，说明不了检查是对的。
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const { analyzeDrift } = await import('../dist/index.js')

const roots = []

/**
 * 造一个 profile + 一个源包。
 * @param {{spec: 'file'|'link', source: Record<string,string>, installed: Record<string,string>|null, files?: string[]}} o
 */
function fixture(o) {
  const root = mkdtempSync(join(tmpdir(), 'drift-'))
  roots.push(root)
  const src = join(root, 'src')
  const profile = join(root, 'profile')
  mkdirSync(src, { recursive: true })
  mkdirSync(join(profile, 'node_modules'), { recursive: true })
  writeFileSync(join(src, 'package.json'), JSON.stringify({ name: '@x/y', version: '1.0.0', files: o.files ?? ['index.js'] }))
  for (const [rel, body] of Object.entries(o.source)) {
    const p = join(src, rel)
    mkdirSync(join(p, '..'), { recursive: true })
    writeFileSync(p, body)
  }
  writeFileSync(
    join(profile, 'package.json'),
    JSON.stringify({ name: 'profile', dependencies: { '@x/y': `${o.spec}:${src.replace(/\\/g, '/')}` } }, null, 2),
  )
  const dst = join(profile, 'node_modules', '@x', 'y')
  if (o.spec === 'link') {
    mkdirSync(join(profile, 'node_modules', '@x'), { recursive: true })
    symlinkSync(o.installedLink ?? src, dst, 'junction')
  } else if (o.installed !== null) {
    mkdirSync(dst, { recursive: true })
    writeFileSync(join(dst, 'package.json'), JSON.stringify({ name: '@x/y', version: '1.0.0', files: o.files ?? ['index.js'] }))
    for (const [rel, body] of Object.entries(o.installed)) writeFileSync(join(dst, rel), body)
  }
  return { root, profile, src, dst }
}

test.after(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true })
})

test('an identical copy is reported clean (must-accept control)', async () => {
  const f = fixture({ spec: 'file', source: { 'index.js': 'export const a = 1\n' }, installed: { 'index.js': 'export const a = 1\n' } })
  const r = await analyzeDrift(f.profile)
  assert.equal(r.checked, 1)
  assert.equal(r.issues.length, 0)
  assert.equal(r.verdict, 'SAFE')
  assert.equal(r.deps[0].state, 'ok')
})

test('a stale copy is reported with the differing file and the fix (must-reject)', async () => {
  // 这正是 2026-11-06 实测到的形状：源码新、拷贝旧、pnpm install 认为已满足。
  const f = fixture({ spec: 'file', source: { 'index.js': 'export const VERSION = 2\n' }, installed: { 'index.js': 'export const VERSION = 1\n' } })
  const r = await analyzeDrift(f.profile)
  assert.equal(r.verdict, 'HIGH')
  assert.equal(r.issues.length, 1)
  const d = r.deps[0]
  assert.equal(d.state, 'stale')
  assert.deepEqual(d.differs, ['index.js'])
  assert.match(d.detail, /delete node_modules\/@x\/y/, 'the report must name the fix that actually works')
  assert.match(d.detail, /pnpm install|dsh plugin --profile/, 'and say that install is the second half')
})

test('a missing copy is not silently treated as ok', async () => {
  const f = fixture({ spec: 'file', source: { 'index.js': 'x\n' }, installed: null })
  const r = await analyzeDrift(f.profile)
  assert.equal(r.deps[0].state, 'missing')
  assert.equal(r.verdict, 'HIGH')
})

test('the files[] allowlist is respected: drift outside the published surface is not a finding', async () => {
  // 必须绿：改一个不会被发布的文件（这里 files=index.js），不算漂移
  const f = fixture({
    spec: 'file',
    files: ['index.js'],
    source: { 'index.js': 'same\n', 'notes.md': 'source notes\n' },
    installed: { 'index.js': 'same\n', 'notes.md': 'old notes\n' },
  })
  const r = await analyzeDrift(f.profile)
  assert.equal(r.deps[0].state, 'ok', 'notes.md is outside files[], so it is not part of the published surface')
})

test('a link: dependency is ok only when it really points at the source', async () => {
  const ok = fixture({ spec: 'link', source: { 'index.js': 'x\n' } })
  assert.equal((await analyzeDrift(ok.profile)).deps[0].state, 'ok')

  const other = mkdtempSync(join(tmpdir(), 'drift-other-'))
  roots.push(other)
  const bad = fixture({ spec: 'link', source: { 'index.js': 'x\n' }, installedLink: other })
  const r = await analyzeDrift(bad.profile)
  assert.equal(r.deps[0].state, 'wrong-link')
  assert.equal(r.verdict, 'HIGH')
})

test('docs-only drift is reported but not as a failure (calibration)', async () => {
  // 实测 2026-11-06：第一次真跑，「过期」的两包都只是 LICENSE / README 不同 —— 代码是同版本。
  // 把它报成 HIGH 会训练人忽略这个检查，所以它是 LOW，且文案要说清「跑的代码没变」。
  const f = fixture({
    spec: 'file',
    files: ['index.js', 'LICENSE'],
    source: { 'index.js': 'same\n', LICENSE: 'MIT new\n' },
    installed: { 'index.js': 'same\n' },
  })
  const r = await analyzeDrift(f.profile)
  assert.equal(r.deps[0].state, 'docs-only')
  assert.equal(r.verdict, 'LOW')
  assert.match(r.deps[0].detail, /the running code is the same copy/)

  // 对照：同一个 fixture，只让代码不同 → 必须升级成 HIGH
  const g = fixture({
    spec: 'file',
    files: ['index.js', 'LICENSE'],
    source: { 'index.js': 'v2\n', LICENSE: 'MIT new\n' },
    installed: { 'index.js': 'v1\n' },
  })
  const r2 = await analyzeDrift(g.profile)
  assert.equal(r2.deps[0].state, 'stale')
  assert.equal(r2.verdict, 'HIGH')
})

test('the startup warning fires for CODE drift and stays silent otherwise', async () => {
  // 这条检查被做成「启动时自己跑」而不是「文档里写着」：文档 09-27 就写了同一件事，
  // 2026-11-06 我仍然差点宣称「已生效」。机制要在那一秒响，而那一秒永远是启动。
  const { driftWarning } = await import('../dist/index.js')

  const stale = fixture({ spec: 'file', source: { 'index.js': 'v2\n' }, installed: { 'index.js': 'v1\n' } })
  const w = driftWarning(await analyzeDrift(stale.profile))
  assert.ok(w, 'stale code must produce a warning')
  assert.match(w, /@x\/y/, 'the warning names the package')
  assert.match(w, /delete node_modules/, 'and the fix that works')

  const docs = fixture({ spec: 'file', files: ['index.js', 'LICENSE'], source: { 'index.js': 'x\n', LICENSE: 'new\n' }, installed: { 'index.js': 'x\n' } })
  assert.equal(driftWarning(await analyzeDrift(docs.profile)), undefined, 'docs-only drift must not warn at startup')

  const clean = fixture({ spec: 'file', source: { 'index.js': 'same\n' }, installed: { 'index.js': 'same\n' } })
  assert.equal(driftWarning(await analyzeDrift(clean.profile)), undefined, 'a clean profile must not warn')
})

test('non file:/link: dependencies are ignored', async () => {
  const root = mkdtempSync(join(tmpdir(), 'drift-plain-'))
  roots.push(root)
  const profile = join(root, 'profile')
  mkdirSync(profile, { recursive: true })
  writeFileSync(join(profile, 'package.json'), JSON.stringify({ dependencies: { react: '^19.0.0', '@x/y': 'file:./nope' } }))
  const r = await analyzeDrift(profile)
  assert.equal(r.checked, 1, 'react is not a file: dependency')
  assert.equal(r.deps[0].state, 'missing')
})
