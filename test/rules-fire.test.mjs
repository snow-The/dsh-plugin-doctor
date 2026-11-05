// 反向量测：每一条规则都必须能被一句「应该要红」的样本打红。
//
// 来源：GAS 2026-11-06 的信里那条可移植的坑 —— 他们的 `both-axes-wrong` 规则 allow 收了裸
// 「錯」而 deny 也在找「錯」，**规则从设计上就不可能红**，却绿了很久，而且「死规则」在输出上
// 跟「通过」长得一模一样。他们的数字是 6/18（18 句该红的改写只抓到 6 条）。
//
// 这里做同一件事：13 条规则，每条配一句必然该命中的样本，跑真工具，数几条真的红。
// 样本写错也会让规则不响，所以下面 `SAMPLES` 的注释写的是「这条样本为什么必然命中这个正则」，
// 若某条不响，先看注释再决定是样本错还是规则死。
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const { apply } = await import('../dist/index.js')

/** 每条规则一句必然命中的样本（右列是它命中的原因）。 */
const SAMPLES = {
  'exfil-http': 'const u = "https://evil.example.com/x"\n', // 非 localhost 的 https://
  'exfil-shell-net': 'execSync("curl http://example.com")\n', // \bcurl\b
  'exfil-fetch': "fetch('http://example.com/x')\n", // fetch( 后接协议
  'cred-secrets': "const k = readFileSync(home + '/.ssh/id_rsa')\n", // .ssh 与 id_rsa 都命中
  'cred-env-harvest': 'const all = Object.keys(process.env)\n', // Object.keys(process.env)
  'obf-eval': 'const v = eval("2+2")\n', // \beval\s*\(
  'obf-base64': `const blob = '${'A'.repeat(220)}'\n`, // 220 个 base64 字符
  'obf-hidden-unicode': 'const s = "a\u200bb"\n', // U+200B 零宽空格
  'persist-registry': 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v X\n', // reg add
  'persist-startup': 'schtasks /create /tn X /tr y\n', // schtasks
  'persist-shellrc': 'echo "x" >> ~/.bashrc\n', // bashrc >>
  'destructive-rm': 'rm -rf /\n', // rm -rf /
  'destructive-git': 'git push --force origin main\n', // --force
}

function makeCtx() {
  const tools = []
  tools.register = (t) => tools.push(t)
  return { tools }
}

test('every rule can actually fire on a sample that should be caught', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'rules-'))
  try {
    // 一个文件装一条样本，避免互相干扰，也方便定位是谁没响
    for (const [rule, body] of Object.entries(SAMPLES)) {
      mkdirSync(join(dir, 'src'), { recursive: true })
      writeFileSync(join(dir, 'src', `${rule}.js`), body)
    }
    const ctx = makeCtx()
    apply(ctx)
    const tool = ctx.tools.find((t) => t.name === 'doctor_scan')
    const res = await tool.execute({ path: dir })
    // 结果形状：hits 是**数字**，明细在 results[].hits[]（byRule 是 rule -> 次数）
    const fired = new Set(res.results.flatMap((r) => r.hits.map((h) => h.rule)))
    const dead = Object.keys(SAMPLES).filter((r) => !fired.has(r))

    assert.deepEqual(dead, [], `these rules produced no hit for a sample that should match: ${dead.join(', ')}`)
    // 样本数 = 规则数，防止有人加了规则却忘了加样本（沉默的规则等于没有）
    assert.equal(Object.keys(SAMPLES).length, 13, 'update SAMPLES/hits when a rule is added or removed')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('the widened shellrc rule catches the real forms and ignores plain mentions (both directions)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'rules-shellrc-'))
  try {
    mkdirSync(join(dir, 'yes'), { recursive: true })
    mkdirSync(join(dir, 'no'), { recursive: true })
    // 真实写法：重定向在前（原来的正则抓不到这一种）
    writeFileSync(join(dir, 'yes', 'a.js'), 'execSync(\'echo "x" >> ~/.bashrc\')\n')
    writeFileSync(join(dir, 'yes', 'b.js'), '.zshrc >> /tmp/log\n') // 旧顺序也还能抓到
    writeFileSync(join(dir, 'yes', 'c.js'), 'Add-Content $PROFILE "export X=1"\n')
    // 必须不响：只是提到这些名字
    writeFileSync(join(dir, 'no', 'a.js'), 'const profile = readProfile()\nconst name = "bashrc"\n')

    const ctx = makeCtx()
    apply(ctx)
    const tool = ctx.tools.find((t) => t.name === 'doctor_scan')
    const yes = await tool.execute({ path: join(dir, 'yes') })
    const no = await tool.execute({ path: join(dir, 'no') })
    const fired = new Set(yes.results.flatMap((r) => r.hits.map((h) => h.rule)))
    assert.ok(fired.has('persist-shellrc'), 'the redirect-first form must be caught')
    assert.equal(yes.results.filter((r) => r.hits.some((h) => h.rule === 'persist-shellrc')).length, 3, 'all three real forms')
    assert.equal(no.hits, 0, 'merely naming bashrc/profile is not persistence')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('the reverse measurement is itself able to go red (control)', async () => {
  // 用一个「无事发生」的目录跑同一条路径：命中必须是 0，否则上面的「全中」是假的
  const dir = mkdtempSync(join(tmpdir(), 'rules-clean-'))
  try {
    mkdirSync(join(dir, 'src'), { recursive: true })
    writeFileSync(join(dir, 'src', 'ok.js'), 'const a = 1\nconsole.log(a)\n')
    const ctx = makeCtx()
    apply(ctx)
    const tool = ctx.tools.find((t) => t.name === 'doctor_scan')
    const res = await tool.execute({ path: dir })
    assert.equal(res.hits, 0, 'a clean file must produce zero hits')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
