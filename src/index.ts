/**
 * dsh-plugin-doctor — static vetting for DSH plugins (TypeScript).
 *
 * Read-only by design: this plugin NEVER executes scanned code. It walks
 * text files, applies pattern rules with file:line evidence, and returns a
 * score. Heuristics are conservative — a hit means "read the evidence", not
 * "this is malware".
 */
import { readdir, readFile, stat } from 'node:fs/promises'
import { join, extname } from 'node:path'
import { homedir } from 'node:os'

export const name = 'plugin-doctor'
export const inject = ['tools']

// --- minimal DSH tool surface ---
type Json = null | boolean | number | string | Json[] | { [k: string]: Json | undefined }

interface Tool {
  name: string
  description: string
  parameters: { type: 'object'; properties: Record<string, Json>; required?: string[] }
  output: {
    schema: Json
    render: (args: Json, value: Json) => { type: 'text'; text: string }[]
  }
  timeoutMs?: number
  isConcurrencySafe?: () => boolean
  presentCall?: (args: Json) => Json
  execute: (args: Json, exec: { signal?: AbortSignal }) => Promise<Json>
}

interface Ctx {
  tools: { register: (tool: Tool) => void }
}

const HIDDEN = new Set([
  0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d,
  0x202e, 0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0x061c, 0x034f, 0xfeff,
  0x00ad, 0x180e,
])

type Rule = [id: string, label: string, re: RegExp, severity: 1 | 2 | 3]

const RULES: Rule[] = [
  ['exfil-http', 'HTTP(s) to non-localhost host', /(?:https?:\/\/(?!127\.0\.0\.1|localhost|\[::1\]))[a-zA-Z0-9.-]+/g, 2],
  ['exfil-shell-net', 'curl/wget/nc/socket in code', /\b(?:curl|wget|nc\s+-|net\.connect|socket\.connect|Invoke-WebRequest|Start-BitsTransfer)\b/g, 2],
  ['exfil-fetch', 'fetch to remote', /\bfetch\s*\(\s*['"`][a-z]+:\/\//g, 2],
  ['cred-secrets', 'credential file reads', /\.(?:ssh|aws|env|credentials|netrc|npmrc)\b|id_rsa|id_ed25519|\.pem\b/g, 3],
  ['cred-env-harvest', 'wholesale process.env harvest', /Object\.(?:keys|entries|values)\(\s*process\.env|for\s*\(\s*[a-z]+\s+in\s+process\.env/g, 2],
  ['obf-eval', 'dynamic code execution', /\beval\s*\(|new\s+Function\s*\(|vm\.runIn(?:NewContext|ThisContext)|fromCharCode\s*\(/g, 2],
  ['obf-base64', 'long base64 blob', /[A-Za-z0-9+/]{200,}={0,2}/g, 1],
  ['obf-hidden-unicode', 'hidden Unicode (checked per-char, see scan)', /[\u200B-\u200D\u202A-\u202E\u2060\uFEFF\u00AD]/g, 2],
  ['persist-registry', 'registry autostart', /HKCU\s*\\\s*Software\s*\\\s*Microsoft\s*\\\s*Windows\s*\\\s*CurrentVersion\s*\\\s*Run|reg\s+add/g, 3],
  ['persist-startup', 'startup folder / scheduled task', /Startup\s*\\|schtasks|Start-Process.*-WindowStyle.*Hidden/g, 2],
  ['persist-shellrc', 'shell rc append', /(?:bashrc|zshrc|profile)\s*>>|Add-Content.*(?:bashrc|zshrc|profile)/g, 2],
  ['destructive-rm', 'recursive force delete of root', /rm\s+-rf\s+(?:\/|\$HOME\s*\/\s*\*|~\s*\/\s*\*)|Remove-Item.*-Recurse.*(?:\\|C:)/g, 3],
  ['destructive-git', 'force push', /git\s+push.*--force|git\s+push.*-f\b/g, 1],
]

const LIFECYCLE = ['preinstall', 'install', 'postinstall'] as const

const textOutput = (): Tool['output'] => ({
  schema: { type: 'object', additionalProperties: true },
  render: (_args, value) => [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }],
})

async function walkFiles(dir: string, depth = 0): Promise<string[]> {
  if (depth > 8) return []
  const out: string[] = []
  let entries
  try { entries = await readdir(dir, { withFileTypes: true }) } catch { return [] }
  for (const e of entries) {
    if (e.name === '.git' || e.name === 'node_modules') continue
    const full = join(dir, e.name)
    if (e.isDirectory()) out.push(...(await walkFiles(full, depth + 1)))
    else if (e.isFile()) out.push(full)
  }
  return out
}

interface Hit { rule: string; severity: number; evidence: string; line: number; snippet?: string }
interface ScanResult { file: string; hits: Hit[]; note: string | null }

async function scanFile(file: string, maxBytes = 2 * 1024 * 1024): Promise<ScanResult> {
  const hits: Hit[] = []
  let text: string
  try {
    const st = await stat(file)
    if (st.size > maxBytes) return { file, hits: [], note: 'skipped (too large)' }
    text = await readFile(file, 'utf8')
  } catch {
    return { file, hits: [], note: 'unreadable' }
  }
  const ext = extname(file).toLowerCase()
  const isText = ['.js', '.ts', '.mjs', '.cjs', '.json', '.yml', '.yaml', '.md', '.txt', '.sh', '.ps1', '.py'].includes(ext)
  if (isText) {
    let unicode = 0
    for (let i = 0; i < text.length; i++) {
      if (HIDDEN.has(text.charCodeAt(i))) unicode++
    }
    if (unicode > 0) hits.push({ rule: 'obf-hidden-unicode', severity: 2, evidence: `hidden unicode chars: ${unicode}`, line: 0 })
  }
  const lines = text.split(/\r?\n/)
  for (const [id, label, re, sev] of RULES) {
    if (id === 'obf-hidden-unicode') continue
    for (let i = 0; i < lines.length; i++) {
      re.lastIndex = 0
      let m: RegExpExecArray | null
      while ((m = re.exec(lines[i])) !== null) {
        hits.push({ rule: id, severity: sev, evidence: label, line: i + 1, snippet: lines[i].trim().slice(0, 140) })
        if (hits.filter((h) => h.rule === id && h.line === i + 1).length > 3) break
      }
    }
  }
  return { file, hits, note: null }
}

function scoreHits(hits: Hit[]): { verdict: string; worst: number; byRule: Record<string, number> } {
  let worst = 0
  const byRule: Record<string, number> = {}
  for (const h of hits) {
    worst = Math.max(worst, h.severity)
    byRule[h.rule] = (byRule[h.rule] ?? 0) + 1
  }
  const verdict = worst >= 3 ? 'HIGH' : worst === 2 ? 'MEDIUM' : worst === 1 ? 'LOW' : 'SAFE'
  return { verdict, worst, byRule }
}

async function scanTarget(root: string) {
  const st = await stat(root).catch(() => null)
  if (!st) throw new Error(`path not found: ${root}`)
  const files = st.isDirectory() ? await walkFiles(root) : [root]
  const results: ScanResult[] = []
  for (const f of files) {
    const r = await scanFile(f)
    if (r.hits.length > 0 || r.note) results.push(r)
  }
  const allHits = results.flatMap((r) => r.hits)
  const packageJson = files.find((f) => f.endsWith('package.json'))
  let lifecycle: { script: string; command: string }[] = []
  if (packageJson) {
    try {
      const pj = JSON.parse(await readFile(packageJson, 'utf8')) as { scripts?: Record<string, string> }
      lifecycle = LIFECYCLE.filter((k) => pj.scripts?.[k]).map((k) => ({ script: k, command: pj.scripts![k] }))
    } catch { /* not a package */ }
  }
  return { root, files: files.length, scanned: files.length, results, hits: allHits.length, lifecycle, ...scoreHits(allHits) }
}

export function apply(ctx: Ctx): void {
  const scanTool = (toolName: string): Tool => ({
    name: toolName,
    description:
      'Static vetting scan of a plugin directory or file. Never executes scanned code. Returns per-file evidence (file:line, rule, severity), a verdict (SAFE/LOW/MEDIUM/HIGH) and any lifecycle scripts found. Path must be an absolute path on this machine.',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path to a directory or file to scan (default: current profile node_modules)' },
      },
    },
    output: textOutput(),
    timeoutMs: 120000,
    isConcurrencySafe: () => true,
    presentCall: (a) => ({ card: 'generic', title: 'doctor scan', kind: 'read', rawInput: a }),
    async execute(args) {
      const a = args as Record<string, Json>
      let root: string
      if (typeof a.path === 'string' && a.path) {
        root = a.path
      } else {
        const profile = process.env.DSH_PROFILE ?? 'web'
        root = join(homedir(), '.dsh', 'profiles', profile, 'node_modules')
      }
      if (!/^[A-Za-z]:[\\/]|^\//.test(root)) {
        throw new Error('path must be an absolute path')
      }
      const res = await scanTarget(root)
      const summary = res.hits === 0 ? 'clean' : `${res.hits} hits (${res.verdict})`
      return { ok: true, ...(res as unknown as Record<string, Json>), summary }
    },
  })

  for (const name of ['doctor_scan', 'doctor_scan_path']) {
    try { ctx.tools.register(scanTool(name)) } catch (err) { console.error(`[plugin-doctor] ${name} skipped: ${err}`) }
  }
}
