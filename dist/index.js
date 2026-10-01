// src/index.ts
import { readdir, readFile, stat } from "node:fs/promises";
import { join, extname } from "node:path";
import { homedir } from "node:os";
var name = "plugin-doctor";
var inject = ["tools"];
var HIDDEN = /* @__PURE__ */ new Set([
  8203,
  8204,
  8205,
  8206,
  8207,
  8234,
  8235,
  8236,
  8237,
  8238,
  8288,
  8294,
  8295,
  8296,
  8297,
  1564,
  847,
  65279,
  173,
  6158
]);
var RULES = [
  ["exfil-http", "HTTP(s) to non-localhost host", /(?:https?:\/\/(?!127\.0\.0\.1|localhost|\[::1\]))[a-zA-Z0-9.-]+/g, 2],
  ["exfil-shell-net", "curl/wget/nc/socket in code", /\b(?:curl|wget|nc\s+-|net\.connect|socket\.connect|Invoke-WebRequest|Start-BitsTransfer)\b/g, 2],
  ["exfil-fetch", "fetch to remote", /\bfetch\s*\(\s*['"`][a-z]+:\/\//g, 2],
  ["cred-secrets", "credential file reads", /\.(?:ssh|aws|env|credentials|netrc|npmrc)\b|id_rsa|id_ed25519|\.pem\b/g, 3],
  ["cred-env-harvest", "wholesale process.env harvest", /Object\.(?:keys|entries|values)\(\s*process\.env|for\s*\(\s*[a-z]+\s+in\s+process\.env/g, 2],
  ["obf-eval", "dynamic code execution", /\beval\s*\(|new\s+Function\s*\(|vm\.runIn(?:NewContext|ThisContext)|fromCharCode\s*\(/g, 2],
  ["obf-base64", "long base64 blob", /[A-Za-z0-9+/]{200,}={0,2}/g, 1],
  ["obf-hidden-unicode", "hidden Unicode (checked per-char, see scan)", /[\u200B-\u200D\u202A-\u202E\u2060\uFEFF\u00AD]/g, 2],
  ["persist-registry", "registry autostart", /HKCU\s*\\\s*Software\s*\\\s*Microsoft\s*\\\s*Windows\s*\\\s*CurrentVersion\s*\\\s*Run|reg\s+add/g, 3],
  ["persist-startup", "startup folder / scheduled task", /Startup\s*\\|schtasks|Start-Process.*-WindowStyle.*Hidden/g, 2],
  ["persist-shellrc", "shell rc append", /(?:bashrc|zshrc|profile)\s*>>|Add-Content.*(?:bashrc|zshrc|profile)/g, 2],
  ["destructive-rm", "recursive force delete of root", /rm\s+-rf\s+(?:\/|\$HOME\s*\/\s*\*|~\s*\/\s*\*)|Remove-Item.*-Recurse.*(?:\\|C:)/g, 3],
  ["destructive-git", "force push", /git\s+push.*--force|git\s+push.*-f\b/g, 1]
];
var LIFECYCLE = ["preinstall", "install", "postinstall"];
var textOutput = () => ({
  schema: { type: "object", additionalProperties: true },
  render: (_args, value) => [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }]
});
async function walkFiles(dir, depth = 0) {
  if (depth > 8) return [];
  const out = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  for (const e of entries) {
    if (e.name === ".git" || e.name === "node_modules") continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) out.push(...await walkFiles(full, depth + 1));
    else if (e.isFile()) out.push(full);
  }
  return out;
}
async function scanFile(file, maxBytes = 2 * 1024 * 1024) {
  const hits = [];
  let text;
  try {
    const st = await stat(file);
    if (st.size > maxBytes) return { file, hits: [], note: "skipped (too large)" };
    text = await readFile(file, "utf8");
  } catch {
    return { file, hits: [], note: "unreadable" };
  }
  const ext = extname(file).toLowerCase();
  const isText = [".js", ".ts", ".mjs", ".cjs", ".json", ".yml", ".yaml", ".md", ".txt", ".sh", ".ps1", ".py"].includes(ext);
  if (isText) {
    let unicode = 0;
    for (let i = 0; i < text.length; i++) {
      if (HIDDEN.has(text.charCodeAt(i))) unicode++;
    }
    if (unicode > 0) hits.push({ rule: "obf-hidden-unicode", severity: 2, evidence: `hidden unicode chars: ${unicode}`, line: 0 });
  }
  const lines = text.split(/\r?\n/);
  for (const [id, label, re, sev] of RULES) {
    if (id === "obf-hidden-unicode") continue;
    for (let i = 0; i < lines.length; i++) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(lines[i])) !== null) {
        hits.push({ rule: id, severity: sev, evidence: label, line: i + 1, snippet: lines[i].trim().slice(0, 140) });
        if (hits.filter((h) => h.rule === id && h.line === i + 1).length > 3) break;
      }
    }
  }
  return { file, hits, note: null };
}
function scoreHits(hits) {
  let worst = 0;
  const byRule = {};
  for (const h of hits) {
    worst = Math.max(worst, h.severity);
    byRule[h.rule] = (byRule[h.rule] ?? 0) + 1;
  }
  const verdict = worst >= 3 ? "HIGH" : worst === 2 ? "MEDIUM" : worst === 1 ? "LOW" : "SAFE";
  return { verdict, worst, byRule };
}
async function scanTarget(root) {
  const st = await stat(root).catch(() => null);
  if (!st) throw new Error(`path not found: ${root}`);
  const files = st.isDirectory() ? await walkFiles(root) : [root];
  const results = [];
  for (const f of files) {
    const r = await scanFile(f);
    if (r.hits.length > 0 || r.note) results.push(r);
  }
  const allHits = results.flatMap((r) => r.hits);
  const packageJson = files.find((f) => f.endsWith("package.json"));
  let lifecycle = [];
  if (packageJson) {
    try {
      const pj = JSON.parse(await readFile(packageJson, "utf8"));
      lifecycle = LIFECYCLE.filter((k) => pj.scripts?.[k]).map((k) => ({ script: k, command: pj.scripts[k] }));
    } catch {
    }
  }
  return { root, files: files.length, scanned: files.length, results, hits: allHits.length, lifecycle, ...scoreHits(allHits) };
}
var unquote = (v) => {
  const t = v.trim();
  if (t.startsWith("'") && t.endsWith("'") && t.length > 1 || t.startsWith('"') && t.endsWith('"') && t.length > 1) {
    return t.slice(1, -1);
  }
  return t;
};
function parsePatchInserts(text) {
  const rows = [];
  const lines = text.split(/\r?\n/);
  let current = null;
  let currentIndent = -1;
  for (let i = 0; i < lines.length; i++) {
    const stripped = lines[i].replace(/(^|\s)#.*$/, "");
    if (stripped.trim() === "") continue;
    const indent = stripped.length - stripped.trimStart().length;
    const t = stripped.trim();
    const rowStart = /^-\s*id:\s*(.+)$/.exec(t);
    if (rowStart) {
      current = { id: unquote(rowStart[1]), name: null, disabled: false, line: i + 1 };
      currentIndent = indent;
      rows.push(current);
      continue;
    }
    if (/^-\s*insert:\s*$/.test(t) || t === "insert:") {
      current = null;
      currentIndent = -1;
      continue;
    }
    const kv = /^(name|disabled):\s*(.+)$/.exec(t);
    if (kv && current !== null && indent > currentIndent) {
      if (kv[1] === "name") current.name = unquote(kv[2]);
      else current.disabled = unquote(kv[2]) === "true";
      continue;
    }
    if (current !== null && indent <= currentIndent) {
      current = null;
      currentIndent = -1;
    }
  }
  return rows;
}
var PATCH_NAME_RE = /(?:^|[\\/])(?:cordis\.patch\.yml|cordis\.yml)$/;
async function analyzePatches(root) {
  const files = [];
  const st = await stat(root).catch(() => null);
  if (!st) throw new Error(`path not found: ${root}`);
  if (st.isFile()) {
    files.push(root);
  } else {
    for (const f of await walkFiles(root)) if (PATCH_NAME_RE.test(f)) files.push(f);
    const nm = join(root, "node_modules");
    if (await stat(nm).catch(() => null)) {
      const scopes = await readdir(nm, { withFileTypes: true }).catch(() => []);
      for (const sc of scopes) {
        if (!sc.isDirectory()) continue;
        const scopeDir = join(nm, sc.name);
        const pkgs = sc.name.startsWith("@") ? (await readdir(scopeDir, { withFileTypes: true }).catch(() => [])).filter((e) => e.isDirectory()).map((e) => join(scopeDir, e.name)) : [scopeDir];
        for (const pkgDir of pkgs) {
          for (const cand of ["cordis.patch.yml", "cordis.yml"]) {
            const p = join(pkgDir, cand);
            if (await stat(p).catch(() => null) && !files.includes(p)) files.push(p);
          }
        }
      }
    }
  }
  const declarations = /* @__PURE__ */ new Map();
  const configRows = [];
  let rows = 0;
  for (const f of files) {
    let text;
    try {
      text = await readFile(f, "utf8");
    } catch {
      continue;
    }
    for (const row of parsePatchInserts(text)) {
      rows++;
      if (row.name === null) {
        configRows.push({ id: row.id, file: f, line: row.line });
        continue;
      }
      const list = declarations.get(row.id) ?? [];
      list.push({ file: f, line: row.line, name: row.name });
      declarations.set(row.id, list);
    }
  }
  const issues = [];
  for (const [id, decls] of declarations) {
    const byFile = /* @__PURE__ */ new Map();
    for (const d of decls) {
      const l = byFile.get(d.file) ?? [];
      l.push(d);
      byFile.set(d.file, l);
    }
    for (const [file, group] of byFile) {
      if (group.length < 2) continue;
      issues.push({
        kind: "duplicate-declaration-same-file",
        severity: 3,
        id,
        detail: `"${id}" is DECLARED ${group.length}x in one patch file. The loader builds its row map with Object.fromEntries, which keeps the LAST value for a duplicate key, so the earlier declaration is dropped and nothing is logged (cordis-plugin-loader/lib/index.js:82)`,
        where: group.map((g) => `${g.file}:${g.line} (${g.name})`)
      });
    }
    if (byFile.size > 1) {
      issues.push({
        kind: "duplicate-declaration-cross-file",
        severity: 2,
        id,
        detail: `"${id}" is declared by ${byFile.size} different patch files. The loader reuses ONE entry for the id (\u2026:60) and the later declaration overwrites its options, so whichever composes last wins \u2014 a carefully configured row here can be replaced by a bundle's minimal one`,
        where: decls.map((g) => `${g.file}:${g.line} (${g.name})`)
      });
    }
  }
  const unresolvedConfigIds = [];
  const declaredIds = [...declarations.keys()];
  const editDistance = (a, b) => {
    const prev = Array.from({ length: b.length + 1 }, (_, j) => j);
    for (let i = 1; i <= a.length; i++) {
      let diag = prev[0];
      prev[0] = i;
      for (let j = 1; j <= b.length; j++) {
        const tmp = prev[j];
        prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
        diag = tmp;
      }
    }
    return prev[b.length];
  };
  for (const c of configRows) {
    if (declarations.has(c.id)) continue;
    const near = c.id.length < 8 ? [] : declaredIds.filter((d) => d.length >= 8 && d !== c.id && editDistance(c.id, d) <= 2);
    if (near.length > 0) {
      issues.push({
        kind: "dangling-config-row",
        severity: 2,
        id: c.id,
        detail: `"${c.id}" is configured here but nothing in this scan declares it \u2014 it is ${near.length === 1 ? "one edit away from" : "close to"} the declared id(s) ${near.map((n) => `"${n}"`).join(", ")}, which usually means a typo rather than a bundle outside the scan`,
        where: [`${c.file}:${c.line}`]
      });
    } else {
      unresolvedConfigIds.push({ id: c.id, where: `${c.file}:${c.line}` });
    }
  }
  issues.sort((a, b) => b.severity - a.severity || a.id.localeCompare(b.id));
  const worst = issues.reduce((m, i) => Math.max(m, i.severity), 0);
  return {
    root,
    patchFiles: files.length,
    patchFileList: files,
    rowCount: rows,
    declarationCount: [...declarations.values()].reduce((n, l) => n + l.length, 0),
    uniqueIds: declarations.size,
    configRowCount: configRows.length,
    /** Config rows whose id no scanned patch declares — informational: a bundle outside the scan may own it. */
    unresolvedConfigIds,
    issues,
    verdict: worst >= 3 ? "HIGH" : worst === 2 ? "MEDIUM" : worst === 1 ? "LOW" : "SAFE"
  };
}
function apply(ctx) {
  const scanTool = (toolName) => ({
    name: toolName,
    description: "Static vetting scan of a plugin directory or file. Never executes scanned code. Returns per-file evidence (file:line, rule, severity), a verdict (SAFE/LOW/MEDIUM/HIGH) and any lifecycle scripts found. Path must be an absolute path on this machine.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to a directory or file to scan (default: current profile node_modules)" }
      }
    },
    output: textOutput(),
    timeoutMs: 12e4,
    isConcurrencySafe: () => true,
    presentCall: (a) => ({ card: "generic", title: "doctor scan", kind: "read", rawInput: a }),
    async execute(args) {
      const a = args;
      let root;
      if (typeof a.path === "string" && a.path) {
        root = a.path;
      } else {
        const profile = process.env.DSH_PROFILE ?? "web";
        root = join(homedir(), ".dsh", "profiles", profile, "node_modules");
      }
      if (!/^[A-Za-z]:[\\/]|^\//.test(root)) {
        throw new Error("path must be an absolute path");
      }
      const res = await scanTarget(root);
      const summary = res.hits === 0 ? "clean" : `${res.hits} hits (${res.verdict})`;
      return { ok: true, ...res, summary };
    }
  });
  for (const name2 of ["doctor_scan", "doctor_scan_path"]) {
    try {
      ctx.tools.register(scanTool(name2));
    } catch (err) {
      console.error(`[plugin-doctor] ${name2} skipped: ${err}`);
    }
  }
  const patchTool = {
    name: "doctor_patch",
    description: "Check cordis patch files for loader-row collisions. A patch file is one list of rows, given either directly (`- id: \u2026 / name: \u2026`) or inside an `- insert:` wrapper; a row WITH `name` declares an entry, a row without one only configures or toggles it. Two declarations of the same id in one file are DROPPED SILENTLY by the loader (its row map is built with Object.fromEntries, which keeps the last value), so the plugin never mounts and no error is logged; two declarations across files reuse one loader entry and the later one overwrites the options. Also reports config rows whose id nothing declares. Read-only: parses YAML-shaped text, never executes anything. Path must be an absolute path on this machine.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to a plugin directory, a profile directory, or a single patch file (default: current profile)" }
      }
    },
    output: textOutput(),
    timeoutMs: 6e4,
    isConcurrencySafe: () => true,
    presentCall: (a) => ({ card: "generic", title: "doctor patch", kind: "read", rawInput: a }),
    async execute(args) {
      const a = args;
      let root;
      if (typeof a.path === "string" && a.path) root = a.path;
      else root = join(homedir(), ".dsh", "profiles", process.env.DSH_PROFILE ?? "web");
      if (!/^[A-Za-z]:[\\/]|^\//.test(root)) throw new Error("path must be an absolute path");
      const res = await analyzePatches(root);
      const info = res.unresolvedConfigIds.length ? `, ${res.unresolvedConfigIds.length} config row(s) owned outside this scan` : "";
      const summary = res.issues.length === 0 ? `clean (${res.uniqueIds} declared ids across ${res.patchFiles} patch files${info})` : `${res.issues.length} issue(s) / ${res.verdict} (${res.uniqueIds} declared ids, ${res.declarationCount} declarations across ${res.patchFiles} patch files${info})`;
      return { ok: true, summary, ...res };
    }
  };
  try {
    ctx.tools.register(patchTool);
  } catch (err) {
    console.error(`[plugin-doctor] doctor_patch skipped: ${err}`);
  }
  ctx.inject?.(["webServer"], (webCtx) => {
    const register = (kind, path, handler) => {
      webCtx.webServer.register({ kind, path, handler });
    };
    const mount = () => registerHttpRoutes(ctx, register);
    if (typeof webCtx.effect === "function") webCtx.effect(mount, "plugin-doctor: GET /api/doctor/health");
    else mount();
  });
}
function createRequestFence(ctx) {
  const resolveConnection = () => {
    const read = ctx?.get;
    if (typeof read !== "function") return void 0;
    try {
      const connection = read.call(ctx, "connection");
      return typeof connection?.requestRejection === "function" ? connection : void 0;
    } catch {
      return void 0;
    }
  };
  return (req, res) => {
    const connection = resolveConnection();
    if (connection === void 0) {
      res.statusCode = 503;
      res.setHeader("content-type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ error: "connection service unavailable: the Host/Origin fence cannot be applied" }));
      return true;
    }
    const rejection = connection.requestRejection(req);
    if (rejection === void 0) return false;
    res.statusCode = rejection;
    res.end();
    return true;
  };
}
function registerHttpRoutes(ctx, register) {
  const rejected = createRequestFence(ctx);
  register("exact", "/api/doctor/health", (req, res) => {
    if (rejected(req, res)) return;
    if (req.method !== "GET") {
      res.statusCode = 405;
      res.setHeader("allow", "GET");
      res.end();
      return;
    }
    res.statusCode = 200;
    res.setHeader("content-type", "application/json; charset=utf-8");
    res.end(JSON.stringify({ ok: true, plugin: "dsh-plugin-doctor", ts: true, rules: RULES.length }));
  });
}
export {
  apply,
  inject,
  name,
  parsePatchInserts,
  registerHttpRoutes
};
