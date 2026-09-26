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
  registerHttpRoutes
};
