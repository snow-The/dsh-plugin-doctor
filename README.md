# dsh-plugin-doctor

Static vetting for DSH plugins — an own-built replacement for third-party
vetting plugins. Scans a plugin directory (a checkout, or an installed
package under `~/.dsh/profiles/*/node_modules`) for red flags, scores them
SAFE / LOW / MEDIUM / HIGH, and reports evidence with file:line. **It never
executes the scanned code** — purely read-only static analysis.

## Checked patterns

- **Exfiltration**: fetch/http(s) to non-localhost hosts, curl/wget/nc in
  child processes, sockets
- **Credential access**: reads of `.ssh`, `.aws`, `.env`, credentials
  files, wholesale `process.env` harvest
- **Obfuscation**: long base64/hex blobs, `eval`/Function/vm, hidden
  Unicode (zero-width / bidi controls)
- **Persistence**: registry Run keys, startup folders, scheduled tasks,
  shell-rc appends
- **Destructive**: `rm -rf /`-style deletes, force pushes
- **Lifecycle hooks**: preinstall / install / postinstall scripts
  (always worth a human look — they run with the installer's privileges)

## Tools

- `doctor_scan` — scan a path (directory or single file), defaulting to
  the current profile's node_modules plugin packages
- `doctor_scan_path` — alias with an explicit path parameter
- `doctor_patch` — check cordis patch files for loader-row collisions
  (a duplicated id is dropped **silently** by the loader: the plugin never
  mounts and nothing is logged)
- `doctor_drift` — compare every `file:` / `link:` dependency of a profile with
  the copy the host actually loads

### Why `doctor_drift` exists

A `file:` dependency is a **copy**, not a link. Editing the source package — even
pushing it — does not change the installed copy, and `pnpm install` will not
refresh it because the lockfile still says the dependency is satisfied.

Measured on 2026-11-06 in this workspace: after editing a plugin and bumping its
version, the profile still held the copy from 2026-10-19 (`client.js` 6798 bytes
vs the source's 7285) — the fix worked on disk and in git, and would never have
reached the running host. The fix that works: delete
`node_modules/<the-package>` and run `dsh plugin --profile <name> install`;
`install` alone does nothing.

Docs-only drift (LICENSE / README) is still reported, but as `LOW`: the question
this check answers is "is the host running my code?", and answering it with
licence noise trains the reader to ignore the check.

## License

MIT
