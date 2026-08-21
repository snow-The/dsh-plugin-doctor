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

## License

MIT
