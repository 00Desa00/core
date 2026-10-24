# Snitch network audit

Branta should only talk to Branta servers. This check launches the built app,
watches every socket its process tree opens with
[snitch](https://github.com/karol-broda/snitch) and fails CI when the app
connects to a host that is not on the allowlist.

## How it works

1. `npm run build`, then the Electron app is started under Xvfb with a
   throwaway `HOME` (no real profile or auto-launch entry is touched).
2. `snitch ls -o json` is sampled every 250 ms for 30 s. Only sockets owned by
   the app's process tree are kept; loopback and listening sockets are ignored.
3. Every remote IP is mapped back to a hostname using Chromium's own DNS
   results (`--log-net-log`), so rotating CDN IPs do not cause false
   positives. The allowlisted hosts are also resolved directly as a fallback.
4. Each endpoint is classified:
   - `ok`: host is in `allowed`
   - `KNOWN`: host is in `knownIssues`, reported as a CI warning but not failing
   - `FAIL`: any other host, or an IP that cannot be attributed to a hostname
5. A JSON report (`snitch-report.json`) is uploaded as a workflow artifact.

## Run locally (Linux)

```sh
npm ci && npm run build
# install snitch: https://github.com/karol-broda/snitch#install
xvfb-run -a node scripts/snitch/snitch-check.mjs --duration 30
```

Options: `--duration <s>`, `--interval <ms>`, `--allowlist <file>`,
`--report <file>`. Env: `SNITCH_BIN`, `ELECTRON_BIN`.

## Allowlist

`scripts/snitch/allowlist.json`. Entries are hostnames, `*.example.com`
matches the domain and all subdomains.

The first runs found the following existing connections. They are listed under
`knownIssues` so the check can be merged without blocking CI:

| Host | Cause | Fix |
| --- | --- | --- |
| `fonts.googleapis.com`, `fonts.gstatic.com` | Google Fonts `<link>` tags in `src/index.html` | bundle Roboto, Roboto Mono and Material Icons locally |
| `*.gvt1.com` | Chromium spellchecker downloads Hunspell dictionaries | `webPreferences: { spellcheck: false }` |

Once these are fixed, remove them from `knownIssues` so a regression fails CI.
