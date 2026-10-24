#!/usr/bin/env node
// Snitch network audit for Branta.
//
// Launches the built Electron app (headless under Xvfb on CI), samples every
// socket opened by the app's process tree with `snitch`
// (https://github.com/karol-broda/snitch) and fails if any remote endpoint is
// not covered by scripts/snitch/allowlist.json.
//
// Remote IPs are mapped back to hostnames using Chromium's own DNS results
// (--log-net-log), so CDN IP rotation does not cause false positives. As a
// fallback, the allowlisted hosts are also resolved directly.
//
// Usage:
//   npm run build
//   xvfb-run -a node scripts/snitch/snitch-check.mjs [--duration 30] [--report snitch-report.json]
//
// Env:
//   SNITCH_BIN      path to the snitch binary (default: "snitch" on PATH)
//   ELECTRON_BIN    path to electron (default: node_modules/.bin/electron)

import { execFile, spawn } from 'node:child_process';
import { promises as dns } from 'node:dns';
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..', '..');

function arg(name, fallback) {
    const i = process.argv.indexOf(`--${name}`);
    return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const durationMs = Number(arg('duration', process.env.SNITCH_DURATION ?? '30')) * 1000;
const intervalMs = Number(arg('interval', '250'));
const reportPath = arg('report', path.join(root, 'snitch-report.json'));
const allowlistPath = arg('allowlist', path.join(here, 'allowlist.json'));
const snitchBin = process.env.SNITCH_BIN ?? 'snitch';
const electronBin = process.env.ELECTRON_BIN ?? path.join(root, 'node_modules', '.bin', 'electron');
const mainJs = path.join(root, 'build', 'app', 'main.js');

const allowlist = JSON.parse(readFileSync(allowlistPath, 'utf8'));
const allowed = allowlist.allowed ?? [];
const known = allowlist.knownIssues ?? [];

// ---------- helpers ----------

export function normalizeIp(ip) {
    ip = String(ip)
        .replace(/^\[|\]$/g, '')
        .replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i, '$1');
    if (!net.isIPv6(ip)) return ip;
    const [head, tail = ''] = ip.split('::');
    const h = head ? head.split(':') : [];
    const t = tail ? tail.split(':') : [];
    const fill = ip.includes('::') ? Array(8 - h.length - t.length).fill('0') : [];
    return [...h, ...fill, ...t].map((p) => parseInt(p, 16).toString(16)).join(':');
}

function isLocal(ip) {
    return ['', '*', '0.0.0.0', '0:0:0:0:0:0:0:0', '0:0:0:0:0:0:0:1'].includes(ip) || ip.startsWith('127.');
}

function matches(host, pattern) {
    if (pattern.startsWith('*.')) return host === pattern.slice(2) || host.endsWith(pattern.slice(1));
    return host === pattern;
}

function findRule(hosts, rules) {
    for (const rule of rules) {
        for (const host of hosts) if (matches(host, rule.host)) return rule;
    }
    return null;
}

async function resolveHosts(rules) {
    const ips = new Map();
    for (const { host } of rules) {
        if (host.startsWith('*.')) continue;
        for (const family of ['resolve4', 'resolve6']) {
            try {
                for (const ip of await dns[family](host)) ips.set(normalizeIp(ip), host);
            } catch {
                // no records of that family
            }
        }
    }
    return ips;
}

// ip -> Set(hostnames), taken from Chromium's net-log DNS results. The log is
// not closed properly when the app is killed, so it is scanned with regexes
// instead of JSON.parse.
function ipsFromNetLog(file) {
    const map = new Map();
    if (!existsSync(file)) return map;
    const text = readFileSync(file, 'utf8');
    const add = (ip, name) => {
        ip = normalizeIp(ip);
        if (!map.has(ip)) map.set(ip, new Set());
        map.get(ip).add(name);
    };
    const aliasOf = new Map();
    for (const m of text.matchAll(/"alias_target":"([^"]+)","domain_name":"([^"]+)"/g)) aliasOf.set(m[1], m[2]);
    for (const m of text.matchAll(/"domain_name":"([^"]+)","endpoints":\[([^\]]*)\]/g)) {
        for (const a of m[2].matchAll(/"address":"([^"]+)"/g)) {
            let name = m[1];
            add(a[1], name);
            const visited = new Set();
            while (aliasOf.has(name) && !visited.has(name)) {
                visited.add(name);
                name = aliasOf.get(name);
                add(a[1], name);
            }
        }
    }
    return map;
}

// All PIDs in the process tree rooted at rootPid (Linux /proc).
function processTree(rootPid) {
    const children = new Map();
    for (const entry of readdirSync('/proc')) {
        if (!/^\d+$/.test(entry)) continue;
        try {
            const stat = readFileSync(`/proc/${entry}/stat`, 'utf8');
            const ppid = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]);
            if (!children.has(ppid)) children.set(ppid, []);
            children.get(ppid).push(Number(entry));
        } catch {
            // process exited while scanning
        }
    }
    const tree = new Set([rootPid]);
    const queue = [rootPid];
    while (queue.length) {
        for (const child of children.get(queue.shift()) ?? []) {
            if (!tree.has(child)) {
                tree.add(child);
                queue.push(child);
            }
        }
    }
    return tree;
}

async function snapshot() {
    const { stdout } = await execFileAsync(snitchBin, ['ls', '-o', 'json', '--color', 'never', '--resolve-addrs=false'], {
        maxBuffer: 32 * 1024 * 1024,
        env: { ...process.env, NO_COLOR: '1' }
    });
    return JSON.parse(stdout || '[]') ?? [];
}

// ---------- main ----------

async function main() {
    if (!existsSync(mainJs)) {
        console.error(`snitch: ${mainJs} not found, run "npm run build" first`);
        process.exit(2);
    }
    try {
        await execFileAsync(snitchBin, ['--help']);
    } catch {
        console.error(`snitch: "${snitchBin}" not found, install it or set SNITCH_BIN`);
        process.exit(2);
    }

    // Throwaway HOME so the run never touches a real profile (auto-launch entry, stored data).
    const home = mkdtempSync(path.join(os.tmpdir(), 'branta-snitch-'));
    const netLog = path.join(home, 'netlog.json');
    const app = spawn(electronBin, [mainJs, '--no-sandbox', `--log-net-log=${netLog}`], {
        cwd: root,
        env: { ...process.env, HOME: home, XDG_CONFIG_HOME: path.join(home, '.config'), ELECTRON_DISABLE_SECURITY_WARNINGS: 'true' },
        stdio: ['ignore', 'inherit', 'inherit']
    });
    let exited = null;
    app.on('exit', (code, signal) => (exited = { code, signal }));

    const sockets = new Map();
    const deadline = Date.now() + durationMs;
    let samples = 0;
    while (Date.now() < deadline && !exited) {
        const pids = processTree(app.pid);
        for (const c of await snapshot()) {
            if (!pids.has(c.pid) || c.state === 'LISTEN') continue;
            const raddr = normalizeIp(c.raddr);
            if (isLocal(raddr)) continue;
            const key = `${c.proto}|${raddr}|${c.rport}`;
            if (!sockets.has(key)) sockets.set(key, { proto: c.proto, state: c.state, raddr, rport: c.rport, process: c.process, firstSeen: c.ts });
        }
        samples++;
        await new Promise((r) => setTimeout(r, intervalMs));
    }
    const exitedEarly = exited !== null;
    if (!exited) {
        app.kill('SIGTERM');
        await new Promise((r) => setTimeout(r, 1500));
        if (!exited) app.kill('SIGKILL');
    }

    const netLogIps = ipsFromNetLog(netLog);
    const dnsIps = await resolveHosts([...allowed, ...known]);

    const connections = [...sockets.values()].map((c) => {
        if (c.rport === 53 && allowlist.allowDns) return { ...c, hosts: [], verdict: 'ok', reason: 'dns' };
        const hosts = [...new Set([...(netLogIps.get(c.raddr) ?? []), ...(dnsIps.has(c.raddr) ? [dnsIps.get(c.raddr)] : [])])];
        const ok = findRule(hosts, allowed);
        if (ok) return { ...c, hosts, verdict: 'ok', reason: ok.reason ?? `allowed: ${ok.host}` };
        const warn = findRule(hosts, known);
        if (warn) return { ...c, hosts, verdict: 'known', reason: warn.reason ?? `known issue: ${warn.host}` };
        return { ...c, hosts, verdict: 'fail', reason: hosts.length ? 'host not in allowlist' : 'unattributed connection' };
    });
    const violations = connections.filter((c) => c.verdict === 'fail');
    const knownHits = connections.filter((c) => c.verdict === 'known');

    writeFileSync(reportPath, JSON.stringify({ durationMs, samples, exitedEarly, exit: exited, connections, violations, knownIssues: knownHits }, null, 2));

    console.log(`snitch: ${samples} samples, ${connections.length} unique remote endpoints, report: ${reportPath}`);
    for (const c of connections) {
        const tag = { ok: 'ok   ', known: 'KNOWN', fail: 'FAIL ' }[c.verdict];
        console.log(`  ${tag} ${c.proto} ${c.raddr}:${c.rport} ${c.hosts.length ? `[${c.hosts.join(', ')}] ` : ''}- ${c.reason}`);
    }
    if (process.env.GITHUB_ACTIONS) {
        for (const c of knownHits) console.log(`::warning title=snitch known issue::${c.proto} ${c.raddr}:${c.rport} ${c.hosts.join(', ')} - ${c.reason}`);
        for (const c of violations)
            console.log(`::error title=snitch unexpected connection::${c.proto} ${c.raddr}:${c.rport} ${c.hosts.join(', ')} - ${c.reason}`);
    }

    if (exitedEarly) {
        console.error(`snitch: app exited early (${JSON.stringify(exited)}), audit is not meaningful`);
        process.exit(1);
    }
    if (violations.length) {
        console.error(`snitch: ${violations.length} unexpected connection(s)`);
        process.exit(1);
    }
    console.log(`snitch: no unexpected network connections${knownHits.length ? ` (${knownHits.length} known issue(s), see warnings)` : ''}`);
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
