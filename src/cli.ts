#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { diagnose } from './doctor.js';
import { formatReport } from './format.js';

const HELP = `steel-proxy-doctor: check a bring-your-own proxy before a Steel session uses it.

Usage:
  steel-proxy-doctor [proxy-url] [options]

The proxy URL can also come from the STEEL_PROXY_URL environment variable,
which keeps the password out of your shell history.

Options:
  --target <url>    Also fetch this page through the proxy and flag blocks
  --rounds <n>      Tunnels to open when checking for IP rotation (default 3)
  --echo <url>      IP-echo endpoint (default https://api.ipify.org?format=json)
  --timeout <ms>    Per-stage timeout (default 8000)
  --json            Print the report as JSON (for scripts and agents)
  --insecure-proxy-tls  Skip certificate checks on an https:// proxy's own TLS
  -h, --help        Show this help

Exit codes: 0 passed, 1 a check failed, 2 bad usage.`;

async function main(): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        target: { type: 'string' },
        rounds: { type: 'string' },
        echo: { type: 'string' },
        timeout: { type: 'string' },
        json: { type: 'boolean', default: false },
        'insecure-proxy-tls': { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
      },
    });
  } catch (e) {
    console.error((e as Error).message + '\n\n' + HELP);
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.help) {
    console.log(HELP);
    return 0;
  }

  const url = positionals[0] ?? process.env.STEEL_PROXY_URL;
  if (!url) {
    console.error('No proxy URL given. Pass it as an argument or set STEEL_PROXY_URL.\n\n' + HELP);
    return 2;
  }

  const num = (v: string | undefined, name: string) => {
    if (v === undefined) return undefined;
    const n = Number(v);
    if (!Number.isFinite(n) || n <= 0) throw new Error(`--${name} must be a positive number`);
    return n;
  };

  let report;
  try {
    report = await diagnose(url, {
      target: values.target,
      echoUrl: values.echo,
      rounds: num(values.rounds, 'rounds'),
      timeoutMs: num(values.timeout, 'timeout'),
      insecureProxyTls: values['insecure-proxy-tls'],
    });
  } catch (e) {
    console.error((e as Error).message);
    return 2;
  }

  if (values.json) console.log(JSON.stringify(report, null, 2));
  else console.log(formatReport(report, process.stdout.isTTY && !process.env.NO_COLOR));
  return report.ok ? 0 : 1;
}

main().then((code) => process.exit(code));
