import net from 'node:net';
import { buildError, type Ctx } from './catalog.js';
import { errMsg, httpGet, openTunnel, resolveHost, StageError, type Recorder } from './net.js';
import { parseProxyUrl, redactRaw } from './parse.js';
import type { ErrorCode, InferredType, ParsedProxy, Report } from './types.js';

export const DEFAULT_ECHO_URL = 'https://api.ipify.org?format=json';

export interface DiagnoseOptions {
  /** URL that returns the caller's IP, as plain text or JSON with an "ip" field. */
  echoUrl?: string;
  /** How many separate tunnels to open to learn whether the exit IP rotates. Default 3. */
  rounds?: number;
  /** Optional site to test through the proxy, e.g. the page your agent needs. */
  target?: string;
  /** Per-stage timeout in milliseconds. Default 8000. */
  timeoutMs?: number;
  /** Skip certificate checks on an https:// proxy's own TLS. Off by default. */
  insecureProxyTls?: boolean;
}

const BROWSER_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

const CHALLENGE_MARKERS: [RegExp, string][] = [
  [/cf-chl|challenge-platform|Just a moment\.\.\./i, 'Cloudflare challenge'],
  [/px-captcha|perimeterx/i, 'PerimeterX challenge'],
  [/datadome/i, 'DataDome challenge'],
  [/validateCaptcha|<title>\s*Robot Check/i, 'Amazon bot check'],
  [/g-recaptcha|hcaptcha|captcha/i, 'CAPTCHA'],
];

const portOf = (u: URL) => (u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80);
const hostOf = (u: URL) => u.hostname.replace(/^\[|\]$/g, '');

function extractIp(body: string): string | null {
  const text = body.trim();
  if (net.isIP(text)) return text;
  try {
    const j = JSON.parse(text);
    for (const k of ['ip', 'origin', 'query', 'address']) {
      const v = typeof j?.[k] === 'string' ? j[k].split(',')[0].trim() : null;
      if (v && net.isIP(v)) return v;
    }
  } catch {
    // not JSON
  }
  const m = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.exec(text);
  return m && net.isIP(m[0]) ? m[0] : null;
}

export function inferType(ips: string[]): InferredType {
  if (ips.length < 2) return 'unknown';
  const unique = new Set(ips).size;
  if (unique === 1) return 'static_or_sticky';
  if (unique === ips.length) return 'rotating';
  return 'mixed';
}

async function echoRound(p: ParsedProxy, address: string, echo: URL, opts: Required<Pick<DiagnoseOptions, 'timeoutMs'>> & DiagnoseOptions, rec?: Recorder) {
  const tunnel = await openTunnel(p, address, hostOf(echo), portOf(echo), opts.timeoutMs, rec, opts.insecureProxyTls);
  const t = Date.now();
  try {
    const res = await httpGet(tunnel, echo, opts.timeoutMs, { maxBody: 4096 });
    const ip = extractIp(res.body);
    if (res.status !== 200 || !ip) {
      throw new StageError('echo_failed', `${echo.host} answered HTTP ${res.status}${ip ? '' : ' with no IP address in the body'}`);
    }
    rec?.('exit_ip', true, Date.now() - t, ip);
    return ip;
  } catch (e) {
    rec?.('exit_ip', false, Date.now() - t);
    if (e instanceof StageError) throw e;
    throw new StageError('echo_failed', `${echo.host}: ${errMsg(e)}`);
  } finally {
    tunnel.destroy();
  }
}

/**
 * Check a bring-your-own proxy the way a Steel session would use it, and explain the first failure.
 * Never throws for proxy problems; the answer is in the returned report.
 */
export async function diagnose(rawUrl: string, options: DiagnoseOptions = {}): Promise<Report> {
  const opts = { ...options, timeoutMs: options.timeoutMs ?? 8000 };
  const rounds = Math.max(1, Math.min(10, Math.floor(options.rounds ?? 3)));
  const echo = new URL(options.echoUrl ?? DEFAULT_ECHO_URL);

  const parsed = parseProxyUrl(rawUrl);
  const report: Report = {
    ok: false,
    proxy: parsed.ok ? parsed.proxy.redacted : redactRaw(rawUrl),
    checked_from: 'this_machine',
    error: null,
    warnings: [...parsed.warnings],
    stages: [],
    context: {
      protocol: parsed.ok ? parsed.proxy.protocol : null,
      exit_ips: [],
      inferred_type: 'unknown',
      rounds: { attempted: 0, failed: 0 },
      target: null,
    },
  };

  const finish = (code: ErrorCode, ctx: Ctx): Report => {
    report.error = buildError(code, ctx);
    return report;
  };

  if (!parsed.ok) {
    report.stages.push({ stage: 'parse', ok: false });
    return finish(parsed.code, { detail: parsed.detail });
  }
  report.stages.push({ stage: 'parse', ok: true });

  const p = parsed.proxy;
  const ctx: Ctx = { host: p.host, port: p.port, protocol: p.protocol === 'socks5' ? 'SOCKS5' : 'HTTP CONNECT' };

  // DNS
  let address: string;
  let t = Date.now();
  try {
    address = await resolveHost(p.host, opts.timeoutMs);
    report.stages.push({ stage: 'dns', ok: true, ms: Date.now() - t, detail: address });
  } catch (e) {
    report.stages.push({ stage: 'dns', ok: false, ms: Date.now() - t });
    const se = e instanceof StageError ? e : new StageError('dns_failed', errMsg(e));
    return finish(se.code, { ...ctx, detail: se.detail });
  }

  // Tunnel + exit IP, several times. The first round must pass; later failures count as flakiness.
  const rec: Recorder = (stage, ok, ms, detail) => report.stages.push({ stage, ok, ms, detail });
  for (let i = 0; i < rounds; i++) {
    report.context.rounds.attempted++;
    try {
      const ip = await echoRound(p, address, echo, opts, i === 0 ? rec : undefined);
      report.context.exit_ips.push(ip);
    } catch (e) {
      const se = e instanceof StageError ? e : new StageError('tcp_failed', errMsg(e));
      if (i === 0) return finish(se.code, { ...ctx, detail: se.detail });
      report.context.rounds.failed++;
    }
  }

  const { failed, attempted } = report.context.rounds;
  if (failed > 0) {
    report.warnings.push({
      code: 'proxy_flaky',
      message: `${failed} of ${attempted} tunnels failed after the first one worked. A browser opens many connections per page, so expect intermittent "Proxy Connection Failed" errors in Steel sessions.`,
    });
  }

  const type = inferType(report.context.exit_ips);
  report.context.inferred_type = type;
  if (type === 'rotating' || type === 'mixed') {
    report.warnings.push({
      code: 'proxy_rotates_per_connection',
      message:
        'The exit IP changed between connections. A browser opens many connections per page, so one Steel session will reach sites from several IPs. That often triggers bot checks and drops logins. Use your provider\'s sticky-session option (usually a session ID in the username).',
    });
  }

  const handshake = report.stages.find((s) => s.stage === 'handshake');
  if (handshake?.ms !== undefined && handshake.ms > 3000) {
    report.warnings.push({
      code: 'proxy_slow',
      message: `The proxy took ${handshake.ms} ms to open a tunnel. Pages with many requests will load slowly and may hit navigation timeouts.`,
    });
  }

  if (options.target) {
    const targetResult = await checkTarget(p, address, new URL(options.target), opts, report);
    if (targetResult) return finish(targetResult.code, { ...ctx, detail: targetResult.detail });
  }

  report.ok = true;
  return report;
}

async function checkTarget(
  p: ParsedProxy,
  address: string,
  target: URL,
  opts: DiagnoseOptions & { timeoutMs: number },
  report: Report,
): Promise<{ code: ErrorCode; detail: string } | null> {
  const t = Date.now();
  const done = (ok: boolean, detail?: string) => report.stages.push({ stage: 'target', ok, ms: Date.now() - t, detail });

  let tunnel;
  try {
    tunnel = await openTunnel(p, address, hostOf(target), portOf(target), opts.timeoutMs, undefined, opts.insecureProxyTls);
  } catch (e) {
    done(false);
    const se = e instanceof StageError ? e : null;
    if (se?.code === 'proxy_denied') return { code: 'target_denied_by_proxy', detail: target.host };
    return { code: 'target_unreachable', detail: se?.detail ?? errMsg(e) };
  }

  let res;
  try {
    res = await httpGet(tunnel, target, opts.timeoutMs, { userAgent: BROWSER_UA });
  } catch (e) {
    done(false);
    const why = errMsg(e);
    return { code: 'target_unreachable', detail: why === 'ECONNRESET' ? 'connection reset during the request' : why };
  }

  report.context.target = { url: target.href, status: res.status, ms: Date.now() - t };
  const challenge = CHALLENGE_MARKERS.find(([re]) => re.test(res.body))?.[1];
  if (challenge) {
    done(true, `HTTP ${res.status}, ${challenge}`);
    report.warnings.push({
      code: 'target_challenge',
      message: `${target.host} returned a ${challenge} page. This check is a plain HTTP request, not a browser, so protected sites often do this. It means the IP isn't banned outright; Steel's stealth mode and CAPTCHA solving may still get through.`,
    });
    return null;
  }
  if ([401, 403, 407, 429, 451].includes(res.status)) {
    done(false, `HTTP ${res.status}`);
    return { code: 'target_blocked', detail: `HTTP ${res.status}` };
  }
  if (res.status === 202) {
    // A GET has nothing to "accept"; sites such as Amazon answer suspected bots with 202 and an interstitial.
    done(true, `HTTP 202, ${res.body.length} bytes`);
    report.warnings.push({
      code: 'target_soft_block',
      message: `${target.host} answered 202 Accepted (${res.body.length} bytes) instead of 200. Some sites, Amazon among them, send this to suspected bots in place of the real page. The IP isn't banned outright, but try the page in a Steel session before relying on this proxy.`,
    });
    return null;
  }
  done(true, `HTTP ${res.status}`);
  return null;
}
