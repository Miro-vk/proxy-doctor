import { diagnose, type DiagnoseOptions } from './doctor.js';
import { oneLine } from './format.js';
import type { Report } from './types.js';

export class ProxyCheckError extends Error {
  readonly report: Report;
  constructor(report: Report) {
    super(oneLine(report));
    this.name = 'ProxyCheckError';
    this.report = report;
  }
}

export interface WithProxyCheckOptions extends DiagnoseOptions {
  /** Reuse a passing result for this long, so a batch of sessions doesn't re-check the same proxy. Default 60s. */
  cacheTtlMs?: number;
  /** Called with every passing report, e.g. to log warnings such as a rotating exit IP. */
  onReport?: (report: Report) => void;
}

interface SessionsClient<P, R> {
  sessions: { create(params: P, ...rest: any[]): Promise<R> };
}

const cache = new Map<string, { at: number; report: Report }>();

/** Pull a BYO proxy URL out of session params: Steel Cloud's useProxy.server, Python's use_proxy, or self-hosted proxyUrl. */
export function proxyUrlFrom(params: unknown): string | null {
  const p = params as Record<string, any> | null | undefined;
  if (!p) return null;
  for (const key of ['useProxy', 'use_proxy']) {
    const v = p[key];
    if (v && typeof v === 'object' && typeof v.server === 'string') return v.server;
  }
  for (const key of ['proxyUrl', 'proxy_url']) if (typeof p[key] === 'string') return p[key];
  return null;
}

/**
 * Check a bring-your-own proxy, then create the Steel session.
 * Throws ProxyCheckError (with the full report) instead of starting a session that would fail on the proxy.
 * Sessions without a BYO proxy pass straight through.
 */
export async function withProxyCheck<P, R>(client: SessionsClient<P, R>, params: P, opts: WithProxyCheckOptions = {}): Promise<R> {
  const url = proxyUrlFrom(params);
  if (url) {
    const ttl = opts.cacheTtlMs ?? 60_000;
    const key = `${url}\n${opts.target ?? ''}`;
    const hit = cache.get(key);
    let report: Report;
    if (hit && Date.now() - hit.at < ttl) {
      report = hit.report;
    } else {
      report = await diagnose(url, { rounds: 2, ...opts });
      if (report.ok) cache.set(key, { at: Date.now(), report });
    }
    if (!report.ok) throw new ProxyCheckError(report);
    opts.onReport?.(report);
  }
  return client.sessions.create(params);
}

export function clearProxyCheckCache() {
  cache.clear();
}
