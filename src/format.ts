import type { Report } from './types.js';

const TYPE_LABEL = {
  rotating: 'rotating (new IP per connection)',
  static_or_sticky: 'static or sticky (same IP every time)',
  mixed: 'mixed (IP changed on some connections)',
  unknown: 'unknown (needs 2+ rounds)',
} as const;

export function formatReport(r: Report, color = false): string {
  const c = (code: number, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const ok = c(32, '✓');
  const bad = c(31, '✗');
  const out: string[] = [];

  out.push(`${c(1, 'steel-proxy-doctor')}  ${r.proxy}  ${c(2, '(checked from this machine)')}`, '');
  for (const s of r.stages) {
    const ms = s.ms !== undefined ? `${s.ms} ms`.padStart(8) : ''.padStart(8);
    out.push(`  ${s.ok ? ok : bad} ${s.stage.padEnd(10)}${ms}  ${s.detail ?? ''}`.trimEnd());
  }
  out.push('');

  if (r.error) {
    const e = r.error;
    out.push(`  ${c(31, e.what_happened)}`);
    if (e.wrong_input) out.push(`  Wrong input: ${e.wrong_input}`);
    out.push(`  Fix: ${e.fix}`);
    out.push(`  Whose part failed: ${e.owner.replace('_', ' ')}`);
    out.push(`  Docs: ${e.docs}`);
  } else {
    if (r.context.exit_ips.length) {
      out.push(`  Exit IPs: ${r.context.exit_ips.join(', ')}`);
      out.push(`  Proxy type: ${TYPE_LABEL[r.context.inferred_type]}`);
    }
    if (r.context.target) out.push(`  Target: ${r.context.target.url} answered HTTP ${r.context.target.status}`);
  }

  if (r.warnings.length) {
    out.push('', `  ${c(33, 'Warnings')}`);
    for (const w of r.warnings) out.push(`  - ${w.message}`);
  }

  out.push('', r.ok ? `  ${c(32, 'OK')}: this proxy is ready for useProxy.server.` : `  ${c(31, 'FAILED')} at stage "${r.error?.stage}".`);
  return out.join('\n');
}

/** One line for exception messages and logs. */
export function oneLine(r: Report): string {
  if (!r.error) return `Proxy ${r.proxy} passed all checks.`;
  return `Proxy check failed at ${r.error.stage} (${r.error.code}) for ${r.proxy}: ${r.error.what_happened} Fix: ${r.error.fix}`;
}
