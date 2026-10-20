import type { ErrorCode, ParsedProxy, ProxyProtocol, Warning } from './types.js';

export type ParseResult =
  | { ok: true; proxy: ParsedProxy; warnings: Warning[] }
  | { ok: false; code: ErrorCode; detail?: string; warnings: Warning[] };

const DEFAULT_PORTS: Record<ProxyProtocol, number> = { http: 80, https: 443, socks5: 1080 };

/** Hide credentials in a string we couldn't parse, so it is still safe to print. */
export function redactRaw(raw: string): string {
  const s = raw.trim();
  if (s.includes('://')) return s.replace(/:\/\/[^/]*@/, '://***@');
  return s.replace(/^[^/]*@/, '***@');
}

export function parseProxyUrl(raw: string): ParseResult {
  const warnings: Warning[] = [];
  const fail = (code: ErrorCode, detail?: string): ParseResult => ({ ok: false, code, detail, warnings });

  const input = raw.trim();
  if (input !== raw) {
    warnings.push({ code: 'url_whitespace', message: 'The proxy URL had leading or trailing whitespace. It was trimmed here, but strip it in your code too.' });
  }
  if (!input) return fail('url_invalid', 'empty string');
  if (/\s/.test(input)) return fail('url_bad_chars', 'whitespace');

  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//.exec(input);
  if (!schemeMatch) return fail('url_missing_scheme');

  const scheme = schemeMatch[1].toLowerCase();
  let protocol: ProxyProtocol;
  if (scheme === 'http' || scheme === 'https') protocol = scheme;
  else if (scheme === 'socks5' || scheme === 'socks5h') protocol = 'socks5';
  else return fail('url_unsupported_scheme', scheme);
  if (scheme === 'socks5h') {
    warnings.push({ code: 'url_socks5h', message: 'socks5h:// was read as socks5://. Hostnames are sent to the proxy unresolved either way.' });
  }

  // Look at the raw authority before the URL parser can quietly reinterpret it.
  const rest = input.slice(schemeMatch[0].length);
  const at = rest.lastIndexOf('@');
  const userinfo = at === -1 ? '' : rest.slice(0, at);
  if (/[#/?]/.test(userinfo)) return fail('url_bad_chars', 'userinfo');
  if (userinfo.includes('@')) {
    warnings.push({
      code: 'url_unencoded_at',
      message: 'The username or password contains a raw "@". This tool read it correctly, but some clients split the URL at the first "@". Encode it as %40.',
    });
  }
  const afterAuth = at === -1 ? rest : rest.slice(at + 1);
  const hostPort = afterAuth.split(/[/?#]/)[0];
  const explicitPort = /:\d+$/.test(hostPort);
  const pathPart = afterAuth.slice(hostPort.length);

  let url: URL;
  try {
    url = new URL(input);
  } catch (e) {
    return fail('url_invalid', (e as Error).message);
  }

  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!host) return fail('url_missing_host');

  let port = url.port ? Number(url.port) : DEFAULT_PORTS[protocol];
  if (!explicitPort) {
    warnings.push({
      code: 'url_default_port',
      message: `No port given, so ${port} was assumed. Proxy providers rarely use the default port; copy the exact port from your provider.`,
    });
  } else if (!url.port) {
    port = DEFAULT_PORTS[protocol];
  }

  if (pathPart && pathPart !== '/') {
    warnings.push({ code: 'url_has_path', message: `The URL has a path or query ("${pathPart}") that proxies ignore. Remove it.` });
  }

  let username: string | undefined;
  let password: string | undefined;
  try {
    username = url.username ? decodeURIComponent(url.username) : undefined;
    password = url.password ? decodeURIComponent(url.password) : undefined;
  } catch {
    return fail('url_invalid', 'bad percent-encoding in credentials');
  }
  if (username !== undefined && password === undefined) {
    warnings.push({ code: 'url_empty_password', message: 'A username was given with no password. Most providers need both.' });
  }
  if (protocol === 'socks5' && ((username?.length ?? 0) > 255 || (password?.length ?? 0) > 255)) {
    return fail('url_invalid', 'SOCKS5 usernames and passwords are limited to 255 bytes');
  }

  const hostForUrl = host.includes(':') ? `[${host}]` : host;
  const creds = username !== undefined ? `${encodeURIComponent(username)}:***@` : '';
  return {
    ok: true,
    warnings,
    proxy: { protocol, host, port, username, password, redacted: `${protocol}://${creds}${hostForUrl}:${port}` },
  };
}
