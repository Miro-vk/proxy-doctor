import type { DoctorError, ErrorCode, Owner, Stage } from './types.js';

export const DOCS_URL = 'https://docs.steel.dev/overview/stealth/proxies';

export interface Ctx {
  host?: string;
  port?: number;
  protocol?: string;
  detail?: string;
}

interface Entry {
  stage: Stage;
  owner: Owner;
  wrong: string | null;
  what: (c: Ctx) => string;
  fix: (c: Ctx) => string;
}

const SERVER = 'useProxy.server';
const where = (c: Ctx) => `${c.host}:${c.port}`;

const CATALOG: Record<ErrorCode, Entry> = {
  url_invalid: {
    stage: 'parse',
    owner: 'customer_input',
    wrong: SERVER,
    what: (c) => `The proxy URL couldn't be parsed${c.detail ? ` (${c.detail})` : ''}.`,
    fix: () => 'Use the form http://USERNAME:PASSWORD@HOST:PORT. https:// and socks5:// also work.',
  },
  url_missing_scheme: {
    stage: 'parse',
    owner: 'customer_input',
    wrong: SERVER,
    what: () => "The proxy URL has no scheme, so there's no way to tell which protocol the proxy speaks.",
    fix: () => 'Add http://, https:// or socks5:// to the front, for example http://USERNAME:PASSWORD@HOST:PORT.',
  },
  url_unsupported_scheme: {
    stage: 'parse',
    owner: 'customer_input',
    wrong: SERVER,
    what: (c) => `"${c.detail}://" isn't a proxy protocol Steel supports.`,
    fix: () => 'Steel accepts http://, https:// and socks5://. For a SOCKS4 proxy, ask your provider for an HTTP or SOCKS5 endpoint.',
  },
  url_bad_chars: {
    stage: 'parse',
    owner: 'customer_input',
    wrong: SERVER,
    what: (c) =>
      c.detail === 'whitespace'
        ? 'The proxy URL contains a space or line break.'
        : 'The username or password contains a character (#, / or ?) that cuts the URL short.',
    fix: () =>
      'Percent-encode the credentials before building the URL: encodeURIComponent(password) in JS, urllib.parse.quote(password, safe="") in Python. # becomes %23, / becomes %2F, ? becomes %3F.',
  },
  url_missing_host: {
    stage: 'parse',
    owner: 'customer_input',
    wrong: SERVER,
    what: () => 'The proxy URL has no hostname.',
    fix: () => 'Use the form http://USERNAME:PASSWORD@HOST:PORT.',
  },
  dns_not_found: {
    stage: 'dns',
    owner: 'customer_input',
    wrong: 'hostname in ' + SERVER,
    what: (c) => `The proxy hostname "${c.host}" doesn't resolve to any address.`,
    fix: () =>
      "Check the hostname for typos against your provider's dashboard. A private or internal hostname won't resolve from Steel's cloud either.",
  },
  dns_failed: {
    stage: 'dns',
    owner: 'network',
    wrong: null,
    what: (c) => `The DNS lookup for "${c.host}" failed (${c.detail}).`,
    fix: () => "Check this machine's DNS and run the check again. This one may be local to where you ran it.",
  },
  tcp_refused: {
    stage: 'tcp',
    owner: 'customer_proxy',
    wrong: 'port in ' + SERVER,
    what: (c) => `Nothing accepted the connection at ${where(c)}; it was refused.`,
    fix: () =>
      "Check the port. Providers often use a different port per protocol or session type. If the port is right, the proxy server is down; check your provider's status page.",
  },
  tcp_timeout: {
    stage: 'tcp',
    owner: 'customer_proxy',
    wrong: null,
    what: (c) => `Connecting to ${where(c)} timed out.`,
    fix: () =>
      'Either the proxy is down, or a firewall or IP allowlist is dropping the connection. If your provider uses IP allowlisting, the machine running Steel sessions must be on the list; username/password auth avoids this.',
  },
  tcp_unreachable: {
    stage: 'tcp',
    owner: 'customer_proxy',
    wrong: null,
    what: (c) => `${where(c)} is unreachable from this machine (${c.detail}).`,
    fix: () => 'Check that the host is a public address. Private IPs (10.x, 192.168.x) are not reachable from Steel Cloud.',
  },
  tcp_failed: {
    stage: 'tcp',
    owner: 'customer_proxy',
    wrong: null,
    what: (c) => `The TCP connection to ${where(c)} failed (${c.detail}).`,
    fix: () => 'Run the check again. If it keeps failing, contact your proxy provider with this error.',
  },
  tls_failed: {
    stage: 'tls',
    owner: 'customer_input',
    wrong: 'scheme in ' + SERVER,
    what: (c) => `The TLS handshake with the proxy at ${where(c)} failed (${c.detail}).`,
    fix: () =>
      'https:// means the connection to the proxy itself is encrypted, which few providers offer. If your provider lists this port as plain HTTP, use http://. Your traffic to HTTPS sites stays encrypted either way.',
  },
  auth_required: {
    stage: 'handshake',
    owner: 'customer_input',
    wrong: 'username/password in ' + SERVER,
    what: (c) => `The proxy requires credentials and none were sent (${c.detail}).`,
    fix: () =>
      "Add them: http://USERNAME:PASSWORD@HOST:PORT. If your provider uses IP allowlisting instead, this machine's IP isn't on the list, and Steel's IPs won't be either.",
  },
  auth_rejected: {
    stage: 'handshake',
    owner: 'customer_input',
    wrong: 'username/password in ' + SERVER,
    what: (c) => `The proxy rejected the username or password (${c.detail}).`,
    fix: () =>
      "Copy the credentials again from your provider's dashboard. Also check for an expired plan, a used-up bandwidth quota, or a username suffix your provider requires (zone, country or session parameters).",
  },
  socks_no_method: {
    stage: 'handshake',
    owner: 'customer_proxy',
    wrong: null,
    what: () => "The SOCKS5 proxy accepted neither username/password nor no-auth login.",
    fix: () => 'Confirm this endpoint supports username/password auth. Some providers only allow IP allowlisting on SOCKS ports.',
  },
  proxy_denied: {
    stage: 'handshake',
    owner: 'customer_proxy',
    wrong: null,
    what: (c) => `The proxy refused to open a tunnel to ${c.detail}.`,
    fix: () => "Your plan or provider may block this destination or port. Check the provider's allowed-domain and port rules.",
  },
  upstream_failed: {
    stage: 'handshake',
    owner: 'customer_proxy',
    wrong: null,
    what: (c) => `The proxy accepted the connection but couldn't reach ${c.detail}.`,
    fix: () =>
      "The proxy's exit node or upstream is failing. Steel doesn't rotate bring-your-own proxies, so retrying the Steel session reuses the same broken route. Pick another zone or pool, or contact your provider.",
  },
  handshake_timeout: {
    stage: 'handshake',
    owner: 'customer_proxy',
    wrong: 'scheme in ' + SERVER,
    what: (c) => `The proxy accepted the TCP connection but never answered the ${c.protocol} handshake.`,
    fix: () =>
      'The port may speak a different protocol: try socks5:// if you used http://, or the reverse. If the protocol is right, the proxy is overloaded.',
  },
  handshake_closed: {
    stage: 'handshake',
    owner: 'customer_proxy',
    wrong: 'scheme in ' + SERVER,
    what: (c) => `The proxy closed the connection without answering the ${c.protocol} handshake.`,
    fix: (c) =>
      c.protocol === 'SOCKS5'
        ? 'This usually means a protocol mismatch. If your provider lists this port as HTTP, change socks5:// to http://.'
        : 'This usually means a protocol mismatch. If your provider lists this port as SOCKS5, change http:// to socks5://. If it requires an encrypted connection to the proxy, use https://.',
  },
  handshake_bad_response: {
    stage: 'handshake',
    owner: 'customer_input',
    wrong: 'scheme in ' + SERVER,
    what: (c) => `The proxy replied, but not in ${c.protocol} format.`,
    fix: (c) =>
      c.detail === 'looks_http'
        ? 'This port speaks HTTP. Change socks5:// to http://.'
        : c.detail === 'looks_socks'
          ? 'This port looks like SOCKS. Change http:// to socks5://.'
          : 'Check which protocol your provider lists for this port.',
  },
  handshake_unexpected_status: {
    stage: 'handshake',
    owner: 'customer_proxy',
    wrong: null,
    what: (c) => `The proxy answered the tunnel request with "${c.detail}".`,
    fix: () => "Look up that status in your provider's docs, or send them this error.",
  },
  echo_failed: {
    stage: 'exit_ip',
    owner: 'customer_proxy',
    wrong: null,
    what: (c) => `A tunnel opened, but fetching the exit IP through it failed (${c.detail}).`,
    fix: () =>
      'The proxy may be intercepting TLS or blocking the IP-check site. Rerun with --echo set to another IP-echo URL. If Steel sessions still fail, send this to your provider.',
  },
  target_unreachable: {
    stage: 'target',
    owner: 'target_site',
    wrong: null,
    what: (c) => `The proxy works, but the target site couldn't be reached through it (${c.detail}).`,
    fix: () =>
      'The site may be dropping connections from this exit IP. Try a different country or pool, a sticky session, or Steel-managed proxies with useProxy: true.',
  },
  target_denied_by_proxy: {
    stage: 'target',
    owner: 'customer_proxy',
    wrong: null,
    what: (c) => `Your proxy refused to connect to ${c.detail}.`,
    fix: () =>
      'Many providers block categories such as ticketing, banking and government sites. Check your provider\'s blocklist or ask them to allow this domain.',
  },
  target_blocked: {
    stage: 'target',
    owner: 'target_site',
    wrong: null,
    what: (c) => `The target site answered ${c.detail} through this proxy.`,
    fix: () =>
      'The site is likely blocking this exit IP or its range. Try a residential or different-country pool, or Steel-managed proxies with useProxy: true.',
  },
};

export function buildError(code: ErrorCode, ctx: Ctx): DoctorError {
  const e = CATALOG[code];
  return {
    stage: e.stage,
    code,
    owner: e.owner,
    what_happened: e.what(ctx),
    wrong_input: e.wrong,
    fix: e.fix(ctx),
    docs: DOCS_URL,
  };
}

export function stageOf(code: ErrorCode): Stage {
  return CATALOG[code].stage;
}
