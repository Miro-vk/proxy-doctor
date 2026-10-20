# steel-proxy-doctor

Check a bring-your-own proxy before a [Steel](https://steel.dev) browser session uses it, and get a plain explanation when it fails.

```
$ steel-proxy-doctor http://agent:wrong@proxy.example.com:8080

steel-proxy-doctor  http://agent:***@proxy.example.com:8080  (checked from this machine)

  ✓ parse
  ✓ dns          14 ms  203.0.113.20
  ✓ tcp          31 ms
  ✗ handshake    29 ms

  The proxy rejected the username or password (HTTP 407).
  Wrong input: username/password in useProxy.server
  Fix: Copy the credentials again from your provider's dashboard. Also check for an
  expired plan, a used-up bandwidth quota, or a username suffix your provider requires
  (zone, country or session parameters).
  Whose part failed: customer input
  Docs: https://docs.steel.dev/overview/stealth/proxies

  FAILED at stage "handshake".
```

## Why

Steel's team [published data](https://steel.dev/blog/developer-tools-come-with-an-assembly-required-sticker) showing customer-supplied proxies failed to open a tunnel about 9% of the time, against 0.4% for Steel-managed ones. Inside a session, all of those failures look the same: "Proxy Connection Failed". Steel doesn't retry or rotate a proxy it doesn't understand, which is the right call, but it leaves you guessing whether the password is wrong, the port is wrong, or the provider's pool is dead.

This tool runs the same steps a Steel session does, one at a time, from your side, and stops at the first one that breaks. Every failure answers three questions: what happened, which input was wrong, and how to fix it. That follows the error format Steel's CTO describes in [Errors Are the Interface Agents Actually Read](https://steel.dev/blog/errors-are-the-interface-agents-actually-read), and the `--json` output is meant for coding agents as much as people.

It needs no Steel API key and sends nothing to Steel.

## What it checks

| Stage | What happens | Typical failures it explains |
| --- | --- | --- |
| parse | Reads the URL the way your code would pass it to `useProxy.server` | missing `http://`, `#` or `/` in an unencoded password, `socks4://`, no port |
| dns | Resolves the proxy hostname | typo in the hostname |
| tcp | Connects to the proxy port | wrong port, proxy down, IP allowlist dropping you |
| tls | Only for `https://` proxies: TLS to the proxy itself | `https://` used for a plain HTTP port |
| handshake | HTTP `CONNECT` or SOCKS5 negotiation, with credentials | 407 / bad login, protocol mismatch (`http://` on a SOCKS port and the reverse), upstream 502 |
| exit_ip | Fetches your exit IP through the tunnel, several times | proxy can't reach the internet, TLS interception |
| target | Optional: fetches a page you name through the proxy | site blocks the exit IP, provider blocklists the domain |

After the exit-IP rounds it reports whether the proxy is **rotating** (new IP per connection) or **static/sticky**. A rotating proxy passes, but with a warning: a browser opens many connections per page, so one Steel session would show up at a site from several IPs.

## Usage

```bash
npx steel-proxy-doctor 'http://USER:PASS@HOST:PORT'

# keep the password out of shell history
export STEEL_PROXY_URL='http://USER:PASS@HOST:PORT'
npx steel-proxy-doctor

# also test the site your agent needs
npx steel-proxy-doctor --target https://www.example-shop.com

# machine-readable
npx steel-proxy-doctor --json
```

Options: `--target <url>`, `--rounds <n>` (default 3), `--echo <url>` (default `https://api.ipify.org?format=json`), `--timeout <ms>` (per stage, default 8000), `--json`, `--insecure-proxy-tls`. Exit code is 0 when everything passes, 1 when a check fails, 2 for bad usage.

### In code, before creating a session

```ts
import Steel from 'steel-sdk';
import { withProxyCheck, ProxyCheckError } from 'steel-proxy-doctor';

const client = new Steel();

try {
  const session = await withProxyCheck(client, {
    useProxy: { server: process.env.MY_PROXY_URL! },
  });
  // ...connect Playwright or Puppeteer as usual
} catch (e) {
  if (e instanceof ProxyCheckError) {
    console.error(e.report.error); // { stage, code, owner, what_happened, wrong_input, fix, docs }
  }
  throw e;
}
```

`withProxyCheck` only checks when there's a bring-your-own proxy (`useProxy.server`, Python-style `use_proxy.server`, or self-hosted `proxyUrl`). Sessions with `useProxy: true` go straight through. Passing results are cached for 60 seconds so a batch of sessions doesn't re-check the same proxy.

Or call the check directly:

```ts
import { diagnose } from 'steel-proxy-doctor';

const report = await diagnose(proxyUrl, { target: 'https://example.com' });
if (!report.ok) console.log(report.error.fix);
```

### As a Steel Skill for coding agents

`skill/steel-proxy-doctor/SKILL.md` tells Claude Code, Codex or any agent with a shell when to run the check (after `ERR_TUNNEL_CONNECTION_FAILED` and friends) and how to act on the JSON. For Claude Code, copy the folder into `~/.claude/skills/`.

## The report

```jsonc
{
  "ok": false,
  "proxy": "http://agent:***@proxy.example.com:8080", // password never appears anywhere in the report
  "checked_from": "this_machine",
  "error": {
    "stage": "handshake",
    "code": "auth_rejected",
    "owner": "customer_input", // customer_input | customer_proxy | target_site | network
    "what_happened": "The proxy rejected the username or password (HTTP 407).",
    "wrong_input": "username/password in useProxy.server",
    "fix": "Copy the credentials again from your provider's dashboard. ...",
    "docs": "https://docs.steel.dev/overview/stealth/proxies"
  },
  "warnings": [],            // soft problems on a passing proxy: rotation, flakiness, slowness, bot challenges
  "stages": [ /* each stage with ok and timing */ ],
  "context": {
    "protocol": "http",
    "exit_ips": [],
    "inferred_type": "unknown", // rotating | static_or_sticky | mixed | unknown
    "rounds": { "attempted": 1, "failed": 0 },
    "target": null
  }
}
```

## Limits worth knowing

- It runs from your machine, not Steel's cloud. If your provider authenticates by IP allowlist, a pass here doesn't prove Steel's IPs are allowed, and a failure here might not happen from Steel.
- The target check is a single plain HTTP request, not a browser. It catches IP bans and provider blocklists. Sites behind Cloudflare or similar will often return a challenge page; that's reported as a warning, since Steel's stealth mode and CAPTCHA solving may still get through.
- Rotation is inferred from a few connections. Providers that rotate on a timer rather than per connection will look static over a short check.
- Each round uses a little of your proxy bandwidth (a few KB).

## Development

```bash
npm install
npm test       # 31 tests against local HTTP CONNECT and SOCKS5 proxies that fail on purpose
npm run build
```

The test fixtures in `test/fixtures.ts` start real proxies on localhost: one that wants credentials, one that denies everything, one that rotates its exit IP (via 127.0.0.2 on Linux, or IPv6 loopback on macOS), a SOCKS5 server, and a port that accepts connections and never answers. No internet access needed.

There are no runtime dependencies; everything is built on Node's `net`, `tls` and `dns` modules.

## License

MIT
