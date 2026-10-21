import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { clearProxyCheckCache, diagnose, parseProxyUrl, ProxyCheckError, withProxyCheck } from '../src/index.js';
import { closedPort, detectRotationMode, startEcho, startHttpProxy, startSilent, startSocks5, type Running } from './fixtures.js';

const AUTH = { user: 'agent', pass: 's3cret-pw' };
let echo: Running;
let echoUrl: string;
const fast = (extra = {}) => ({ echoUrl, timeoutMs: 1500, ...extra });

before(async () => {
  echo = await startEcho();
  echoUrl = `http://127.0.0.1:${echo.port}/`;
});
after(() => echo.close());

describe('parsing', () => {
  test('missing scheme', () => {
    const r = parseProxyUrl('user:pass@proxy.example.com:8080');
    assert.equal(r.ok, false);
    assert.equal(!r.ok && r.code, 'url_missing_scheme');
  });

  test('unsupported scheme', () => {
    const r = parseProxyUrl('socks4://proxy.example.com:1080');
    assert.equal(!r.ok && r.code, 'url_unsupported_scheme');
  });

  test('# in password cuts the URL short', () => {
    const r = parseProxyUrl('http://user:pa#ss@proxy.example.com:8080');
    assert.equal(!r.ok && r.code, 'url_bad_chars');
  });

  test('raw @ in password parses, with a warning', () => {
    const r = parseProxyUrl('http://user:p@ss@proxy.example.com:8080');
    assert.ok(r.ok);
    assert.equal(r.ok && r.proxy.password, 'p@ss');
    assert.equal(r.ok && r.proxy.host, 'proxy.example.com');
    assert.ok(r.warnings.some((w) => w.code === 'url_unencoded_at'));
  });

  test('missing port warns and assumes the default', () => {
    const r = parseProxyUrl('socks5://proxy.example.com');
    assert.ok(r.ok);
    assert.equal(r.ok && r.proxy.port, 1080);
    assert.ok(r.warnings.some((w) => w.code === 'url_default_port'));
  });

  test('redacted form never contains the password', () => {
    const r = parseProxyUrl('http://agent:s3cret-pw@proxy.example.com:8080');
    assert.ok(r.ok);
    assert.equal(r.ok && r.proxy.redacted, 'http://agent:***@proxy.example.com:8080');
  });
});

describe('network failures', () => {
  test('unparseable URL fails at parse with no network calls', async () => {
    const r = await diagnose('proxy.example.com:8080', fast());
    assert.equal(r.ok, false);
    assert.equal(r.error?.stage, 'parse');
    assert.equal(r.error?.owner, 'customer_input');
  });

  test('hostname that does not resolve', async () => {
    const r = await diagnose('http://no-such-proxy.invalid:8080', fast());
    assert.equal(r.error?.stage, 'dns');
  });

  test('nothing listening on the port', async () => {
    const port = await closedPort();
    const r = await diagnose(`http://127.0.0.1:${port}`, fast());
    assert.equal(r.error?.code, 'tcp_refused');
    assert.equal(r.error?.wrong_input, 'port in useProxy.server');
  });

  test('proxy that accepts TCP and never answers', async () => {
    const s = await startSilent();
    try {
      const r = await diagnose(`http://127.0.0.1:${s.port}`, fast({ timeoutMs: 500 }));
      assert.equal(r.error?.code, 'handshake_timeout');
    } finally {
      await s.close();
    }
  });

  test('proxy cannot reach the destination (502)', async () => {
    const proxy = await startHttpProxy();
    const dead = await closedPort();
    try {
      const r = await diagnose(`http://127.0.0.1:${proxy.port}`, fast({ echoUrl: `http://127.0.0.1:${dead}/` }));
      assert.equal(r.error?.code, 'upstream_failed');
      assert.equal(r.error?.owner, 'customer_proxy');
      assert.match(r.error!.fix, /doesn't rotate/);
    } finally {
      await proxy.close();
    }
  });

  test('proxy refuses the destination (403)', async () => {
    const proxy = await startHttpProxy({ deny: true });
    try {
      const r = await diagnose(`http://127.0.0.1:${proxy.port}`, fast());
      assert.equal(r.error?.code, 'proxy_denied');
    } finally {
      await proxy.close();
    }
  });
});

describe('HTTP CONNECT proxies', () => {
  let open: Running, authed: Running, rotating: Running;
  before(async () => {
    open = await startHttpProxy();
    authed = await startHttpProxy({ auth: AUTH });
    rotating = await startHttpProxy({ rotate: true });
  });
  after(async () => {
    await Promise.all([open.close(), authed.close(), rotating.close()]);
  });

  test('working static proxy', async () => {
    const r = await diagnose(`http://127.0.0.1:${open.port}`, fast());
    assert.equal(r.ok, true, JSON.stringify(r.error));
    assert.deepEqual(r.context.exit_ips, ['127.0.0.1', '127.0.0.1', '127.0.0.1']);
    assert.equal(r.context.inferred_type, 'static_or_sticky');
    assert.deepEqual(
      r.stages.map((s) => s.stage),
      ['parse', 'dns', 'tcp', 'handshake', 'exit_ip'],
    );
  });

  test('JSON echo endpoints work too', async () => {
    const r = await diagnose(`http://127.0.0.1:${open.port}`, fast({ echoUrl: `http://127.0.0.1:${echo.port}/json`, rounds: 1 }));
    assert.equal(r.ok, true);
    assert.deepEqual(r.context.exit_ips, ['127.0.0.1']);
    assert.equal(r.context.inferred_type, 'unknown');
  });

  test('rotating proxy is detected and warned about', async (t) => {
    const mode = await detectRotationMode();
    if (!mode) return t.skip('this machine has neither 127.0.0.2 nor IPv6 loopback to simulate rotation');
    const r = await diagnose(`http://127.0.0.1:${rotating.port}`, fast({ rounds: 2 }));
    assert.equal(r.ok, true, JSON.stringify(r.error));
    assert.deepEqual(r.context.exit_ips, ['127.0.0.1', mode === 'ipv6' ? '::1' : '127.0.0.2']);
    assert.equal(r.context.inferred_type, 'rotating');
    assert.ok(r.warnings.some((w) => w.code === 'proxy_rotates_per_connection'));
  });

  test('credentials missing', async () => {
    const r = await diagnose(`http://127.0.0.1:${authed.port}`, fast());
    assert.equal(r.error?.code, 'auth_required');
  });

  test('credentials wrong', async () => {
    const r = await diagnose(`http://agent:wrong@127.0.0.1:${authed.port}`, fast());
    assert.equal(r.error?.code, 'auth_rejected');
    assert.equal(r.error?.wrong_input, 'username/password in useProxy.server');
  });

  test('credentials right', async () => {
    const r = await diagnose(`http://${AUTH.user}:${AUTH.pass}@127.0.0.1:${authed.port}`, fast());
    assert.equal(r.ok, true);
  });

  test('the password never appears in the report', async () => {
    const r = await diagnose(`http://agent:${AUTH.pass}@127.0.0.1:${authed.port}`, fast());
    assert.ok(!JSON.stringify(r).includes(AUTH.pass));
  });

  test('target site blocking the exit IP', async () => {
    const r = await diagnose(`http://127.0.0.1:${open.port}`, fast({ rounds: 1, target: `http://127.0.0.1:${echo.port}/blocked` }));
    assert.equal(r.ok, false);
    assert.equal(r.error?.code, 'target_blocked');
    assert.equal(r.error?.owner, 'target_site');
  });

  test('202 from a GET is flagged as a likely soft block', async () => {
    const r = await diagnose(`http://127.0.0.1:${open.port}`, fast({ rounds: 1, target: `http://127.0.0.1:${echo.port}/soft-block` }));
    assert.equal(r.ok, true);
    assert.ok(r.warnings.some((w) => w.code === 'target_soft_block'));
  });

  test('Amazon robot check page is recognized', async () => {
    const r = await diagnose(`http://127.0.0.1:${open.port}`, fast({ rounds: 1, target: `http://127.0.0.1:${echo.port}/robot-check` }));
    assert.equal(r.ok, true);
    assert.ok(r.warnings.some((w) => w.code === 'target_challenge' && /Amazon bot check/.test(w.message)));
  });

  test('bot challenge is a warning, not a failure', async () => {
    const r = await diagnose(`http://127.0.0.1:${open.port}`, fast({ rounds: 1, target: `http://127.0.0.1:${echo.port}/challenge` }));
    assert.equal(r.ok, true);
    assert.ok(r.warnings.some((w) => w.code === 'target_challenge'));
  });
});

describe('SOCKS5 proxies', () => {
  let socks: Running, socksAuth: Running, httpProxy: Running;
  before(async () => {
    socks = await startSocks5();
    socksAuth = await startSocks5({ auth: AUTH });
    httpProxy = await startHttpProxy();
  });
  after(async () => {
    await Promise.all([socks.close(), socksAuth.close(), httpProxy.close()]);
  });

  test('working SOCKS5 proxy', async () => {
    const r = await diagnose(`socks5://127.0.0.1:${socks.port}`, fast());
    assert.equal(r.ok, true, JSON.stringify(r.error));
    assert.equal(r.context.inferred_type, 'static_or_sticky');
  });

  test('SOCKS5 with credentials', async () => {
    const r = await diagnose(`socks5://${AUTH.user}:${AUTH.pass}@127.0.0.1:${socksAuth.port}`, fast());
    assert.equal(r.ok, true, JSON.stringify(r.error));
  });

  test('SOCKS5 credentials missing', async () => {
    const r = await diagnose(`socks5://127.0.0.1:${socksAuth.port}`, fast());
    assert.equal(r.error?.code, 'auth_required');
  });

  test('SOCKS5 credentials wrong', async () => {
    const r = await diagnose(`socks5://agent:nope@127.0.0.1:${socksAuth.port}`, fast());
    assert.equal(r.error?.code, 'auth_rejected');
  });

  test('http:// pointed at a SOCKS port explains the mismatch', async () => {
    const r = await diagnose(`http://127.0.0.1:${socks.port}`, fast());
    assert.equal(r.ok, false);
    assert.equal(r.error?.stage, 'handshake');
    assert.match(r.error!.fix, /socks5:\/\//);
  });

  test('socks5:// pointed at an HTTP proxy says to use http://', async () => {
    const r = await diagnose(`socks5://127.0.0.1:${httpProxy.port}`, fast());
    assert.equal(r.error?.code, 'handshake_bad_response');
    assert.equal(r.error?.fix, 'This port speaks HTTP. Change socks5:// to http://.');
  });
});

describe('withProxyCheck', () => {
  let proxy: Running;
  before(async () => {
    proxy = await startHttpProxy();
  });
  after(() => proxy.close());

  const fakeClient = () => {
    const calls: unknown[] = [];
    return { calls, sessions: { create: async (p: unknown) => (calls.push(p), { id: 'sess_123' }) } };
  };

  test('creates the session when the proxy passes', async () => {
    clearProxyCheckCache();
    const client = fakeClient();
    const s = await withProxyCheck(client, { useProxy: { server: `http://127.0.0.1:${proxy.port}` } }, fast());
    assert.equal(s.id, 'sess_123');
    assert.equal(client.calls.length, 1);
  });

  test('throws ProxyCheckError and skips the session when the proxy fails', async () => {
    const client = fakeClient();
    const port = await closedPort();
    await assert.rejects(
      withProxyCheck(client, { useProxy: { server: `http://127.0.0.1:${port}` } }, fast()),
      (e: unknown) => e instanceof ProxyCheckError && e.report.error?.code === 'tcp_refused' && /Fix:/.test(e.message),
    );
    assert.equal(client.calls.length, 0);
  });

  test('passes through sessions without a BYO proxy', async () => {
    const client = fakeClient();
    await withProxyCheck(client, { useProxy: true }, fast());
    assert.equal(client.calls.length, 1);
  });

  test('reads the Python and self-hosted spellings', async () => {
    clearProxyCheckCache();
    const client = fakeClient();
    const port = await closedPort();
    await assert.rejects(withProxyCheck(client, { use_proxy: { server: `http://127.0.0.1:${port}` } }, fast()), ProxyCheckError);
    await assert.rejects(withProxyCheck(client, { proxyUrl: `http://127.0.0.1:${port}` }, fast()), ProxyCheckError);
  });
});
