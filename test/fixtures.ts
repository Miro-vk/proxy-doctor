import http from 'node:http';
import net from 'node:net';
import { Reader } from '../src/net.js';

export interface Running {
  port: number;
  close(): Promise<void>;
}

/** Track sockets so close() never hangs on a held-open connection. */
function closable(server: net.Server): Running['close'] {
  const sockets = new Set<net.Socket>();
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });
  return () =>
    new Promise((resolve) => {
      for (const s of sockets) s.destroy();
      server.close(() => resolve());
    });
}

async function listen(server: net.Server, host = '127.0.0.1'): Promise<Running> {
  const close = closable(server);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  return { port: (server.address() as net.AddressInfo).port, close };
}

function canListen(host: string): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(0, host, () => s.close(() => resolve(true)));
  });
}

/**
 * How a fake rotating proxy can make the echo server see different client IPs on this machine.
 * Linux answers on all of 127.0.0.0/8, so we can send from 127.0.0.2. macOS only configures
 * 127.0.0.1, but usually has IPv6, so we alternate with ::1. Null means neither works here.
 */
export type RotationMode = 'loopback-alias' | 'ipv6' | null;
let rotationMode: Promise<RotationMode> | undefined;
export function detectRotationMode(): Promise<RotationMode> {
  rotationMode ??= (async () => {
    if (await canListen('127.0.0.2')) return 'loopback-alias';
    if (await canListen('::1')) return 'ipv6';
    return null;
  })();
  return rotationMode;
}

/** Echo server: returns the caller's IP, plus a few pages that act like a protected site. */
export function startEcho(): Promise<Running> {
  const server = http.createServer((req, res) => {
    if (req.url === '/blocked') {
      res.writeHead(403, { 'content-type': 'text/html' });
      return res.end('<h1>Access denied</h1>');
    }
    if (req.url === '/challenge') {
      res.writeHead(503, { 'content-type': 'text/html' });
      return res.end('<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/x.js"></script>');
    }
    if (req.url === '/soft-block') {
      res.writeHead(202, { 'content-type': 'text/html' });
      return res.end('<html><body></body></html>');
    }
    if (req.url === '/robot-check') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end('<title>Robot Check</title><form action="/errors/validateCaptcha"></form>');
    }
    if (req.url === '/json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ ip: req.socket.remoteAddress?.replace('::ffff:', '') }));
    }
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(req.socket.remoteAddress?.replace('::ffff:', ''));
  });
  // Dual-stack when we rotate over IPv6, so the proxy can reach it over both 127.0.0.1 and ::1.
  return detectRotationMode().then((mode) => listen(server, mode === 'ipv6' ? '::' : '127.0.0.1'));
}

/** HTTP CONNECT proxy. rotate=true makes alternate tunnels reach the echo server from a different IP. */
export async function startHttpProxy(opts: { auth?: { user: string; pass: string }; deny?: boolean; rotate?: boolean } = {}): Promise<Running> {
  let n = 0;
  const mode = opts.rotate ? await detectRotationMode() : null;
  const server = http.createServer((_req, res) => {
    res.writeHead(405);
    res.end();
  });
  server.on('connect', (req, client: net.Socket, head: Buffer) => {
    client.on('error', () => {});
    if (opts.auth) {
      const expected = 'Basic ' + Buffer.from(`${opts.auth.user}:${opts.auth.pass}`).toString('base64');
      if (req.headers['proxy-authorization'] !== expected) {
        client.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="test"\r\n\r\n');
        return;
      }
    }
    if (opts.deny) {
      client.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      return;
    }
    const i = req.url!.lastIndexOf(':');
    const requested = req.url!.slice(0, i).replace(/^\[|\]$/g, '');
    const port = Number(req.url!.slice(i + 1));
    const second = opts.rotate && requested === '127.0.0.1' && n++ % 2 === 1;
    const up =
      second && mode === 'ipv6'
        ? net.connect({ host: '::1', port })
        : net.connect({ host: requested, port, localAddress: second && mode === 'loopback-alias' ? '127.0.0.2' : undefined });
    up.once('connect', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) up.write(head);
      up.pipe(client);
      client.pipe(up);
    });
    up.once('error', () => client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'));
    client.on('close', () => up.destroy());
  });
  return listen(server);
}

/** Minimal SOCKS5 proxy (RFC 1928/1929), CONNECT only. */
export function startSocks5(opts: { auth?: { user: string; pass: string } } = {}): Promise<Running> {
  const server = net.createServer(async (c) => {
    c.on('error', () => {});
    const r = new Reader(c);
    const deadline = Date.now() + 5000;
    try {
      const [ver, count] = await r.bytes(2, deadline);
      if (ver !== 5) return void c.destroy();
      const methods = [...(await r.bytes(count, deadline))];
      if (opts.auth) {
        if (!methods.includes(2)) return void c.end(Buffer.from([5, 0xff]));
        c.write(Buffer.from([5, 2]));
        const [, ulen] = await r.bytes(2, deadline);
        const user = (await r.bytes(ulen, deadline)).toString();
        const [plen] = await r.bytes(1, deadline);
        const pass = (await r.bytes(plen, deadline)).toString();
        if (user !== opts.auth.user || pass !== opts.auth.pass) return void c.end(Buffer.from([1, 1]));
        c.write(Buffer.from([1, 0]));
      } else {
        if (!methods.includes(0)) return void c.end(Buffer.from([5, 0xff]));
        c.write(Buffer.from([5, 0]));
      }
      const [, , , atyp] = await r.bytes(4, deadline);
      let host: string;
      if (atyp === 1) host = [...(await r.bytes(4, deadline))].join('.');
      else if (atyp === 3) {
        const [len] = await r.bytes(1, deadline);
        host = (await r.bytes(len, deadline)).toString();
      } else return void c.end(Buffer.from([5, 8, 0, 1, 0, 0, 0, 0, 0, 0]));
      const port = (await r.bytes(2, deadline)).readUInt16BE(0);
      r.detach();
      const up = net.connect({ host, port });
      up.once('connect', () => {
        c.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
        up.pipe(c);
        c.pipe(up);
      });
      up.once('error', () => c.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])));
      c.on('close', () => up.destroy());
    } catch {
      c.destroy();
    }
  });
  return listen(server);
}

/** Accepts TCP connections and never says anything. */
export function startSilent(): Promise<Running> {
  return listen(net.createServer((c) => c.on('error', () => {})));
}

/** A port with nothing listening on it. */
export async function closedPort(): Promise<number> {
  const s = await listen(net.createServer());
  await s.close();
  return s.port;
}
