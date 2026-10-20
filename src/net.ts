import net from 'node:net';
import tls from 'node:tls';
import { lookup } from 'node:dns/promises';
import type { Duplex } from 'node:stream';
import type { ErrorCode, ParsedProxy, Stage } from './types.js';

/** A failure tied to an entry in the error catalog. */
export class StageError extends Error {
  constructor(
    public readonly code: ErrorCode,
    public readonly detail?: string,
  ) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'StageError';
  }
}

export class ReadTimeout extends Error {
  constructor() {
    super('timed out waiting for a response');
  }
}
export class ReadClosed extends Error {
  constructor() {
    super('connection closed before a full response');
  }
}
export class ReadOverflow extends Error {
  constructor() {
    super('response header too large');
  }
}

export const errMsg = (e: unknown): string => {
  const err = e as NodeJS.ErrnoException;
  return err?.code || err?.message || String(e);
};

/** Buffers a socket's data so handshakes can read exact byte counts or up to a delimiter. */
export class Reader {
  private buf: Buffer = Buffer.alloc(0);
  private ended = false;
  private waiter: (() => void) | null = null;

  private readonly onData = (d: Buffer) => {
    this.buf = Buffer.concat([this.buf, d]);
    this.wake();
  };
  private readonly onEnd = () => {
    this.ended = true;
    this.wake();
  };

  constructor(private readonly sock: Duplex) {
    sock.on('data', this.onData);
    sock.on('end', this.onEnd);
    sock.on('close', this.onEnd);
    sock.on('error', this.onEnd);
    sock.resume(); // a previous Reader may have paused it
  }

  get buffered(): Buffer {
    return this.buf;
  }

  private wake() {
    const w = this.waiter;
    this.waiter = null;
    w?.();
  }

  private wait(deadline: number): Promise<void> {
    const ms = deadline - Date.now();
    if (ms <= 0) return Promise.reject(new ReadTimeout());
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        this.waiter = null;
        reject(new ReadTimeout());
      }, ms);
      this.waiter = () => {
        clearTimeout(t);
        resolve();
      };
    });
  }

  async bytes(n: number, deadline: number): Promise<Buffer> {
    while (this.buf.length < n) {
      if (this.ended) throw new ReadClosed();
      await this.wait(deadline);
    }
    const out = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }

  async until(delim: string, deadline: number, max = 64 * 1024): Promise<Buffer> {
    const d = Buffer.from(delim);
    for (;;) {
      const i = this.buf.indexOf(d);
      if (i !== -1) {
        const out = this.buf.subarray(0, i);
        this.buf = this.buf.subarray(i + d.length);
        return out;
      }
      if (this.buf.length > max) throw new ReadOverflow();
      if (this.ended) throw new ReadClosed();
      await this.wait(deadline);
    }
  }

  /** Read to end of stream, up to max bytes. Returns what it has on timeout. */
  async rest(deadline: number, max: number): Promise<Buffer> {
    try {
      while (!this.ended && this.buf.length < max) await this.wait(deadline);
    } catch (e) {
      if (!(e instanceof ReadTimeout)) throw e;
    }
    const out = this.buf.subarray(0, max);
    this.buf = Buffer.alloc(0);
    return out;
  }

  detach() {
    this.sock.off('data', this.onData);
    this.sock.off('end', this.onEnd);
    this.sock.off('close', this.onEnd);
    this.sock.off('error', this.onEnd);
    this.sock.pause();
  }
}

export async function resolveHost(host: string, timeoutMs: number): Promise<string> {
  if (net.isIP(host)) return host;
  let timer: NodeJS.Timeout | undefined;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new StageError('dns_failed', 'timed out')), timeoutMs);
    });
    const r = await Promise.race([lookup(host), timeout]);
    return r.address;
  } catch (e) {
    if (e instanceof StageError) throw e;
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOTFOUND') throw new StageError('dns_not_found');
    throw new StageError('dns_failed', code ?? errMsg(e));
  } finally {
    clearTimeout(timer);
  }
}

export function connectTcp(address: string, port: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: address, port });
    const timer = setTimeout(() => {
      s.destroy();
      reject(new StageError('tcp_timeout'));
    }, timeoutMs);
    const onError = (e: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      s.destroy();
      if (e.code === 'ECONNREFUSED') reject(new StageError('tcp_refused'));
      else if (e.code === 'ETIMEDOUT') reject(new StageError('tcp_timeout'));
      else if (e.code === 'EHOSTUNREACH' || e.code === 'ENETUNREACH') reject(new StageError('tcp_unreachable', e.code));
      else reject(new StageError('tcp_failed', errMsg(e)));
    };
    s.once('error', onError);
    s.once('connect', () => {
      clearTimeout(timer);
      s.off('error', onError);
      s.on('error', () => {}); // later errors surface through readers
      resolve(s);
    });
  });
}

export function tlsConnect(socket: net.Socket, servername: string, timeoutMs: number, rejectUnauthorized = true): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const opts: tls.ConnectionOptions = { socket, rejectUnauthorized, ALPNProtocols: ['http/1.1'] };
    if (!net.isIP(servername)) opts.servername = servername;
    const t = tls.connect(opts);
    const timer = setTimeout(() => {
      t.destroy();
      reject(new Error('TLS handshake timed out'));
    }, timeoutMs);
    t.once('error', (e) => {
      clearTimeout(timer);
      t.destroy();
      reject(e);
    });
    t.once('secureConnect', () => {
      clearTimeout(timer);
      t.on('error', () => {});
      resolve(t);
    });
  });
}

const hostPort = (host: string, port: number) => (host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`);

function handshakeReadError(e: unknown, protocol: string): StageError {
  if (e instanceof StageError) return e;
  if (e instanceof ReadTimeout) return new StageError('handshake_timeout');
  if (e instanceof ReadOverflow) return new StageError('handshake_bad_response');
  if (e instanceof ReadClosed) return new StageError('handshake_closed');
  return new StageError('handshake_closed', `${protocol}: ${errMsg(e)}`);
}

export async function httpConnect(s: Duplex, p: ParsedProxy, host: string, port: number, deadline: number): Promise<void> {
  const target = hostPort(host, port);
  const lines = [`CONNECT ${target} HTTP/1.1`, `Host: ${target}`, 'User-Agent: steel-proxy-doctor'];
  if (p.username !== undefined) {
    const token = Buffer.from(`${p.username}:${p.password ?? ''}`).toString('base64');
    lines.push(`Proxy-Authorization: Basic ${token}`);
  }
  s.write(lines.join('\r\n') + '\r\n\r\n');

  const r = new Reader(s);
  let head: string;
  try {
    head = (await r.until('\r\n\r\n', deadline, 16 * 1024)).toString('latin1');
  } catch (e) {
    const b = r.buffered;
    if (e instanceof ReadClosed && b.length >= 2 && b[0] === 0x05) throw new StageError('handshake_bad_response', 'looks_socks');
    throw handshakeReadError(e, 'http');
  }
  if (!head.startsWith('HTTP/')) {
    throw new StageError('handshake_bad_response', head.charCodeAt(0) === 0x05 ? 'looks_socks' : undefined);
  }
  const statusLine = head.split('\r\n')[0];
  const status = Number(statusLine.split(' ')[1]);
  if (status >= 200 && status < 300) {
    r.detach();
    return;
  }
  if (status === 407) throw new StageError(p.username !== undefined ? 'auth_rejected' : 'auth_required', 'HTTP 407');
  if (status === 403) throw new StageError('proxy_denied', `${target} (HTTP 403)`);
  if (status === 502 || status === 503 || status === 504) throw new StageError('upstream_failed', `${target} (HTTP ${status})`);
  throw new StageError('handshake_unexpected_status', statusLine);
}

const SOCKS_REPLIES: Record<number, string> = {
  1: 'general failure',
  2: 'not allowed by ruleset',
  3: 'network unreachable',
  4: 'host unreachable',
  5: 'connection refused',
  6: 'TTL expired',
  7: 'command not supported',
  8: 'address type not supported',
};

export async function socks5Connect(s: Duplex, p: ParsedProxy, host: string, port: number, deadline: number): Promise<void> {
  const r = new Reader(s);
  const hasCreds = p.username !== undefined;
  const methods = hasCreds ? [0x00, 0x02] : [0x00];
  s.write(Buffer.from([0x05, methods.length, ...methods]));

  try {
    const choice = await r.bytes(2, deadline);
    if (choice[0] !== 0x05) {
      throw new StageError('handshake_bad_response', choice.toString('latin1') === 'HT' ? 'looks_http' : undefined);
    }
    if (choice[1] === 0xff) throw new StageError(hasCreds ? 'socks_no_method' : 'auth_required', 'SOCKS5');
    if (choice[1] === 0x02) {
      if (!hasCreds) throw new StageError('auth_required', 'SOCKS5');
      const u = Buffer.from(p.username!);
      const pw = Buffer.from(p.password ?? '');
      s.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([pw.length]), pw]));
      const auth = await r.bytes(2, deadline);
      if (auth[1] !== 0x00) throw new StageError('auth_rejected', 'SOCKS5 login');
    } else if (choice[1] !== 0x00) {
      throw new StageError('handshake_bad_response');
    }

    let addr: Buffer;
    if (net.isIPv4(host)) addr = Buffer.from([0x01, ...host.split('.').map(Number)]);
    else if (net.isIPv6(host)) addr = Buffer.concat([Buffer.from([0x04]), ipv6Bytes(host)]);
    else {
      const name = Buffer.from(host);
      addr = Buffer.concat([Buffer.from([0x03, name.length]), name]);
    }
    s.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addr, Buffer.from([port >> 8, port & 0xff])]));

    const rep = await r.bytes(4, deadline);
    if (rep[0] !== 0x05) throw new StageError('handshake_bad_response');
    if (rep[1] !== 0x00) {
      const why = SOCKS_REPLIES[rep[1]] ?? `code ${rep[1]}`;
      const target = hostPort(host, port);
      if (rep[1] === 2) throw new StageError('proxy_denied', `${target} (SOCKS5: ${why})`);
      if (rep[1] === 7 || rep[1] === 8) throw new StageError('handshake_unexpected_status', `SOCKS5: ${why}`);
      throw new StageError('upstream_failed', `${target} (SOCKS5: ${why})`);
    }
    const atyp = rep[3];
    if (atyp === 0x01) await r.bytes(4 + 2, deadline);
    else if (atyp === 0x04) await r.bytes(16 + 2, deadline);
    else if (atyp === 0x03) {
      const [len] = await r.bytes(1, deadline);
      await r.bytes(len + 2, deadline);
    } else throw new StageError('handshake_bad_response');
    r.detach();
  } catch (e) {
    throw handshakeReadError(e, 'socks5');
  }
}

function ipv6Bytes(ip: string): Buffer {
  const [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2));
  return out;
}

export type Recorder = (stage: Stage, ok: boolean, ms: number, detail?: string) => void;

/** TCP to the proxy, optional TLS to the proxy, then an HTTP CONNECT or SOCKS5 tunnel to host:port. */
export async function openTunnel(
  p: ParsedProxy,
  address: string,
  host: string,
  port: number,
  timeoutMs: number,
  rec: Recorder = () => {},
  insecureProxyTls = false,
): Promise<net.Socket | tls.TLSSocket> {
  let t = Date.now();
  let sock: net.Socket;
  try {
    sock = await connectTcp(address, p.port, timeoutMs);
    rec('tcp', true, Date.now() - t);
  } catch (e) {
    rec('tcp', false, Date.now() - t);
    throw e;
  }

  let s: net.Socket | tls.TLSSocket = sock;
  if (p.protocol === 'https') {
    t = Date.now();
    try {
      s = await tlsConnect(sock, p.host, timeoutMs, !insecureProxyTls);
      rec('tls', true, Date.now() - t);
    } catch (e) {
      sock.destroy();
      rec('tls', false, Date.now() - t);
      throw new StageError('tls_failed', errMsg(e));
    }
  }

  t = Date.now();
  try {
    const deadline = Date.now() + timeoutMs;
    if (p.protocol === 'socks5') await socks5Connect(s, p, host, port, deadline);
    else await httpConnect(s, p, host, port, deadline);
    rec('handshake', true, Date.now() - t);
  } catch (e) {
    s.destroy();
    rec('handshake', false, Date.now() - t);
    throw e;
  }
  return s;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** A minimal HTTP/1.1 GET over an already-open tunnel. Not a browser: no JS, no cookies. */
export async function httpGet(
  tunnel: net.Socket | tls.TLSSocket,
  url: URL,
  timeoutMs: number,
  opts: { userAgent?: string; maxBody?: number } = {},
): Promise<HttpResponse> {
  const maxBody = opts.maxBody ?? 256 * 1024;
  let s: Duplex = tunnel;
  if (url.protocol === 'https:') s = await tlsConnect(tunnel as net.Socket, url.hostname.replace(/^\[|\]$/g, ''), timeoutMs);

  const path = (url.pathname || '/') + url.search;
  s.write(
    `GET ${path} HTTP/1.1\r\nHost: ${url.host}\r\nUser-Agent: ${opts.userAgent ?? 'steel-proxy-doctor'}\r\n` +
      'Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n',
  );

  const deadline = Date.now() + timeoutMs;
  const r = new Reader(s);
  try {
    const head = (await r.until('\r\n\r\n', deadline)).toString('latin1');
    const [statusLine, ...headerLines] = head.split('\r\n');
    const status = Number(statusLine.split(' ')[1]);
    const headers: Record<string, string> = {};
    for (const line of headerLines) {
      const i = line.indexOf(':');
      if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
    }

    let body: Buffer;
    if (headers['transfer-encoding']?.toLowerCase().includes('chunked')) {
      const parts: Buffer[] = [];
      let total = 0;
      for (;;) {
        const size = parseInt((await r.until('\r\n', deadline)).toString('latin1'), 16);
        if (!size || Number.isNaN(size)) break;
        const chunk = await r.bytes(size, deadline);
        await r.bytes(2, deadline);
        parts.push(chunk);
        total += size;
        if (total >= maxBody) break;
      }
      body = Buffer.concat(parts);
    } else if (headers['content-length'] !== undefined) {
      body = await r.bytes(Math.min(Number(headers['content-length']), maxBody), deadline);
    } else {
      body = await r.rest(deadline, maxBody);
    }
    return { status, headers, body: body.toString('utf8') };
  } finally {
    s.destroy();
  }
}
