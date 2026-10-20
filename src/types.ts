export type ProxyProtocol = 'http' | 'https' | 'socks5';

export type Stage = 'parse' | 'dns' | 'tcp' | 'tls' | 'handshake' | 'exit_ip' | 'target';

/** Whose part of the assembled system failed. */
export type Owner = 'customer_input' | 'customer_proxy' | 'target_site' | 'network';

export type ErrorCode =
  | 'url_invalid'
  | 'url_missing_scheme'
  | 'url_unsupported_scheme'
  | 'url_bad_chars'
  | 'url_missing_host'
  | 'dns_not_found'
  | 'dns_failed'
  | 'tcp_refused'
  | 'tcp_timeout'
  | 'tcp_unreachable'
  | 'tcp_failed'
  | 'tls_failed'
  | 'auth_required'
  | 'auth_rejected'
  | 'socks_no_method'
  | 'proxy_denied'
  | 'upstream_failed'
  | 'handshake_timeout'
  | 'handshake_closed'
  | 'handshake_bad_response'
  | 'handshake_unexpected_status'
  | 'echo_failed'
  | 'target_unreachable'
  | 'target_denied_by_proxy'
  | 'target_blocked';

export interface ParsedProxy {
  protocol: ProxyProtocol;
  host: string;
  port: number;
  username?: string;
  password?: string;
  /** The URL with the password replaced by ***. Safe to log. */
  redacted: string;
}

export interface Warning {
  code: string;
  message: string;
}

export interface StageResult {
  stage: Stage;
  ok: boolean;
  ms?: number;
  detail?: string;
}

/** Every failure answers: what happened, which input was wrong, how to fix it. */
export interface DoctorError {
  stage: Stage;
  code: ErrorCode;
  owner: Owner;
  what_happened: string;
  wrong_input: string | null;
  fix: string;
  docs: string;
}

export type InferredType = 'rotating' | 'static_or_sticky' | 'mixed' | 'unknown';

export interface Report {
  ok: boolean;
  proxy: string;
  /** The checks ran from wherever this tool ran, not from Steel's cloud. */
  checked_from: 'this_machine';
  error: DoctorError | null;
  warnings: Warning[];
  stages: StageResult[];
  context: {
    protocol: ProxyProtocol | null;
    exit_ips: string[];
    inferred_type: InferredType;
    rounds: { attempted: number; failed: number };
    target: { url: string; status: number; ms: number } | null;
  };
}
