// Bridge to the native (Tauri/Rust + OpenSSL) certificate backend.
//
// In the desktop app these calls remove the browser's crypto limitations
// (any-curve verification, EC/Ed key+cert+CSR generation, modern PKCS#12).
// In the web build `isNativeCrypto()` is false and callers fall back to the
// existing node-forge / WebCrypto implementations.

let cachedInvoke: ((cmd: string, args?: Record<string, unknown>) => Promise<unknown>) | null = null;
let probed = false;

interface TauriWindow {
  __TAURI_INTERNALS__?: unknown;
  __TAURI__?: unknown;
}

/** True when running inside the Tauri desktop shell. */
export function isNativeCrypto(): boolean {
  if (typeof window === 'undefined') return false;
  const w = window as unknown as TauriWindow;
  return w.__TAURI_INTERNALS__ !== undefined || w.__TAURI__ !== undefined;
}

async function getInvoke() {
  if (cachedInvoke) return cachedInvoke;
  if (probed && !cachedInvoke) return null;
  probed = true;
  try {
    const mod = await import('@tauri-apps/api/core');
    cachedInvoke = mod.invoke as unknown as typeof cachedInvoke;
    return cachedInvoke;
  } catch {
    return null;
  }
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const invoke = await getInvoke();
  if (!invoke) throw new Error('Native backend is not available.');
  return (await invoke(cmd, args)) as T;
}

// ─── Shared types (mirror the Rust structs) ──────────────────────────────────

export interface NativeSubject {
  common_name: string;
  organization: string;
  org_unit: string;
  country: string;
  state: string;
  locality: string;
  san: string[];
}

export interface NativeKeySpec {
  kind: 'rsa' | 'ec' | 'ed25519' | 'ed448';
  rsa_bits?: number;
  curve?: string;
}

export interface NativeChainLink {
  index: number;
  subject: string;
  issuer: string;
  not_after: string;
  self_signed: boolean;
  issuer_chain_ok: boolean;
  signature_ok: boolean | null;
}

export interface NativeMatchResult {
  matched: boolean;
  detail: string;
}

export interface NativeKeyCert {
  cert_pem: string;
  key_pem: string;
}

export interface NativeCsrKey {
  csr_pem: string;
  key_pem: string;
}

export interface NativeGenCertInput {
  cert_type: 'self-signed' | 'root-ca' | 'intermediate-ca' | 'ca-signed';
  subject?: NativeSubject;
  key: NativeKeySpec;
  valid_days: number;
  ca_cert_pem?: string;
  ca_key_pem?: string;
  csr_pem?: string;
}

// ─── Typed command wrappers ──────────────────────────────────────────────────

export const nativeCert = {
  verifyChain: (chainPem: string) =>
    call<NativeChainLink[]>('cert_verify_chain', { chainPem }),

  matchKey: (certPem: string, keyPem: string) =>
    call<NativeMatchResult>('cert_match_key', { certPem, keyPem }),

  matchCsr: (certPem: string, csrPem: string) =>
    call<NativeMatchResult>('cert_match_csr', { certPem, csrPem }),

  generateCsr: (subject: NativeSubject, key: NativeKeySpec) =>
    call<NativeCsrKey>('cert_generate_csr', { subject, key }),

  generate: (input: NativeGenCertInput) =>
    call<NativeKeyCert>('cert_generate', { input }),

  toPkcs12: (
    certPem: string,
    keyPem: string,
    chainPem: string,
    password: string,
    friendlyName: string,
  ) =>
    call<string>('cert_to_pkcs12', {
      certPem,
      keyPem,
      chainPem,
      password,
      friendlyName,
    }),
};
