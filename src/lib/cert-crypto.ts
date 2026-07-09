import * as forge from 'node-forge';
import { isNativeCrypto, nativeCert, type NativeSubject, type NativeKeySpec } from './nativeCrypto';


// ─── Helpers ──────────────────────────────────────────────────────────────────

export function attrMap(attrs: forge.pki.CertificateField[]): Record<string, string> {
  const m: Record<string, string> = {};
  for (const a of attrs) m[String(a.shortName ?? a.name)] = String(a.value);
  return m;
}

export function certFingerprint(cert: forge.pki.Certificate, algo: 'md5' | 'sha1' | 'sha256'): string {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).bytes();
  const md = algo === 'md5' ? forge.md.md5.create() : algo === 'sha1' ? forge.md.sha1.create() : forge.md.sha256.create();
  return md.update(der).digest().toHex().replace(/../g, (h) => h.toUpperCase() + ':').slice(0, -1);
}

export function splitPemCerts(pem: string): string[] {
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
  return pem.match(regex) ?? [];
}

export function getRsaModulus(key: forge.pki.PublicKey | forge.pki.PrivateKey): string {
  return (key as forge.pki.rsa.PublicKey).n?.toString(16) ?? '';
}

// Async RSA key-pair generator (uses web workers when available)
export function generateRsaKeyPair(bits: number): Promise<forge.pki.rsa.KeyPair> {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits, workers: -1 }, (err, kp) => {
      if (err) reject(err);
      else resolve(kp);
    });
  });
}

// ─── Universal (non-RSA) cert parsing via raw ASN.1 ──────────────────────────

export const DN_OID_MAP: Record<string, string> = {
  '2.5.4.3': 'CN', '2.5.4.4': 'SN', '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C',  '2.5.4.7': 'L',  '2.5.4.8': 'ST', '2.5.4.9': 'street',
  '2.5.4.10': 'O', '2.5.4.11': 'OU', '1.2.840.113549.1.9.1': 'E',
};
export const EC_SPKI_OID = '1.2.840.10045.2.1';
export const EC_CURVE_BITS: Record<string, number> = {
  '1.2.840.10045.3.1.1': 192, // prime192v1 / secp192r1
  '1.3.132.0.33': 224,        // secp224r1
  '1.2.840.10045.3.1.7': 256, // prime256v1 / secp256r1 (P-256)
  '1.3.132.0.34': 384,        // secp384r1 (P-384)
  '1.3.132.0.35': 521,        // secp521r1 (P-521)
  '1.3.132.0.10': 256,        // secp256k1
  '1.3.36.3.3.2.8.1.1.7': 256,  // brainpoolP256r1
  '1.3.36.3.3.2.8.1.1.11': 384, // brainpoolP384r1
  '1.3.36.3.3.2.8.1.1.13': 512, // brainpoolP512r1
};
export const ED_KEY_TYPES: Record<string, [string, number]> = {
  '1.3.101.112': ['Ed25519', 256], '1.3.101.113': ['Ed448', 448],
};
// EdDSA signature-algorithm OID → WebCrypto algorithm name (raw signature, no r/s)
export const ED_SIG_ALG_NAME: Record<string, string> = {
  '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
};

export function isNonRsaError(e: unknown): boolean {
  const s = String(e);
  return s.includes('OID is not RSA') || s.includes('Cannot read public key');
}

/** Convert a forge ASN.1 OID node (raw DER bytes) to dotted-decimal string */
export function asn1Oid(node: any): string {
  try { return forge.asn1.derToOid(node?.value); } catch { return ''; }
}

export function parseDnAsn1(dn: any): Record<string, string> {
  const result: Record<string, string> = {};
  for (const rdn of dn?.value ?? []) {
    for (const atv of rdn?.value ?? []) {
      const oid = asn1Oid(atv?.value?.[0]);
      const valNode = atv?.value?.[1]?.value;
      if (oid && valNode !== undefined) result[DN_OID_MAP[oid] ?? oid] = asn1ValueToString(valNode);
    }
  }
  return result;
}

export const EXT_OID_MAP: Record<string, string> = {
  '2.5.29.17': 'Subject Alternative Name',
  '2.5.29.15': 'Key Usage',
  '2.5.29.37': 'Extended Key Usage',
  '2.5.29.19': 'Basic Constraints',
  '2.5.29.14': 'Subject Key Identifier',
  '2.5.29.35': 'Authority Key Identifier',
  '2.5.29.31': 'CRL Distribution Points',
  '2.5.29.32': 'Certificate Policies',
  '1.3.6.1.5.5.7.1.1': 'Authority Information Access',
};

export const SIG_ALG_OID_MAP: Record<string, string> = {
  '1.2.840.113549.1.1.5': 'SHA1withRSA',
  '1.2.840.113549.1.1.11': 'SHA256withRSA',
  '1.2.840.113549.1.1.12': 'SHA384withRSA',
  '1.2.840.113549.1.1.13': 'SHA512withRSA',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.4.3.2': 'SHA256withECDSA',
  '1.2.840.10045.4.3.3': 'SHA384withECDSA',
  '1.2.840.10045.4.3.4': 'SHA512withECDSA',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
};

/** Map a signature-algorithm OID to a friendly name, falling back to the OID itself */
export function friendlySigAlg(oid: string): string {
  return SIG_ALG_OID_MAP[oid] ? `${SIG_ALG_OID_MAP[oid]} (${oid})` : oid;
}

export const KEY_USAGE_BITS = ['Digital Signature', 'Non Repudiation', 'Key Encipherment', 'Data Encipherment', 'Key Agreement', 'Certificate Sign', 'CRL Sign', 'Encipher Only', 'Decipher Only'];
export const EKU_OID_MAP: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
  '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code Signing',
  '1.3.6.1.5.5.7.3.4': 'Email Protection',
  '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
};
export const ACCESS_METHOD_MAP: Record<string, string> = {
  '1.3.6.1.5.5.7.48.1': 'OCSP',
  '1.3.6.1.5.5.7.48.2': 'CA Issuers',
};

export function bytesToColonHex(bytes: string): string {
  return forge.util.bytesToHex(bytes).replace(/../g, (h) => h.toUpperCase() + ':').slice(0, -1);
}

/** Collect GeneralName entries (DNS / IP / URI / etc.) from an ASN.1 sequence */
export function collectGeneralNames(seq: any): string[] {
  const out: string[] = [];
  for (const gn of seq?.value ?? []) {
    if (gn.type === 1) out.push(`email: ${asn1ValueToString(gn.value)}`);
    else if (gn.type === 2) out.push(`DNS: ${asn1ValueToString(gn.value)}`);
    else if (gn.type === 6) out.push(`URI: ${asn1ValueToString(gn.value)}`);
    else if (gn.type === 7 && (gn.value as string)?.length === 4) {
      const b = gn.value as string;
      out.push(`IP: ${b.charCodeAt(0)}.${b.charCodeAt(1)}.${b.charCodeAt(2)}.${b.charCodeAt(3)}`);
    }
  }
  return out;
}

/** Decode the human-readable value of a certificate extension from its inner DER bytes */
export function decodeExtensionValue(oid: string, der: string, san: string[]): string {
  let inner: any;
  try { inner = forge.asn1.fromDer(der); } catch { return '(present)'; }
  switch (oid) {
    case '2.5.29.17': { // Subject Alternative Name
      const names = collectGeneralNames(inner);
      san.push(...names);
      return names.join(', ') || '(none)';
    }
    case '2.5.29.15': { // Key Usage (BIT STRING)
      const raw = asn1ValueToString(inner.value);
      // first byte is the number of unused bits; remaining bytes hold the flags MSB-first
      const flagBytes = raw.slice(1);
      const used: string[] = [];
      for (let i = 0; i < KEY_USAGE_BITS.length; i++) {
        const byte = flagBytes.charCodeAt(Math.floor(i / 8)) || 0;
        if (byte & (0x80 >> (i % 8))) used.push(KEY_USAGE_BITS[i]);
      }
      return used.join(', ') || '(none)';
    }
    case '2.5.29.37': // Extended Key Usage
      return (inner.value ?? []).map((n: any) => {
        const o = asn1Oid(n);
        return EKU_OID_MAP[o] ?? o;
      }).join(', ') || '(none)';
    case '2.5.29.19': { // Basic Constraints
      const isCa = (inner.value ?? []).some((n: any) => n.type === 0x01 && !!asn1ValueToString(n.value).charCodeAt(0));
      const pathNode = (inner.value ?? []).find((n: any) => n.type === 0x02);
      const pathLen = pathNode ? forge.util.bytesToHex(pathNode.value).replace(/^0+/, '') || '0' : undefined;
      return `CA: ${isCa ? 'TRUE' : 'FALSE'}${pathLen !== undefined ? `, Path Length: ${parseInt(pathLen, 16)}` : ''}`;
    }
    case '2.5.29.14': // Subject Key Identifier (OCTET STRING)
      return bytesToColonHex(asn1ValueToString(inner.value));
    case '2.5.29.35': { // Authority Key Identifier
      const parts: string[] = [];
      for (const n of inner.value ?? []) {
        if (n.tagClass !== 0x80) continue;
        if (n.type === 0 && typeof n.value === 'string') parts.push(`keyid: ${bytesToColonHex(n.value)}`);
        else if (n.type === 2 && typeof n.value === 'string') parts.push(`serial: ${forge.util.bytesToHex(n.value).toUpperCase()}`);
      }
      return parts.join(', ') || '(present)';
    }
    case '2.5.29.31': { // CRL Distribution Points
      const uris: string[] = [];
      const walk = (node: any) => {
        if (!node) return;
        if (node.type === 6 && node.tagClass === 0x80) uris.push(asn1ValueToString(node.value));
        if (Array.isArray(node.value)) node.value.forEach(walk);
      };
      walk(inner);
      return uris.join(', ') || '(present)';
    }
    case '1.3.6.1.5.5.7.1.1': { // Authority Information Access
      const out: string[] = [];
      for (const acc of inner.value ?? []) {
        const method = asn1Oid(acc?.value?.[0]);
        const loc = acc?.value?.[1];
        const name = ACCESS_METHOD_MAP[method] ?? method;
        out.push(`${name}: ${asn1ValueToString(loc?.value)}`);
      }
      return out.join(', ') || '(present)';
    }
    case '2.5.29.32': // Certificate Policies
      return (inner.value ?? []).map((p: any) => asn1Oid(p?.value?.[0])).filter(Boolean).join(', ') || '(present)';
    default:
      return '(present)';
  }
}

/** Coerce an ASN.1 primitive value (string | ByteStringBuffer) to a plain ASCII string */
export function asn1ValueToString(v: any): string {
  if (typeof v === 'string') return v;
  if (v && typeof v.bytes === 'function') { try { return v.bytes(); } catch { /* noop */ } }
  if (v && typeof v.data === 'string') return v.data;
  if (v && typeof v.toString === 'function') return v.toString();
  return String(v ?? '');
}

/**
 * Self-contained ASN.1 time parser. Handles UTCTime (0x17) and GeneralizedTime (0x18).
 * Supports trailing 'Z', '+HHMM'/'-HHMM' offsets and fractional seconds.
 * Returns null when the value cannot be parsed into a valid Date.
 */
export function parseAsn1Time(t: any): Date | null {
  const raw = asn1ValueToString(t?.value).trim();
  if (!raw) return null;

  // Separate timezone suffix from the core digits
  const tzMatch = raw.match(/(Z|[+-]\d{2}\d{2})$/);
  const tz = tzMatch ? tzMatch[1] : '';
  const core = (tzMatch ? raw.slice(0, -tz.length) : raw).replace(/\.\d+$/, ''); // strip fractional seconds
  const digits = core.replace(/[^0-9]/g, '');

  let year: number, mi: number;
  if (t?.type === 0x17) {
    // UTCTime: YYMMDDHHMM[SS]
    if (digits.length < 10) return null;
    const yy = parseInt(digits.slice(0, 2), 10);
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
    mi = 2;
  } else {
    // GeneralizedTime: YYYYMMDDHHMM[SS]
    if (digits.length < 12) return null;
    year = parseInt(digits.slice(0, 4), 10);
    mi = 4;
  }

  const month = parseInt(digits.slice(mi, mi + 2), 10) - 1;
  const day   = parseInt(digits.slice(mi + 2, mi + 4), 10);
  const hour  = parseInt(digits.slice(mi + 4, mi + 6), 10);
  const min   = parseInt(digits.slice(mi + 6, mi + 8), 10);
  const sec   = parseInt(digits.slice(mi + 8, mi + 10) || '0', 10);

  if ([year, month, day, hour, min, sec].some(Number.isNaN)) return null;

  let ms = Date.UTC(year, month, day, hour, min, sec);
  // Apply numeric timezone offset (Z = UTC = no adjustment)
  if (tz && tz !== 'Z') {
    const sign = tz[0] === '-' ? 1 : -1; // convert local→UTC
    const offMin = parseInt(tz.slice(1, 3), 10) * 60 + parseInt(tz.slice(3, 5), 10);
    ms += sign * offMin * 60000;
  }
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Safe ISO string — returns empty string instead of throwing on invalid dates */
export function safeIso(d: Date | null): string {
  return d && !Number.isNaN(d.getTime()) ? d.toISOString() : '';
}

export interface RawCertInfo {
  subject: Record<string, string>; issuer: Record<string, string>;
  serial: string; notBefore: Date | null; notAfter: Date | null; san: string[];
  md5: string; sha1: string; sha256: string; keyType: string; keyBits: number;
  sigAlgOid: string; version: number;
  extensions: { name: string; critical: boolean; value: string }[];
}

export function parseRawCertFromPem(pem: string): RawCertInfo {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  const derBytes = forge.util.decode64(b64);
  const asn1 = forge.asn1.fromDer(derBytes) as any;
  const tbs = asn1.value[0];
  const kids: any[] = tbs.value ?? [];

  const UNIVERSAL = 0x00, CONTEXT = 0x80;
  const isSeq  = (n: any) => n?.tagClass === UNIVERSAL && n?.type === 0x10;
  const isTime = (n: any) => n?.tagClass === UNIVERSAL && (n?.type === 0x17 || n?.type === 0x18);

  // Anchor on the Validity node: a SEQUENCE containing exactly two Time nodes.
  const vIdx = kids.findIndex((n) => isSeq(n) && Array.isArray(n.value) &&
    n.value.length === 2 && isTime(n.value[0]) && isTime(n.value[1]));
  const validityAsn1 = vIdx >= 0 ? kids[vIdx] : null;

  // Fields are positioned relative to validity (RFC 5280 TBSCertificate ordering).
  const issuerAsn1  = vIdx > 0 ? kids[vIdx - 1] : null;
  const subjectAsn1 = vIdx >= 0 ? kids[vIdx + 1] : null;
  const spkiAsn1    = vIdx >= 0 ? kids[vIdx + 2] : null;

  // Version: leading context-specific [0]
  let version = 1;
  const verNode = kids.find((n) => n?.tagClass === CONTEXT && n?.type === 0);
  if (verNode) {
    const vRaw = verNode.value?.[0]?.value;
    version = (typeof vRaw === 'string' ? vRaw.charCodeAt(0) : Number(vRaw ?? 0)) + 1;
  }

  // Serial: first universal INTEGER in the TBS
  const serialNode = kids.find((n) => n?.tagClass === UNIVERSAL && n?.type === 0x02);
  const serial = forge.util.bytesToHex(serialNode?.value ?? '').replace(/^0+/, '') || '0';

  const spkiAlgOid   = asn1Oid(spkiAsn1?.value?.[0]?.value?.[0]);
  const spkiParamOid = asn1Oid(spkiAsn1?.value?.[0]?.value?.[1]);
  let keyType = 'Unknown', keyBits = 0;
  if (spkiAlgOid === EC_SPKI_OID)    { keyType = 'EC (ECDSA)'; keyBits = EC_CURVE_BITS[spkiParamOid] ?? 0; }
  else if (ED_KEY_TYPES[spkiAlgOid]) { [keyType, keyBits] = ED_KEY_TYPES[spkiAlgOid]; }
  else if (spkiAlgOid === '1.2.840.113549.1.1.1') { keyType = 'RSA'; }

  const sigAlgOid = asn1Oid(asn1.value[1]?.value?.[0]);

  const sha1   = forge.md.sha1.create().update(derBytes).digest().toHex().replace(/../g, h => h.toUpperCase() + ':').slice(0, -1);
  const sha256 = forge.md.sha256.create().update(derBytes).digest().toHex().replace(/../g, h => h.toUpperCase() + ':').slice(0, -1);
  const md5    = forge.md.md5.create().update(derBytes).digest().toHex().replace(/../g, h => h.toUpperCase() + ':').slice(0, -1);

  const san: string[] = [];
  const extensions: { name: string; critical: boolean; value: string }[] = [];
  // Extensions live in the context-specific [3] node
  const extContainer = kids.find((n) => n?.tagClass === CONTEXT && n?.type === 3);
  for (const ext of (extContainer?.value?.[0]?.value ?? [])) {
    const extOid = asn1Oid(ext?.value?.[0]);
    if (!extOid) continue;
    const critNode = ext?.value?.[1];
    const critical = critNode?.tagClass === UNIVERSAL && critNode?.type === 0x01 &&
      !!asn1ValueToString(critNode.value).charCodeAt(0);
    // The extension's encoded value is the final OCTET STRING in the sequence
    const octet = ext.value[ext.value.length - 1];
    const value = decodeExtensionValue(extOid, asn1ValueToString(octet?.value), san);
    extensions.push({ name: EXT_OID_MAP[extOid] ?? extOid, critical, value });
  }

  return {
    subject: parseDnAsn1(subjectAsn1), issuer: parseDnAsn1(issuerAsn1),
    serial,
    notBefore: validityAsn1 ? parseAsn1Time(validityAsn1.value[0]) : null,
    notAfter: validityAsn1 ? parseAsn1Time(validityAsn1.value[1]) : null,
    san, md5, sha1, sha256, keyType, keyBits, sigAlgOid, version, extensions,
  };
}

/** Extract raw SubjectPublicKeyInfo DER bytes from any PEM cert */
export function extractSpkiDer(certPem: string): Uint8Array | null {
  try {
    const b64 = certPem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
    const asn1 = forge.asn1.fromDer(forge.util.decode64(b64)) as any;
    // SPKI is a SEQUENCE (type 16) of [ AlgorithmIdentifier SEQUENCE (16), subjectPublicKey BIT STRING (3) ]
    for (const child of (asn1.value[0]?.value ?? [])) {
      if (child.type === 0x10 && Array.isArray(child.value) && child.value.length === 2 &&
          child.value[0]?.type === 0x10 && child.value[1]?.type === 0x03) {
        const der = forge.asn1.toDer(child).bytes();
        return Uint8Array.from(der, (c: string) => c.charCodeAt(0));
      }
    }
  } catch { /* ignore */ }
  return null;
}

/** Find the subjectPublicKey BIT STRING bytes inside a SubjectPublicKeyInfo SEQUENCE */
export function findSpkiBitString(node: any): string {
  for (const child of (node?.value ?? [])) {
    if (child?.type === 0x10 && Array.isArray(child.value) && child.value.length === 2 &&
        child.value[0]?.type === 0x10 && child.value[1]?.type === 0x03) {
      return typeof child.value[1].value === 'string' ? child.value[1].value : '';
    }
  }
  return '';
}

/** Public key BIT STRING from a PEM cert or CSR (walks the tbs SEQUENCE) */
export function publicKeyBitsFromCertOrCsr(pem: string): string {
  try {
    const der = forge.util.decode64(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''));
    const asn1 = forge.asn1.fromDer(der) as any;
    return findSpkiBitString(asn1.value?.[0]);
  } catch { return ''; }
}

/** Public key BIT STRING embedded in an EC private key PEM (SEC1 or PKCS#8) */
export function publicKeyBitsFromPrivateKey(keyPem: string): string {
  try {
    const der = forge.util.decode64(keyPem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''));
    let seq = forge.asn1.fromDer(der) as any;
    // PKCS#8 wraps the SEC1 ECPrivateKey inside an OCTET STRING (type 4)
    const octet = (seq.value ?? []).find((n: any) => n?.tagClass === 0 && n?.type === 0x04 && typeof n.value === 'string');
    if (octet) {
      try { seq = forge.asn1.fromDer(octet.value) as any; } catch { /* not nested, keep seq */ }
    }
    // SEC1 ECPrivateKey: publicKey is an explicit [1] context tag holding a BIT STRING
    const pub = (seq.value ?? []).find((n: any) => n?.tagClass === 0x80 && n?.type === 1);
    if (pub) {
      const bs = Array.isArray(pub.value) ? pub.value[0] : pub;
      return typeof bs?.value === 'string' ? bs.value : '';
    }
  } catch { /* ignore */ }
  return '';
}

export const ECDSA_HASH_BY_SIG_OID: Record<string, string> = {
  '1.2.840.10045.4.3.2': 'SHA-256',
  '1.2.840.10045.4.3.3': 'SHA-384',
  '1.2.840.10045.4.3.4': 'SHA-512',
  '1.2.840.10045.4.1': 'SHA-1',
};
export const ECDSA_CURVE_BY_PARAM: Record<string, [string, number]> = {
  '1.2.840.10045.3.1.7': ['P-256', 32],
  '1.3.132.0.34': ['P-384', 48],
  '1.3.132.0.35': ['P-521', 66],
};

/** Left-trim leading zero bytes then left-pad to a fixed length (for ECDSA r/s components) */
export function ecCoordToFixed(bytesStr: string, len: number): Uint8Array {
  let s = bytesStr;
  while (s.length > len && s.charCodeAt(0) === 0) s = s.slice(1);
  while (s.length < len) s = '\x00' + s;
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

/** Curve OID from a parsed cert's SubjectPublicKeyInfo (EC param) */
export function ecCurveOidFromCert(asn1: any): string {
  for (const child of (asn1?.value?.[0]?.value ?? [])) {
    if (child?.type === 0x10 && Array.isArray(child.value) && child.value.length === 2 &&
        child.value[0]?.type === 0x10 && child.value[1]?.type === 0x03) {
      return asn1Oid(child.value[0].value?.[1]);
    }
  }
  return '';
}

/** Verify a non-RSA (ECDSA or EdDSA) certificate signature against its issuer's public key via WebCrypto */
export async function verifyEcCertSignature(certPem: string, issuerPem: string): Promise<boolean | null> {
  try {
    const parse = (p: string) => forge.asn1.fromDer(
      forge.util.decode64(p.replace(/-----[^-]+-----/g, '').replace(/\s/g, '')),
      { decodeBitStrings: false } as any,
    ) as any;
    const certAsn1 = parse(certPem);
    const issuerAsn1 = parse(issuerPem);

    const sigAlgOid = asn1Oid(certAsn1.value[1]?.value?.[0]);

    // Signed data is the DER encoding of TBSCertificate
    const tbsDer = forge.asn1.toDer(certAsn1.value[0]).getBytes();
    const tbsBytes = Uint8Array.from(tbsDer, (c) => c.charCodeAt(0));

    // Ed25519 / Ed448: the signature is a raw EdDSA value (no ECDSA-Sig-Value SEQUENCE)
    const edAlg = ED_SIG_ALG_NAME[sigAlgOid];
    if (edAlg) {
      const edBitStr = certAsn1.value[2];
      const edRaw: string = edBitStr.bitStringContents ?? edBitStr.value;
      if (typeof edRaw !== 'string' || edRaw.length < 2) return null;
      const edSig = Uint8Array.from(edRaw.slice(1), (c) => c.charCodeAt(0));
      const edSpki = extractSpkiDer(issuerPem);
      if (!edSpki) return null;
      const edKey = await crypto.subtle.importKey('spki', edSpki.buffer as ArrayBuffer, { name: edAlg }, false, ['verify']);
      return await crypto.subtle.verify({ name: edAlg }, edKey, edSig.buffer as ArrayBuffer, tbsBytes.buffer as ArrayBuffer);
    }

    const hash = ECDSA_HASH_BY_SIG_OID[sigAlgOid];
    if (!hash) return null;

    // Signature BIT STRING content (skip the leading unused-bits byte) → ECDSA-Sig-Value SEQUENCE { r, s }
    const bitStr = certAsn1.value[2];
    const raw: string = bitStr.bitStringContents ?? bitStr.value;
    if (typeof raw !== 'string' || raw.length < 2) return null;
    const sigAsn1 = forge.asn1.fromDer(raw.slice(1)) as any;

    const curveOid = ecCurveOidFromCert(issuerAsn1);
    // WebCrypto only supports the NIST P-curves; secp256k1 / brainpool cannot be verified here
    const curveInfo = ECDSA_CURVE_BY_PARAM[curveOid];
    if (!curveInfo) return null;
    const [namedCurve, coordLen] = curveInfo;
    const r = ecCoordToFixed(sigAsn1.value[0].value, coordLen);
    const s = ecCoordToFixed(sigAsn1.value[1].value, coordLen);
    const rawSig = new Uint8Array(coordLen * 2);
    rawSig.set(r, 0); rawSig.set(s, coordLen);

    const spki = extractSpkiDer(issuerPem);
    if (!spki) return null;
    const pubKey = await crypto.subtle.importKey('spki', spki.buffer as ArrayBuffer, { name: 'ECDSA', namedCurve }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'ECDSA', hash }, pubKey, rawSig.buffer as ArrayBuffer, tbsBytes.buffer as ArrayBuffer);
  } catch {
    return null;
  }
}

/** SHA-256 of the SubjectPublicKeyInfo (HPKP-style pin), as colon-hex and base64 */
export function spkiSha256FromPem(certPem: string): { hex: string; b64: string } {
  const spki = extractSpkiDer(certPem);
  if (!spki) return { hex: '', b64: '' };
  let bin = '';
  for (let i = 0; i < spki.length; i++) bin += String.fromCharCode(spki[i]);
  const digest = forge.md.sha256.create().update(bin).digest();
  return {
    hex: digest.toHex().replace(/../g, (h) => h.toUpperCase() + ':').slice(0, -1),
    b64: forge.util.encode64(digest.bytes()),
  };
}

export function pemDownload(pem: string, filename: string) {
  const blob = new Blob([pem], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

export function binaryDownload(bytes: Uint8Array, filename: string, mime: string) {
  const blob = new Blob([bytes.buffer as BlobPart], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}


// ─── parseTrustEntry ───
export function parseTrustEntry(pem: string, index: number, alias?: string): TrustEntry {
  try {
    let subject: Record<string, string>;
    let issuer: Record<string, string>;
    let serial: string;
    let notBefore: Date | null;
    let notAfter: Date | null;
    let keyType: string;
    let keyBits: number;
    let sigAlgOid: string;
    let version: number;
    let san: string[] = [];
    let extensions: { name: string; critical: boolean; value: string }[] = [];
    let md5fp = '';
    let sha1fp = '';
    let sha256fp = '';

    try {
      const cert = forge.pki.certificateFromPem(pem);
      subject = attrMap(cert.subject.attributes);
      issuer = attrMap(cert.issuer.attributes);
      serial = cert.serialNumber;
      notBefore = cert.validity.notBefore;
      notAfter = cert.validity.notAfter;
      const rsaPub = cert.publicKey as forge.pki.rsa.PublicKey;
      keyType = 'RSA';
      keyBits = rsaPub.n?.bitLength() ?? 0;
      sigAlgOid = cert.siginfo.algorithmOid;
      version = cert.version + 1;
      const sanExt = cert.getExtension('subjectAltName') as { altNames?: { type: number; value?: string; ip?: string }[] } | null;
      for (const n of sanExt?.altNames ?? []) {
        if (n.type === 2 && n.value) san.push(`DNS: ${n.value}`);
        else if (n.type === 7 && n.ip) san.push(`IP: ${n.ip}`);
      }
      extensions = extractForgeExtensions(cert, san);
      md5fp = certFingerprint(cert, 'md5');
      sha1fp = certFingerprint(cert, 'sha1');
      sha256fp = certFingerprint(cert, 'sha256');
    } catch (e) {
      if (!isNonRsaError(e)) throw e;
      const raw = parseRawCertFromPem(pem);
      subject = raw.subject;
      issuer = raw.issuer;
      serial = raw.serial;
      notBefore = raw.notBefore;
      notAfter = raw.notAfter;
      keyType = raw.keyType;
      keyBits = raw.keyBits;
      sigAlgOid = raw.sigAlgOid;
      version = raw.version;
      san = raw.san;
      extensions = raw.extensions;
      md5fp = raw.md5;
      sha1fp = raw.sha1;
      sha256fp = raw.sha256;
    }

    const dnStr = (m: Record<string, string>) => Object.entries(m).map(([k, v]) => `${k}=${v}`).join(', ');
    const selfSigned = dnStr(subject) === dnStr(issuer);

    const bcExt = extensions.find((e) => e.name === 'Basic Constraints');
    const isCA = selfSigned || (bcExt?.value.includes('CA: TRUE') ?? false);

    return {
      index, pem, alias, subject, issuer, serial,
      notBefore, notAfter,
      isCA, selfSigned,
      keyType, keyBits, sigAlgOid, version, san, extensions,
      fingerprints: { md5: md5fp, sha1: sha1fp, sha256: sha256fp },
    };
  } catch (e) {
    return {
      index, pem, alias,
      subject: {}, issuer: {}, serial: '',
      notBefore: null, notAfter: null,
      isCA: false, selfSigned: false,
      keyType: 'Unknown', keyBits: 0, sigAlgOid: '', version: 1,
      san: [], extensions: [],
      fingerprints: { md5: '', sha1: '', sha256: '' },
      error: String(e),
    };
  }
}




// ─── TrustEntry ───
export interface TrustEntry {
  index: number;
  pem: string;
  alias?: string;          // populated for JKS entries
  subject: Record<string, string>;
  issuer: Record<string, string>;
  serial: string;
  notBefore: Date | null;
  notAfter: Date | null;
  isCA: boolean;
  selfSigned: boolean;
  keyType: string;
  keyBits: number;
  sigAlgOid: string;
  version: number;
  san: string[];
  extensions: { name: string; critical: boolean; value: string }[];
  fingerprints: { md5: string; sha1: string; sha256: string };
  error?: string;
}


// ─── KeyAlgoState ───
export interface KeyAlgoState {
  algo: KeyAlgo;
  rsaBits: '2048' | '3072' | '4096';
  curve: string;
}


// ─── toNativeKeySpec ───
export function toNativeKeySpec(k: KeyAlgoState): NativeKeySpec {
  if (k.algo === 'rsa') return { kind: 'rsa', rsa_bits: parseInt(k.rsaBits) };
  if (k.algo === 'ec') return { kind: 'ec', curve: k.curve };
  return { kind: k.algo };
}


// ─── keyAlgoLabel ───
export function keyAlgoLabel(k: KeyAlgoState): string {
  if (k.algo === 'rsa') return `RSA ${k.rsaBits}`;
  if (k.algo === 'ec') return `EC ${k.curve}`;
  return k.algo === 'ed25519' ? 'Ed25519' : 'Ed448';
}


// ─── extractForgeExtensions ───
export function extractForgeExtensions(cert: forge.pki.Certificate, san: string[]): { name: string; critical: boolean; value: string }[] {
  const KU = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];
  const KU_LABEL: Record<string, string> = { digitalSignature: 'Digital Signature', nonRepudiation: 'Non Repudiation', keyEncipherment: 'Key Encipherment', dataEncipherment: 'Data Encipherment', keyAgreement: 'Key Agreement', keyCertSign: 'Certificate Sign', cRLSign: 'CRL Sign', encipherOnly: 'Encipher Only', decipherOnly: 'Decipher Only' };
  const EKU = ['serverAuth', 'clientAuth', 'codeSigning', 'emailProtection', 'timeStamping', 'ocspSigning'];
  const EKU_LABEL: Record<string, string> = { serverAuth: 'TLS Web Server Authentication', clientAuth: 'TLS Web Client Authentication', codeSigning: 'Code Signing', emailProtection: 'Email Protection', timeStamping: 'Time Stamping', ocspSigning: 'OCSP Signing' };
  return (cert.extensions ?? []).map((ext: any) => {
    const name = EXT_OID_MAP[ext.id] ?? ext.name ?? ext.id;
    let value: string;
    if (ext.name === 'subjectAltName') value = san.join(', ') || '(none)';
    else if (ext.name === 'keyUsage') value = KU.filter((k) => ext[k]).map((k) => KU_LABEL[k]).join(', ') || '(none)';
    else if (ext.name === 'extKeyUsage') value = EKU.filter((k) => ext[k]).map((k) => EKU_LABEL[k]).join(', ') || '(none)';
    else if (ext.name === 'basicConstraints') value = `CA: ${ext.cA ? 'TRUE' : 'FALSE'}${ext.pathLenConstraint !== undefined ? `, Path Length: ${ext.pathLenConstraint}` : ''}`;
    else if (ext.name === 'subjectKeyIdentifier' && ext.subjectKeyIdentifier) value = bytesToColonHex(forge.util.hexToBytes(ext.subjectKeyIdentifier));
    else value = decodeExtensionValue(ext.id, typeof ext.value === 'string' ? ext.value : '', san);
    return { name, critical: !!ext.critical, value };
  });
}

export type KeyAlgo = 'rsa' | 'ec' | 'ed25519' | 'ed448';
export const EC_CURVE_OPTIONS = ['P-256', 'P-384', 'P-521', 'secp256k1', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1'];

// ─── parseJksBinary ───
export function parseJksBinary(buffer: ArrayBuffer): { alias: string; pem: string }[] {
  // Work on a flat copy — avoids DataView alignment quirks and shared-view issues.
  const d = new Uint8Array(buffer);
  let pos = 0;

  // Big-endian readers (Java DataOutputStream wire format).
  // >>> 0 coerces the result to an unsigned 32-bit number so large lengths
  // like certLen don't become negative in JavaScript's signed 32-bit shift math.
  const r4 = () => {
    const v = ((d[pos] << 24) | (d[pos+1] << 16) | (d[pos+2] << 8) | d[pos+3]) >>> 0;
    pos += 4; return v;
  };
  const r2 = () => { const v = (d[pos] << 8 | d[pos+1]) >>> 0; pos += 2; return v; };
  // Java writeUTF: 2-byte byte-length prefix + modified-UTF-8 bytes.
  const rUtf = () => {
    const len = r2();
    const s = new TextDecoder('utf-8').decode(d.subarray(pos, pos + len));
    pos += len; return s;
  };
  // Return a *copy* of n bytes so subsequent reads don't alias the same memory.
  const rBytes = (n: number) => { const c = d.slice(pos, pos + n); pos += n; return c; };

  const derToPem = (der: Uint8Array) => {
    let bin = '';
    for (let i = 0; i < der.length; i++) bin += String.fromCharCode(der[i]);
    const b64 = btoa(bin);
    const lines = b64.match(/.{1,64}/g) ?? [];
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
  };

  // A JKS certificate record: writeUTF(type) + writeInt(len) + write(der)
  const rCert = (): string | null => {
    const certType = rUtf();
    const certLen = r4();
    const certDer = rBytes(certLen);
    // Accept both "X.509" (standard) and legacy "X509"
    return (certType === 'X.509' || certType === 'X509') ? derToPem(certDer) : null;
  };

  // ── Header ────────────────────────────────────────────────────────────────
  const magic = r4();
  if (magic !== 0xFEEDFEED && magic !== 0xCECECECE) {
    throw new Error(
      `Not a JKS/JCEKS file (magic: 0x${magic.toString(16).toUpperCase().padStart(8, '0')}). ` +
      `Upload a .jks or .jceks file. PKCS#12 (.p12/.pfx) is not supported here.`
    );
  }
  r4(); // version (1 or 2 — same entry format)
  const count = r4();

  const results: { alias: string; pem: string }[] = [];

  for (let i = 0; i < count; i++) {
    // Snapshot pos so we can report where we stopped on error.
    const entryStart = pos;
    try {
      const tag = r4();
      const alias = rUtf();
      pos += 8; // skip timestamp (Java long, 8 bytes) — value not needed

      if (tag === 1) {
        // PrivateKeyEntry — encrypted key blob + cert chain
        // Both JKS (proprietary cipher) and JCEKS (SealedObject serialization)
        // store the key as a plain writeInt(len) + write(bytes) blob.
        const keyLen = r4();
        pos += keyLen;
        const chainLen = r4();
        for (let j = 0; j < chainLen; j++) {
          const pem = rCert();
          if (pem) results.push({ alias: chainLen > 1 ? `${alias} [chain ${j}]` : alias, pem });
        }
      } else if (tag === 2) {
        // TrustedCertEntry — single X.509 cert
        const pem = rCert();
        if (pem) results.push({ alias, pem });
      } else if (tag === 3) {
        // JCEKS SecretKeyEntry — symmetric key, no associated certs; just skip.
        const keyLen = r4();
        pos += keyLen;
      } else {
        // Unrecognised tag — we already consumed tag+alias+timestamp bytes so the
        // cursor is at an unknown position; safest to stop.
        break;
      }
    } catch {
      // If a single entry blows up (e.g. out-of-bounds read on a truncated file)
      // we can't reliably advance, so stop here and return whatever we have.
      void entryStart;
      break;
    }
  }

  return results;
}

// ─── parsePkcs12Binary ───
export function parsePkcs12Binary(buffer: ArrayBuffer, password: string): { alias: string; pem: string }[] {
  const bytes = new Uint8Array(buffer);
  const bin = new TextDecoder('latin1').decode(bytes);
  const CERT_BAG_OID = '1.2.840.113549.1.9.22.1';

  const tryParse = (pw: string) => {
    const asn1 = forge.asn1.fromDer(bin);
    return forge.pkcs12.pkcs12FromAsn1(asn1, pw);
  };

  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    p12 = tryParse(password);
  } catch (e) {
    // MAC check failed — retry with empty password as fallback
    if (password !== '') {
      try { p12 = tryParse(''); } catch {
        throw new Error(
          'Failed to parse PKCS#12 — wrong password? ' +
          'Java default is "changeit". ' +
          `(${String(e)})`
        );
      }
    } else {
      throw new Error(
        'Failed to parse PKCS#12. ' +
        'Try entering the keystore password (Java default: "changeit"). ' +
        `(${String(e)})`
      );
    }
  }

  let certBags: forge.pkcs12.Bag[] = [];
  try { certBags = p12!.getBags({ bagType: CERT_BAG_OID })[CERT_BAG_OID] ?? []; } catch { /* empty */ }

  const results: { alias: string; pem: string }[] = [];
  for (const bag of certBags) {
    const rawAlias = (bag.attributes as any)?.friendlyName?.[0];
    const alias = typeof rawAlias === 'string' ? rawAlias : '';
    if (!bag.cert) continue;
    try {
      results.push({ alias, pem: forge.pki.certificateToPem(bag.cert) });
    } catch {
      // Non-RSA cert: re-encode from ASN.1 directly
      try {
        const der = forge.asn1.toDer(forge.pki.certificateToAsn1(bag.cert)).bytes();
        const b64 = forge.util.encode64(der);
        const lines = b64.match(/.{1,64}/g) ?? [];
        results.push({ alias, pem: `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----` });
      } catch { /* skip */ }
    }
  }
  return results;
}

// ─── Additional types ─────────────────────────────────────────────────────────

export interface ChainLink {
  index: number; subject: string; issuer: string;
  notAfter: string; selfSigned: boolean;
  issuerChainOk: boolean; signatureOk: boolean | null;
}

export type CertType = 'self-signed' | 'ca-signed' | 'root-ca' | 'intermediate-ca';

export interface ChainLink {
  index: number; subject: string; issuer: string;
  notAfter: string; selfSigned: boolean;
  issuerChainOk: boolean; signatureOk: boolean | null;
}
