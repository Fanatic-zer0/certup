// Native certificate cryptography backed by OpenSSL (vendored).
//
// In the desktop (Tauri) build these commands remove the limitations the
// browser/WebCrypto path has:
//   * signature verification for ANY curve (secp256k1, brainpool, …) and EdDSA
//   * EC / Ed25519 / Ed448 key, CSR and certificate generation
//   * PKCS#12 (.pfx) bundling with modern algorithms
//
// The web build keeps its node-forge / WebCrypto fallbacks; the frontend picks
// the native path automatically when running inside Tauri.

use base64::Engine;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509Name, X509NameBuilder, X509Req, X509ReqBuilder, X509};
use serde::{Deserialize, Serialize};

// ─── Shared input/output types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SubjectInput {
    #[serde(default)]
    pub common_name: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub org_unit: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub locality: String,
    /// DNS / IP entries for the SubjectAlternativeName extension.
    #[serde(default)]
    pub san: Vec<String>,
}

/// Key algorithm requested by the UI. `kind` is "rsa" | "ec" | "ed25519" | "ed448".
#[derive(Debug, Deserialize, Clone)]
pub struct KeySpec {
    pub kind: String,
    /// RSA modulus size (when kind == "rsa").
    #[serde(default)]
    pub rsa_bits: u32,
    /// EC curve name (when kind == "ec"): "P-256" | "P-384" | "P-521" |
    /// "secp256k1" | "brainpoolP256r1" | "brainpoolP384r1" | "brainpoolP512r1".
    #[serde(default)]
    pub curve: String,
}

#[derive(Debug, Serialize)]
pub struct KeyCertPair {
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Debug, Serialize)]
pub struct CsrKeyPair {
    pub csr_pem: String,
    pub key_pem: String,
}

#[derive(Debug, Serialize)]
pub struct MatchResult {
    pub matched: bool,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct ChainLinkResult {
    pub index: usize,
    pub subject: String,
    pub issuer: String,
    pub not_after: String,
    pub self_signed: bool,
    pub issuer_chain_ok: bool,
    /// None = could not verify, Some(bool) = verified result.
    pub signature_ok: Option<bool>,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn build_name(subject: &SubjectInput) -> Result<X509Name, String> {
    let mut nb: X509NameBuilder = X509Name::builder().map_err(map_err)?;
    if !subject.common_name.is_empty() {
        nb.append_entry_by_text("CN", &subject.common_name)
            .map_err(map_err)?;
    }
    if !subject.organization.is_empty() {
        nb.append_entry_by_text("O", &subject.organization)
            .map_err(map_err)?;
    }
    if !subject.org_unit.is_empty() {
        nb.append_entry_by_text("OU", &subject.org_unit)
            .map_err(map_err)?;
    }
    if !subject.country.is_empty() {
        nb.append_entry_by_text("C", &subject.country)
            .map_err(map_err)?;
    }
    if !subject.state.is_empty() {
        nb.append_entry_by_text("ST", &subject.state)
            .map_err(map_err)?;
    }
    if !subject.locality.is_empty() {
        nb.append_entry_by_text("L", &subject.locality)
            .map_err(map_err)?;
    }
    Ok(nb.build())
}

fn ec_group_for(curve: &str) -> Result<EcGroup, String> {
    let nid = match curve {
        "P-256" | "prime256v1" | "secp256r1" => Nid::X9_62_PRIME256V1,
        "P-384" | "secp384r1" => Nid::SECP384R1,
        "P-521" | "secp521r1" => Nid::SECP521R1,
        "secp256k1" => Nid::SECP256K1,
        "brainpoolP256r1" => Nid::BRAINPOOL_P256R1,
        "brainpoolP384r1" => Nid::BRAINPOOL_P384R1,
        "brainpoolP512r1" => Nid::BRAINPOOL_P512R1,
        other => return Err(format!("Unsupported EC curve: {other}")),
    };
    EcGroup::from_curve_name(nid).map_err(map_err)
}

/// Generate a private key according to the requested algorithm.
fn generate_pkey(spec: &KeySpec) -> Result<PKey<Private>, String> {
    match spec.kind.as_str() {
        "rsa" => {
            let bits = if spec.rsa_bits == 0 { 2048 } else { spec.rsa_bits };
            let rsa = openssl::rsa::Rsa::generate(bits).map_err(map_err)?;
            PKey::from_rsa(rsa).map_err(map_err)
        }
        "ec" => {
            let group = ec_group_for(&spec.curve)?;
            let ec = EcKey::generate(&group).map_err(map_err)?;
            PKey::from_ec_key(ec).map_err(map_err)
        }
        "ed25519" => PKey::generate_ed25519().map_err(map_err),
        "ed448" => PKey::generate_ed448().map_err(map_err),
        other => Err(format!("Unsupported key kind: {other}")),
    }
}

/// EdDSA keys must sign with a NULL digest; everything else uses SHA-256.
fn digest_for(pkey: &PKey<Private>) -> Option<MessageDigest> {
    match pkey.id() {
        openssl::pkey::Id::ED25519 | openssl::pkey::Id::ED448 => None,
        _ => Some(MessageDigest::sha256()),
    }
}

fn random_serial() -> Result<openssl::asn1::Asn1Integer, String> {
    let mut serial = BigNum::new().map_err(map_err)?;
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .map_err(map_err)?;
    serial.to_asn1_integer().map_err(map_err)
}

fn add_san(
    builder_ctx: &openssl::x509::X509v3Context,
    san: &[String],
) -> Result<Option<openssl::x509::X509Extension>, String> {
    if san.is_empty() {
        return Ok(None);
    }
    let mut sb = SubjectAlternativeName::new();
    for entry in san {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        // crude IPv4 detection; everything else is treated as a DNS name
        let is_ip = trimmed.split('.').count() == 4
            && trimmed.split('.').all(|p| p.parse::<u8>().is_ok());
        if is_ip {
            sb.ip(trimmed);
        } else {
            sb.dns(trimmed);
        }
    }
    let ext = sb.build(builder_ctx).map_err(map_err)?;
    Ok(Some(ext))
}

fn x509_name_to_string(name: &openssl::x509::X509NameRef) -> String {
    let mut parts: Vec<String> = Vec::new();
    for entry in name.entries() {
        let key = entry
            .object()
            .nid()
            .short_name()
            .unwrap_or("?")
            .to_string();
        let val = entry.data().to_string().unwrap_or_default();
        parts.push(format!("{key}={val}"));
    }
    parts.join(", ")
}

// ─── Commands ────────────────────────────────────────────────────────────────

/// Verify a full certificate chain (leaf → … → root). Each PEM block is one cert.
#[tauri::command]
pub fn cert_verify_chain(chain_pem: String) -> Result<Vec<ChainLinkResult>, String> {
    let certs: Vec<X509> = X509::stack_from_pem(chain_pem.as_bytes()).map_err(map_err)?;
    if certs.is_empty() {
        return Err("No certificates found in the provided PEM.".into());
    }

    let mut out = Vec::with_capacity(certs.len());
    for (i, cert) in certs.iter().enumerate() {
        let subject = x509_name_to_string(cert.subject_name());
        let issuer = x509_name_to_string(cert.issuer_name());
        let self_signed = subject == issuer;

        // The issuing cert is self for roots, otherwise the next cert in the chain.
        let issuer_cert: Option<&X509> = if self_signed {
            Some(cert)
        } else {
            certs.get(i + 1)
        };

        let issuer_chain_ok = if self_signed {
            true
        } else {
            match certs.get(i + 1) {
                Some(next) => x509_name_to_string(next.subject_name()) == issuer,
                None => false,
            }
        };

        let signature_ok = match issuer_cert {
            Some(ic) => match ic.public_key() {
                Ok(pk) => cert.verify(&pk).ok(),
                Err(_) => None,
            },
            None => None,
        };

        out.push(ChainLinkResult {
            index: i,
            subject,
            issuer,
            not_after: cert.not_after().to_string(),
            self_signed,
            issuer_chain_ok,
            signature_ok,
        });
    }
    Ok(out)
}

/// Check whether a private key corresponds to a certificate's public key.
#[tauri::command]
pub fn cert_match_key(cert_pem: String, key_pem: String) -> Result<MatchResult, String> {
    let cert = X509::from_pem(cert_pem.as_bytes()).map_err(map_err)?;
    let key = PKey::private_key_from_pem(key_pem.as_bytes()).map_err(map_err)?;
    let cert_pub = cert.public_key().map_err(map_err)?;
    let matched = cert_pub.public_eq(&key);
    Ok(MatchResult {
        matched,
        detail: if matched {
            "The private key matches the certificate's public key.".into()
        } else {
            "The private key does NOT match this certificate.".into()
        },
    })
}

/// Check whether a certificate was issued from a given CSR (public-key match).
#[tauri::command]
pub fn cert_match_csr(cert_pem: String, csr_pem: String) -> Result<MatchResult, String> {
    let cert = X509::from_pem(cert_pem.as_bytes()).map_err(map_err)?;
    let req = X509Req::from_pem(csr_pem.as_bytes()).map_err(map_err)?;
    let cert_pub = cert.public_key().map_err(map_err)?;
    let csr_pub = req.public_key().map_err(map_err)?;
    let matched = cert_pub.public_eq(&csr_pub);
    Ok(MatchResult {
        matched,
        detail: if matched {
            "The certificate's public key matches the CSR.".into()
        } else {
            "The certificate's public key does NOT match the CSR.".into()
        },
    })
}

/// Generate a CSR + private key with any supported algorithm.
#[tauri::command]
pub fn cert_generate_csr(subject: SubjectInput, key: KeySpec) -> Result<CsrKeyPair, String> {
    if subject.common_name.trim().is_empty() {
        return Err("Common Name (CN) is required.".into());
    }
    let pkey = generate_pkey(&key)?;
    let name = build_name(&subject)?;

    let mut builder: X509ReqBuilder = X509Req::builder().map_err(map_err)?;
    builder.set_subject_name(&name).map_err(map_err)?;
    builder.set_pubkey(&pkey).map_err(map_err)?;

    if !subject.san.is_empty() {
        let mut exts: Stack<openssl::x509::X509Extension> = Stack::new().map_err(map_err)?;
        let ctx = builder.x509v3_context(None);
        if let Some(ext) = add_san(&ctx, &subject.san)? {
            exts.push(ext).map_err(map_err)?;
        }
        builder.add_extensions(&exts).map_err(map_err)?;
    }

    match digest_for(&pkey) {
        Some(md) => builder.sign(&pkey, md).map_err(map_err)?,
        None => builder.sign(&pkey, MessageDigest::null()).map_err(map_err)?,
    }

    let csr = builder.build();
    Ok(CsrKeyPair {
        csr_pem: String::from_utf8(csr.to_pem().map_err(map_err)?).map_err(map_err)?,
        key_pem: String::from_utf8(pkey.private_key_to_pem_pkcs8().map_err(map_err)?)
            .map_err(map_err)?,
    })
}

/// Parameters shared by all certificate-generation flavors.
#[derive(Debug, Deserialize)]
pub struct GenCertInput {
    /// "self-signed" | "root-ca" | "intermediate-ca" | "ca-signed"
    pub cert_type: String,
    #[serde(default)]
    pub subject: Option<SubjectInput>,
    pub key: KeySpec,
    pub valid_days: u32,
    /// Issuing CA cert + key (for intermediate-ca / ca-signed).
    #[serde(default)]
    pub ca_cert_pem: String,
    #[serde(default)]
    pub ca_key_pem: String,
    /// CSR to sign (for ca-signed).
    #[serde(default)]
    pub csr_pem: String,
}

#[tauri::command]
pub fn cert_generate(input: GenCertInput) -> Result<KeyCertPair, String> {
    let days = if input.valid_days == 0 {
        365
    } else {
        input.valid_days
    };
    let not_before = Asn1Time::days_from_now(0).map_err(map_err)?;
    let not_after = Asn1Time::days_from_now(days).map_err(map_err)?;

    let mut builder: X509Builder = X509::builder().map_err(map_err)?;
    builder.set_version(2).map_err(map_err)?; // X.509 v3
    builder.set_not_before(&not_before).map_err(map_err)?;
    builder.set_not_after(&not_after).map_err(map_err)?;
    let serial = random_serial()?;
    builder.set_serial_number(&serial).map_err(map_err)?;

    // Each branch sets the subject name + public key on the builder, then yields
    // the signing key, issuer name, and (for generated keys) the private-key PEM.
    let (signing_key, issuer_name, generated_key_pem): (PKey<Private>, X509Name, Option<String>);

    match input.cert_type.as_str() {
        "self-signed" | "root-ca" => {
            let subject = input
                .subject
                .as_ref()
                .ok_or("Subject is required.".to_string())?;
            if subject.common_name.trim().is_empty() {
                return Err("Common Name (CN) is required.".into());
            }
            let pkey = generate_pkey(&input.key)?;
            let name = build_name(subject)?;
            let issuer = build_name(subject)?; // self-issued
            let key_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8().map_err(map_err)?)
                .map_err(map_err)?;
            builder.set_subject_name(&name).map_err(map_err)?;
            builder.set_pubkey(&pkey).map_err(map_err)?;
            // subject and signing key are the same key (self-signed)
            (signing_key, issuer_name, generated_key_pem) = (pkey, issuer, Some(key_pem));
        }
        "intermediate-ca" => {
            let subject = input
                .subject
                .as_ref()
                .ok_or("Subject is required.".to_string())?;
            if subject.common_name.trim().is_empty() {
                return Err("Common Name (CN) is required.".into());
            }
            if input.ca_cert_pem.trim().is_empty() || input.ca_key_pem.trim().is_empty() {
                return Err("Root CA certificate and key are required.".into());
            }
            let ca_cert = X509::from_pem(input.ca_cert_pem.as_bytes()).map_err(map_err)?;
            let ca_key = PKey::private_key_from_pem(input.ca_key_pem.as_bytes()).map_err(map_err)?;
            let pkey = generate_pkey(&input.key)?;
            let name = build_name(subject)?;
            let key_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8().map_err(map_err)?)
                .map_err(map_err)?;
            builder.set_subject_name(&name).map_err(map_err)?;
            builder.set_pubkey(&pkey).map_err(map_err)?;
            (signing_key, issuer_name, generated_key_pem) = (
                ca_key,
                ca_cert.subject_name().to_owned().map_err(map_err)?,
                Some(key_pem),
            );
        }
        "ca-signed" => {
            if input.ca_cert_pem.trim().is_empty() || input.ca_key_pem.trim().is_empty() {
                return Err("CA certificate and key are required.".into());
            }
            if input.csr_pem.trim().is_empty() {
                return Err("CSR is required.".into());
            }
            let ca_cert = X509::from_pem(input.ca_cert_pem.as_bytes()).map_err(map_err)?;
            let ca_key = PKey::private_key_from_pem(input.ca_key_pem.as_bytes()).map_err(map_err)?;
            let req = X509Req::from_pem(input.csr_pem.as_bytes()).map_err(map_err)?;
            let req_pub = req.public_key().map_err(map_err)?;
            // Verify the CSR self-signature before trusting its contents.
            if !req.verify(&req_pub).map_err(map_err)? {
                return Err("CSR signature is invalid.".into());
            }
            builder.set_subject_name(req.subject_name()).map_err(map_err)?;
            builder.set_pubkey(&req_pub).map_err(map_err)?;
            (signing_key, issuer_name, generated_key_pem) = (
                ca_key,
                ca_cert.subject_name().to_owned().map_err(map_err)?,
                None,
            );
        }
        other => return Err(format!("Unknown certificate type: {other}")),
    }

    builder.set_issuer_name(&issuer_name).map_err(map_err)?;

    // Extensions vary by certificate role.
    let is_ca = matches!(input.cert_type.as_str(), "root-ca" | "intermediate-ca");
    if is_ca {
        let mut bc = BasicConstraints::new();
        bc.critical().ca();
        if input.cert_type == "intermediate-ca" {
            bc.pathlen(0);
        }
        builder.append_extension(bc.build().map_err(map_err)?).map_err(map_err)?;
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .map_err(map_err)?,
            )
            .map_err(map_err)?;
    } else {
        builder
            .append_extension(BasicConstraints::new().build().map_err(map_err)?)
            .map_err(map_err)?;
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .key_encipherment()
                    .build()
                    .map_err(map_err)?,
            )
            .map_err(map_err)?;
        builder
            .append_extension(
                ExtendedKeyUsage::new()
                    .server_auth()
                    .client_auth()
                    .build()
                    .map_err(map_err)?,
            )
            .map_err(map_err)?;
    }

    // SKI / AKI and SAN need the v3 context (borrows issuer cert when present).
    {
        let issuer_ref = if input.cert_type == "intermediate-ca" || input.cert_type == "ca-signed" {
            X509::from_pem(input.ca_cert_pem.as_bytes()).ok()
        } else {
            None
        };
        let ctx = builder.x509v3_context(issuer_ref.as_deref(), None);
        let ski = SubjectKeyIdentifier::new()
            .build(&ctx)
            .map_err(map_err)?;
        let aki = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&ctx)
            .map_err(map_err)?;
        let san_ext = if let Some(subject) = input.subject.as_ref() {
            add_san(&ctx, &subject.san)?
        } else {
            None
        };
        // ctx borrows builder immutably; collect extensions then drop ctx.
        let mut pending: Vec<openssl::x509::X509Extension> = vec![ski];
        if input.cert_type != "self-signed" && input.cert_type != "root-ca" {
            pending.push(aki);
        }
        if let Some(e) = san_ext {
            pending.push(e);
        }
        drop(ctx);
        for ext in pending {
            builder.append_extension(ext).map_err(map_err)?;
        }
    }

    match digest_for(&signing_key) {
        Some(md) => builder.sign(&signing_key, md).map_err(map_err)?,
        None => builder.sign(&signing_key, MessageDigest::null()).map_err(map_err)?,
    }

    let cert = builder.build();
    Ok(KeyCertPair {
        cert_pem: String::from_utf8(cert.to_pem().map_err(map_err)?).map_err(map_err)?,
        key_pem: generated_key_pem.unwrap_or_default(),
    })
}

/// Bundle a cert + key (+ optional chain) into a base64-encoded PKCS#12 file.
#[tauri::command]
pub fn cert_to_pkcs12(
    cert_pem: String,
    key_pem: String,
    chain_pem: String,
    password: String,
    friendly_name: String,
) -> Result<String, String> {
    let cert = X509::from_pem(cert_pem.as_bytes()).map_err(map_err)?;
    let key = PKey::private_key_from_pem(key_pem.as_bytes()).map_err(map_err)?;

    let mut ca_stack: Stack<X509> = Stack::new().map_err(map_err)?;
    if !chain_pem.trim().is_empty() {
        for c in X509::stack_from_pem(chain_pem.as_bytes()).map_err(map_err)? {
            ca_stack.push(c).map_err(map_err)?;
        }
    }

    let mut builder = Pkcs12::builder();
    builder.name(if friendly_name.trim().is_empty() {
        "certificate"
    } else {
        friendly_name.trim()
    });
    builder.pkey(&key);
    builder.cert(&cert);
    if ca_stack.len() > 0 {
        builder.ca(ca_stack);
    }
    let pkcs12 = builder.build2(&password).map_err(map_err)?;
    let der = pkcs12.to_der().map_err(map_err)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(der))
}
