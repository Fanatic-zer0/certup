# CertUp

A handy cert utility working with PEM, X.509 certificates, CSRs, keystores, and private keys.

All cryptographic operations run locally in the app.

---

## Features

### Inspect
| Tab | Description |
|-----|-------------|
| **Cert Decode** | Parse any PEM certificate — subject, issuer, SANs, extensions, fingerprints, expiry status |
| **CSR Decode** | Inspect a PEM CSR — subject, public key info, requested extensions |

### Verify
| Tab | Description |
|-----|-------------|
| **Cert ↔ Key** | Check whether a certificate and private key are a matching pair |
| **Cert ↔ CSR** | Confirm a certificate was issued from a given CSR |
| **CSR ↔ Key** | Verify a CSR was signed with a specific private key |
| **Chain Verify** | Validate a full certificate chain (leaf → intermediates → root CA) |

### Stores
| Tab | Description |
|-----|-------------|
| **CA Bundle** | Parse and inspect JKS / PKCS#12 / PEM CA bundle files |
| **Keystore** | Browse entries in a Java KeyStore or PKCS#12 archive |

### Generate
| Tab | Description |
|-----|-------------|
| **Generate CSR** | Create a new CSR with custom subject, SANs, and key algorithm |
| **Generate Cert** | Self-sign or CA-sign a certificate from a CSR |
| **To PFX / P12** | Bundle a certificate + private key into a PKCS#12 / PFX archive |

---

## Tech Stack

- **Runtime** — [Tauri v2](https://tauri.app) (Rust backend, WebView frontend)
- **UI** — React 19, TypeScript, Tailwind CSS v4, Radix UI primitives
- **Crypto** — [node-forge](https://github.com/digitalbazaar/forge) (pure JS, fully offline)
- **Build** — Vite 6

---

## Development

### Prerequisites

- [Node.js](https://nodejs.org) ≥ 20
- [Rust](https://rustup.rs) (stable, ≥ 1.77)
- Tauri CLI v2 (`npm install` installs it as a dev dependency)

### Install dependencies

```bash
npm install
```

### Run in dev mode

```bash
npm run tauri:dev
```

### Build a release app

```bash
npm run tauri:build
```

The signed/notarized build script (macOS) can be run with:

```bash
npm run ship
```

---

## Project Structure

```
src/
  components/
    Shell.tsx           # Sidebar navigation + layout shell
    cert-components.tsx # Shared cert display primitives (Section, Field, TrustEntryCard…)
    ui/
      badge.tsx         # Status badge component (valid, expired, warning, info…)
      button.tsx
      card.tsx
      cert-ui.tsx       # CopyBtn, MatchBanner, CliBlock, PemOutput
      input.tsx         # Input, Textarea, Label
  lib/
    cert-crypto.ts      # All cryptographic helpers (forge-based)
    nativeCrypto.ts     # Native WebCrypto / Tauri-backed operations
    utils.ts
  tabs/                 # One file per tool tab
src-tauri/
  src/
    cert.rs             # Rust-side certificate helpers
    lib.rs
    main.rs
  icons/                # All app icon sizes (generated via `tauri icon`)
  tauri.conf.json
```

---
