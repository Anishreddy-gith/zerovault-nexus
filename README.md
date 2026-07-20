# 🔐 ZeroVault Nexus

**Hardware-Backed Zero Trust Secret Orchestration Platform**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-in%20development-yellow.svg)]()
[![Node](https://img.shields.io/badge/node-%3E%3D20.x-339933?logo=node.js&logoColor=white)]()
[![Python](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)]()
[![React](https://img.shields.io/badge/react-19.x-61DAFB?logo=react&logoColor=black)]()
[![MongoDB](https://img.shields.io/badge/mongodb-8.3-47A248?logo=mongodb&logoColor=white)]()
[![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white)]()
[![Kubernetes](https://img.shields.io/badge/kubernetes-ready-326CE5?logo=kubernetes&logoColor=white)]()

> A self-hostable, open-architecture alternative to HashiCorp Vault — combining **WebAuthn/FIDO2-first authentication**, **envelope encryption**, **just-in-time ephemeral secret leasing**, **graph-based credential lineage**, and an **ML-driven anomaly detection ensemble** into a single zero-trust secrets platform.

---

## Why ZeroVault Nexus?

Most teams still manage secrets the way they did a decade ago — `.env` files, Slack messages, hardcoded credentials, or spreadsheets. Credential exposure and vulnerability exploitation remain top initial-access vectors in modern breaches, and existing tooling forces an uncomfortable trade-off:

| Tool | The Problem |
|---|---|
| **HashiCorp Vault** | Operationally heavy, requires dedicated SRE time, BSL licensing uncertainty (now under IBM ownership) |
| **AWS / Azure / GCP Secret Managers** | Cloud vendor lock-in, weak cross-cloud story, limited anomaly detection |
| **`.env` files / static tokens** | No rotation, no audit trail, no revocation — the de facto startup standard |
| **CyberArk** | Enterprise-grade but priced out of reach for startups and small teams, closed-source |

**ZeroVault Nexus** integrates five capabilities that individually exist in the industry but have never been combined in a single open-architecture platform:

- 🔑 **Hardware-backed authentication** — WebAuthn/FIDO2 as the *primary* auth primitive, not an add-on
- 🔒 **Envelope encryption with KMS delegation** — DEK/KEK key hierarchy; keys never leave the KMS boundary
- ⏱️ **Just-in-time ephemeral leasing** — secrets are leased for a bounded TTL, never persisted client-side
- 🕸️ **Graph-based credential lineage** — directed graph tracking identity → secret → time for forensic/blast-radius analysis
- 🤖 **ML-driven anomaly detection** — Isolation Forest + Autoencoder ensemble baselining per-identity access behavior

---

## Architecture

ZeroVault Nexus is a seven-layer system. Every request traverses the API Gateway, is authorized by the Policy Engine, processed by the Vault Engine, and logged by the Audit Ledger before any secret payload is returned.

```
┌─────────────────────┐
│   React Dashboard    │  Secret mgmt UI · RBAC config · lineage graph · live alerts
└──────────┬───────────┘
           │ HTTPS + WebSocket
┌──────────▼───────────┐
│     API Gateway       │  Routing · TLS · rate limiting · session verification
└──────────┬───────────┘
           │
┌──────────▼───────────┐      ┌────────────────┐
│     Vault Engine      │◄────►│  Policy Engine  │  OPA / Rego (RBAC + ABAC)
│  envelope encryption   │      └────────────────┘
│  lease issuance (JWE)  │
└──────────┬───────────┘
           │
┌──────────▼───────────┐      ┌────────────────┐
│    Lease Manager       │      │  Audit Ledger   │  SHA-256 hash-chained, tamper-evident
│  Redis TTL + revocation│─────►│  MongoDB        │
└──────────┬───────────┘      └────────┬────────┘
           │                             │
┌──────────▼─────────────────────────────▼────────┐
│           ML Anomaly Service (FastAPI)            │
│     Isolation Forest + Autoencoder ensemble         │
└────────────────────────────────────────────────────┘
```

| Layer | Purpose | Tech |
|---|---|---|
| React Dashboard | Secret mgmt, RBAC config, lineage graph, audit viewer, live alerts | React 19, TanStack Query, D3.js, Tailwind |
| API Gateway | Ingress, TLS, rate limiting, validation | Express.js, Helmet.js, OpenTelemetry |
| Vault Engine | Secret CRUD, envelope encryption, lease issuance | Node.js, `jose` (JWE), `crypto` (AES-256-GCM) |
| Policy Engine | Synchronous RBAC/ABAC authorization | OPA sidecar, Rego, Git-versioned bundles |
| Lease Manager | Ephemeral lease lifecycle | Valkey (EXPIRE + keyspace notifications), JWE |
| Audit Ledger | Append-only, tamper-evident event log | MongoDB (majority write concern), SHA-256 hash chain |
| ML Anomaly Service | Async inference on access-event streams | Python 3.12, FastAPI, scikit-learn, PyTorch |

---

## Tech Stack

- **Frontend:** React 19, TanStack Query, D3.js, Tailwind CSS
- **Backend:** Node.js, Express.js, `jose`, Argon2id
- **Data:** MongoDB 8.3 (Queryable Encryption), Valkey (Redis-compatible, Linux Foundation governed)
- **Auth:** WebAuthn/FIDO2 (`simplewebauthn`), OAuth2/OIDC, JWT/JWS/JWE
- **Policy:** Open Policy Agent (OPA) / Rego
- **ML:** Python 3.12, FastAPI, scikit-learn (Isolation Forest), PyTorch (Autoencoder)
- **Infra:** Docker Compose (dev), Kubernetes + Helm (prod), GitHub Actions CI/CD
- **Security tooling:** OWASP ZAP, Snyk, Trivy, cosign

> **Note on Redis:** Redis 8.0+ shifted to a source-available license (SSPLv1/RSALv2). This project uses **Valkey** — the Linux Foundation–governed, wire-compatible fork (also the default on AWS ElastiCache/MemoryDB) — to keep the stack fully open-source, consistent with the Apache 2.0 licensing goal below.

---

## Key Differentiators vs. HashiCorp Vault

| Dimension | HashiCorp Vault | ZeroVault Nexus |
|---|---|---|
| License | BSL, now under IBM ownership | Apache 2.0 (fully open) |
| Authentication | Tokens, AppRole, LDAP | WebAuthn/FIDO2-first (phishing-resistant) |
| Anomaly Detection | None | Isolation Forest + Autoencoder ensemble |
| Credential Graph | None | D3.js lineage visualizer |
| Policy Language | HCL | OPA Rego (formally verifiable) |
| Operational Complexity | High (dedicated SRE) | Moderate (self-hostable via Docker Compose) |

---

## Getting Started

### Prerequisites
- Node.js ≥ 20.x
- Python ≥ 3.12
- Docker & Docker Compose
- pnpm (`npm install -g pnpm`)

### Local Development

```powershell
git clone https://github.com/<your-username>/zerovault-nexus.git
Set-Location zerovault-nexus
Copy-Item .env.example .env
corepack pnpm install
docker compose up -d
corepack pnpm --filter api-gateway exec tsx src/server.ts
```

The dashboard will be available at `http://localhost:5173`, the API at `http://localhost:4000`.

---

## Project Status & Roadmap

Built over a 6-month (24-week) roadmap by a 3-engineer team. Current phase tracked below.

- [ ] **Phase 1 — Foundation** (Weeks 1–4): monorepo, threat model, crypto primitives, DB schemas
- [ ] **Phase 2 — Authentication** (Weeks 5–8): WebAuthn/FIDO2, JWE sessions, OAuth2/OIDC
- [ ] **Phase 3 — Secret Engine** (Weeks 7–10): envelope encryption, lease issuance, revocation
- [ ] **Phase 4 — RBAC + Policy Engine** (Weeks 9–12): OPA integration, Rego policies
- [ ] **Phase 5 — Audit System** (Weeks 11–14): hash-chained audit ledger, tamper detection
- [ ] **Phase 6 — ML Detection** (Weeks 13–18): feature engineering, Isolation Forest + Autoencoder
- [ ] **Phase 7 — Enterprise Features** (Weeks 17–22): rotation, multi-tenancy, observability, CI/CD
- [ ] **Phase 8 — Hardening + Demo** (Weeks 21–24): pentesting, dependency scanning, docs, demo

Full roadmap detail lives in [`docs/PROJECT_GUIDE.md`](docs/PROJECT_GUIDE.md).

---

## Security

- All secrets encrypted at rest with **AES-256-GCM**, DEKs wrapped via **RSA-OAEP** (KMS-delegated)
- **Zero standing privilege** — every secret access is a short-TTL, single-use JWE lease
- **Tamper-evident audit log** — SHA-256 hash chain; any modification breaks verification
- Passwordless by default — WebAuthn/FIDO2 for interactive users, Argon2id for service accounts
- CI pipeline includes OWASP ZAP (DAST), Snyk (SCA), and Trivy (container scanning)

Found a vulnerability? Please see [`SECURITY.md`](SECURITY.md) for responsible disclosure.

---

## Research Extensions

This project doubles as a research vehicle. Active/planned directions include:

- **Lease-invariant formal verification** (Z3/Alloy) for JIT secret-leasing semantics
- **zkML proof-of-anomaly-decision** — proving the ML service flagged/cleared an event without revealing the feature vector
- **Non-human / AI-agent identity leasing** — short-lived, intent-scoped credentials per tool-call, revocation tied to task completion rather than TTL alone
- **Post-quantum credential issuance** — ML-KEM / ML-DSA migration path for KEK wrapping and session signing
- **Federated secret sharing** — Shamir's Secret Sharing + MPC for threshold KEK custody

See [`docs/RESEARCH.md`](docs/RESEARCH.md) for full writeups.

---

## Contributing

Contributions welcome. Please open an issue before submitting large PRs. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for branching strategy (`main` / `develop` / `feature/*`) and commit conventions.

## License

Licensed under the [Apache License 2.0](LICENSE).

---

<p align="center">Built as a zero-trust secrets platform exploring hardware-backed auth, applied cryptography, and ML-driven security telemetry.</p>
