# ZeroVault Nexus STRIDE threat model

## API Gateway

| Threat | Risk | Mitigation |
|---|---|---|
| Spoofing | Stolen browser session is presented as a user. | Require WebAuthn ceremony verification and encrypted, short-lived JWE sessions. |
| Tampering | A caller alters request bodies or session ciphertext. | Enforce HTTPS in deployment, schema validation, and JWE authenticated encryption. |
| Repudiation | A caller denies a sensitive API operation. | Attach verified subject and request trace ID to append-only audit events. |
| Information disclosure | Error responses expose credentials or internals. | Return generic auth failures and apply Helmet security headers. |
| Denial of service | Authentication endpoints are flooded. | Apply per-route rate limits and bounded WebAuthn challenge storage. |
| Elevation of privilege | A session claim is changed to add roles. | Verify JWE integrity and authorize from server-side roles for sensitive operations. |

## Vault Engine

| Threat | Risk | Mitigation |
|---|---|---|
| Spoofing | An untrusted service claims to be the vault. | Authenticate service transport with SPIFFE/mTLS in deployed environments. |
| Tampering | Ciphertext is changed in MongoDB. | AES-256-GCM authentication rejects modified ciphertext. |
| Repudiation | A secret update has no attributable actor. | Require an authenticated subject and emit an audit record for writes. |
| Information disclosure | Plaintext or DEKs are persisted. | Store only AES-GCM ciphertext and RSA-OAEP-wrapped DEKs. |
| Denial of service | Large plaintexts exhaust memory. | Enforce API payload limits before encryption. |
| Elevation of privilege | A caller reads secrets outside its grant. | Invoke OPA authorization before decrypting any secret. |

## Policy Engine

| Threat | Risk | Mitigation |
|---|---|---|
| Spoofing | A rogue process impersonates OPA. | Restrict OPA to the private Docker network and use authenticated service transport in production. |
| Tampering | A policy bundle is modified. | Version policy bundles, review changes, and deploy immutable signed artifacts. |
| Repudiation | A policy decision cannot be reconstructed. | Audit policy input, decision, and policy bundle revision. |
| Information disclosure | Policy input leaks secret values. | Pass identifiers and metadata only; never include secret plaintext. |
| Denial of service | Expensive policy evaluation blocks requests. | Set input-size and evaluation time limits at the gateway. |
| Elevation of privilege | A default-allow rule grants access. | Use deny-by-default policies with explicit grants and tests. |

## Lease Manager

| Threat | Risk | Mitigation |
|---|---|---|
| Spoofing | A caller presents another workload's lease. | Bind leases to verified session/workload subject and audience. |
| Tampering | TTL or lease state is edited in Valkey. | Use ACL-protected Valkey, signed lease tokens, and server-side expiry. |
| Repudiation | Lease use or revocation is disputed. | Log issue, access, revocation, expiry, and correlation IDs. |
| Information disclosure | A lease exposes a reusable secret. | Lease only short-lived, scoped references and never log bearer material. |
| Denial of service | Lease creation exhausts cache memory. | Cap active leases per principal and set maximum TTLs. |
| Elevation of privilege | A lease is used for a different secret. | Put secret ID, subject, and permitted operation in authenticated lease claims. |

## Audit Ledger

| Threat | Risk | Mitigation |
|---|---|---|
| Spoofing | Untrusted code writes audit entries. | Allow writes only through authenticated internal service identity. |
| Tampering | Historical entries are edited or deleted. | Use append-only permissions, majority writes, and a SHA-256 hash chain. |
| Repudiation | An event is claimed to be fabricated. | Store actor, timestamp, request trace, and signed/verified identity context. |
| Information disclosure | Audit records contain secret values. | Redact secret payloads; record metadata and hashes only. |
| Denial of service | Audit ingestion blocks the request path. | Batch noncritical enrichment and size-limit event fields. |
| Elevation of privilege | Audit readers gain secret access. | Separate audit-read role from secret-read permissions. |

## Agent / Workload Identity Service

| Threat | Risk | Mitigation |
|---|---|---|
| Spoofing | A process claims a SPIFFE ID in a header. | Read the URI SAN from the mutually authenticated TLS peer certificate, never a caller header. |
| Tampering | A child agent requests expanded tool scope. | Reject any child scope that is not a subset of its parent's scope. |
| Repudiation | An agent denies creating a sub-agent. | Persist parent ID, creator subject, and creation time in the identity record. |
| Information disclosure | Tool scopes reveal operational details. | Limit identity CRUD to authorized operators and redact credentials. |
| Denial of service | Attackers create unlimited sub-agents. | Rate-limit identity creation and enforce parent/child depth quotas. |
| Elevation of privilege | A child inherits or expands privileges. | Verify parent linkage and subset scope on every creation and authorization. |
