# ADR 0004: Shared session verification

The API Gateway and Vault Engine use one shared JWE verifier so the Vault independently authenticates every request and never trusts forwarded identity headers.
