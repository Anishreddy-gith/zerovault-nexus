# ADR 0006: Lease terminal-state retention and expiry listener

Lease records retain terminal status for audit, and the Vault Engine process owns the Valkey expiry subscriber so expiry updates happen in the same persistence boundary as issuance and revocation.
