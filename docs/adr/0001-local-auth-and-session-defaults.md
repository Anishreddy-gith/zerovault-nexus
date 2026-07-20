# ADR 0001: Local authentication and session defaults

For local development, WebAuthn uses RP ID `localhost` and origin `http://localhost:4000`; sessions are encrypted JWE tokens with a 15-minute expiry.
