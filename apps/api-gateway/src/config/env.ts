export interface GatewayEnvironment {
  webauthnRpId: string;
  webauthnOrigin: string;
  webauthnRpName: string;
  sessionJweKeyBase64: string;
  sessionTtlSeconds: number;
  spiffeTrustDomain: string;
  githubOidcIssuer: string;
  githubOidcAudience: string;
  githubOidcJwksUrl: string;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} must be set`);
  }
  return value;
}

export function loadGatewayEnvironment(): GatewayEnvironment {
  return {
    webauthnRpId: required('WEBAUTHN_RP_ID'),
    webauthnOrigin: required('WEBAUTHN_ORIGIN'),
    webauthnRpName: required('WEBAUTHN_RP_NAME'),
    sessionJweKeyBase64: required('SESSION_JWE_KEY_BASE64'),
    sessionTtlSeconds: Number(process.env.SESSION_TTL_SECONDS ?? 900),
    spiffeTrustDomain: required('SPIFFE_TRUST_DOMAIN'),
    githubOidcIssuer: required('GITHUB_OIDC_ISSUER'),
    githubOidcAudience: required('GITHUB_OIDC_AUDIENCE'),
    githubOidcJwksUrl: required('GITHUB_OIDC_JWKS_URL'),
  };
}
