import { createRemoteJWKSet, jwtVerify } from 'jose';

import { AuthUser } from './webauthn';

export interface GitHubIdentity {
  subject: string;
  email: string;
  displayName: string;
}

export interface GitHubIdentityVerifier {
  verify(idToken: string): Promise<GitHubIdentity>;
}

export function createGitHubOidcVerifier(config: { issuer: string; audience: string; jwksUrl: string }): GitHubIdentityVerifier {
  const keySet = createRemoteJWKSet(new URL(config.jwksUrl));
  return {
    async verify(idToken: string): Promise<GitHubIdentity> {
      const { payload } = await jwtVerify(idToken, keySet, { issuer: config.issuer, audience: config.audience });
      if (typeof payload.sub !== 'string' || typeof payload.email !== 'string') {
        throw new Error('GitHub OIDC token does not contain a subject and verified email');
      }
      return {
        subject: payload.sub,
        email: payload.email.toLowerCase(),
        displayName: typeof payload.name === 'string' ? payload.name : payload.email,
      };
    },
  };
}

export interface GitHubUserRepository {
  findByGitHubId(githubId: string): Promise<AuthUser | null>;
  createGitHubUser(identity: GitHubIdentity): Promise<AuthUser>;
}

export class GitHubAuthenticationService {
  public constructor(
    private readonly verifier: GitHubIdentityVerifier,
    private readonly users: GitHubUserRepository,
  ) {}

  public async authenticate(idToken: string): Promise<AuthUser> {
    const identity = await this.verifier.verify(idToken);
    return (await this.users.findByGitHubId(identity.subject)) ?? this.users.createGitHubUser(identity);
  }
}
