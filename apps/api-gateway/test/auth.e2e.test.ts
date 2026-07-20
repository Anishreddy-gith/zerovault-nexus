import { randomBytes } from 'node:crypto';
import request from 'supertest';

import { AgentIdentity, AgentIdentityRepository, AgentIdentityService } from '../src/agents/agentIdentityService';
import { GitHubAuthenticationService, GitHubIdentity, GitHubIdentityVerifier } from '../src/auth/github';
import { SessionService } from '../src/auth/session';
import { AuthUser, StoredCredential, UserRepository, WebAuthnProvider, WebAuthnService } from '../src/auth/webauthn';
import { createGatewayApp } from '../src/app';
import { GatewayEnvironment } from '../src/config/env';

class MemoryUsers implements UserRepository {
  public readonly users = new Map<string, AuthUser>();

  public async findByEmail(email: string): Promise<AuthUser | null> {
    return this.users.get(email) ?? null;
  }

  public async create(user: AuthUser): Promise<AuthUser> {
    this.users.set(user.email, user);
    return user;
  }

  public async updateCredentialCounter(userId: string, credentialId: string, counter: number): Promise<void> {
    for (const user of this.users.values()) {
      if (user.id === userId) {
        user.credentials = user.credentials.map((credential) =>
          credential.credentialId === credentialId ? { ...credential, counter } : credential,
        );
      }
    }
  }
}

class VirtualAuthenticator implements WebAuthnProvider {
  public async registrationOptions(input: { userId: string; email: string; displayName: string }) {
    return { challenge: `registration-${input.userId}`, options: { challenge: `registration-${input.userId}` } };
  }

  public async verifyRegistration(input: { response: unknown; challenge: string }) {
    return {
      verified: Boolean((input.response as { challenge?: string }).challenge === input.challenge),
      credential: { credentialId: 'virtual-credential', publicKey: 'virtual-public-key', counter: 0, transports: ['internal'] },
    };
  }

  public async authenticationOptions(input: { credentials: StoredCredential[] }) {
    return { challenge: `authentication-${input.credentials[0].credentialId}`, options: { challenge: `authentication-${input.credentials[0].credentialId}` } };
  }

  public async verifyAuthentication(input: { response: unknown; challenge: string; credential: StoredCredential }) {
    return {
      verified: (input.response as { challenge?: string }).challenge === input.challenge && input.credential.credentialId === 'virtual-credential',
      newCounter: input.credential.counter + 1,
    };
  }
}

class MemoryAgents implements AgentIdentityRepository {
  private readonly agents = new Map<string, AgentIdentity>();
  private nextId = 1;

  public async create(agent: Omit<AgentIdentity, 'id'>): Promise<AgentIdentity> {
    const created = { ...agent, id: String(this.nextId++) };
    this.agents.set(created.id, created);
    return created;
  }

  public async getById(id: string): Promise<AgentIdentity | null> { return this.agents.get(id) ?? null; }
  public async update(id: string, update: Pick<AgentIdentity, 'name' | 'toolScope' | 'active'>): Promise<AgentIdentity | null> {
    const current = this.agents.get(id);
    if (!current) return null;
    const updated = { ...current, ...update };
    this.agents.set(id, updated);
    return updated;
  }
  public async delete(id: string): Promise<boolean> { return this.agents.delete(id); }
}

const environment: GatewayEnvironment = {
  webauthnRpId: 'localhost',
  webauthnOrigin: 'http://localhost:4000',
  webauthnRpName: 'ZeroVault Nexus Local',
  sessionJweKeyBase64: randomBytes(32).toString('base64'),
  sessionTtlSeconds: 900,
  spiffeTrustDomain: 'zerovault.local',
  githubOidcIssuer: 'https://github.com',
  githubOidcAudience: 'zerovault-nexus',
  githubOidcJwksUrl: 'https://github.com/.well-known/jwks.json',
};

function makeApp() {
  const users = new MemoryUsers();
  const githubVerifier: GitHubIdentityVerifier = {
    verify: async (): Promise<GitHubIdentity> => ({ subject: 'github-42', email: 'octo@example.test', displayName: 'Octo Cat' }),
  };
  const githubUsers = {
    findByGitHubId: async () => null,
    createGitHubUser: async (identity: GitHubIdentity): Promise<AuthUser> => ({ id: 'github-user', email: identity.email, displayName: identity.displayName, roles: ['user'], credentials: [] }),
  };
  const sessions = new SessionService(environment.sessionJweKeyBase64, environment.sessionTtlSeconds);
  return {
    sessions,
    app: createGatewayApp({
      environment,
      webAuthn: new WebAuthnService(users, new VirtualAuthenticator()),
      github: new GitHubAuthenticationService(githubVerifier, githubUsers),
      sessions,
      agents: new AgentIdentityService(new MemoryAgents()),
      enforceWorkloadIdentity: false,
    }),
  };
}

describe('Phase 2 authentication flows', () => {
  it('registers a virtual WebAuthn credential and then authenticates it end to end', async () => {
    const { app, sessions } = makeApp();
    const email = 'passkey@example.test';
    const beginRegistration = await request(app).post('/auth/webauthn/register/options').send({ email, displayName: 'Pass Key' }).expect(200);
    await request(app).post('/auth/webauthn/register/verify').send({ email, response: { challenge: beginRegistration.body.options.challenge } }).expect(201);
    const beginAuthentication = await request(app).post('/auth/webauthn/authenticate/options').send({ email }).expect(200);
    const authenticated = await request(app).post('/auth/webauthn/authenticate/verify').send({ email, response: { credentialId: 'virtual-credential', challenge: beginAuthentication.body.options.challenge } }).expect(200);

    expect(await sessions.verify(authenticated.body.token)).toMatchObject({ email, authMethod: 'webauthn', roles: ['user'] });
  });

  it('accepts a valid JWE and rejects tampered and expired session tokens with HTTP 401', async () => {
    const { app, sessions } = makeApp();
    const valid = await sessions.issue({ sub: 'user-1', email: 'user@example.test', roles: ['user'], authMethod: 'webauthn' });
    await request(app).get('/protected').set('Authorization', `Bearer ${valid}`).expect(200);
    const tampered = `x${valid.slice(1)}`;
    await request(app).get('/protected').set('Authorization', `Bearer ${tampered}`).expect(401);
    const expired = await new SessionService(environment.sessionJweKeyBase64, -1).issue({ sub: 'user-1', email: 'user@example.test', roles: ['user'], authMethod: 'webauthn' });
    await request(app).get('/protected').set('Authorization', `Bearer ${expired}`).expect(401);
  });

  it('rejects a spawned agent identity whose tool scope exceeds its parent scope', async () => {
    const { app } = makeApp();
    const parent = await request(app).post('/api/agents').send({ name: 'parent', spiffeId: 'spiffe://zerovault.local/agent/parent', toolScope: ['vault.read'], createdBy: 'operator', active: true }).expect(201);
    const child = await request(app).post('/api/agents').send({ name: 'child', spiffeId: 'spiffe://zerovault.local/agent/child', parentId: parent.body.agent.id, toolScope: ['vault.read', 'shell.execute'], createdBy: 'operator', active: true }).expect(422);

    expect(child.body.error).toContain('subset');
  });

  it('creates a GitHub OIDC session with the same JWE shape as a WebAuthn session', async () => {
    const { app, sessions } = makeApp();
    const result = await request(app).post('/auth/github/callback').send({ idToken: 'mocked-github-oidc-token' }).expect(200);

    expect(await sessions.verify(result.body.token)).toEqual({ sub: 'github-user', email: 'octo@example.test', roles: ['user'], authMethod: 'github' });
  });
});
