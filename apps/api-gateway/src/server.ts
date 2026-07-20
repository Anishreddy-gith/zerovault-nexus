import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';

import { createGitHubOidcVerifier, GitHubAuthenticationService, GitHubUserRepository } from './auth/github';
import { createSimpleWebAuthnProvider, AuthUser, StoredCredential, UserRepository } from './auth/webauthn';
import { createProductionGatewayApp, loadGatewayEnvironment } from './app';

dotenv.config({ path: resolve(__dirname, '../../../.env') });

interface StoredUserDocument {
  _id: mongoose.Types.ObjectId;
  email: string;
  displayName: string;
  githubId?: string;
  roles?: unknown[];
  webAuthnCredentials?: StoredCredential[];
}

function serializeUser(document: StoredUserDocument): AuthUser {
  return {
    id: document._id.toString(),
    email: document.email,
    displayName: document.displayName,
    roles: (document.roles ?? []).map(String),
    credentials: document.webAuthnCredentials ?? [],
  };
}

class MongoUserRepository implements UserRepository, GitHubUserRepository {
  private get collection() {
    return mongoose.connection.collection<StoredUserDocument>('users');
  }

  public async findByEmail(email: string): Promise<AuthUser | null> {
    const user = await this.collection.findOne({ email });
    return user ? serializeUser(user) : null;
  }

  public async create(user: AuthUser): Promise<AuthUser> {
    const document = {
      _id: new mongoose.Types.ObjectId(),
      email: user.email,
      displayName: user.displayName,
      roles: user.roles,
      webAuthnCredentials: user.credentials,
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    await this.collection.insertOne(document);
    return serializeUser(document);
  }

  public async updateCredentialCounter(userId: string, credentialId: string, counter: number): Promise<void> {
    await this.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(userId), 'webAuthnCredentials.credentialId': credentialId },
      { $set: { 'webAuthnCredentials.$.counter': counter, updatedAt: new Date() } },
    );
  }

  public async findByGitHubId(githubId: string): Promise<AuthUser | null> {
    const user = await this.collection.findOne({ githubId });
    return user ? serializeUser(user) : null;
  }

  public async createGitHubUser(identity: { subject: string; email: string; displayName: string }): Promise<AuthUser> {
    return this.create({
      id: randomUUID(),
      email: identity.email,
      displayName: identity.displayName,
      roles: ['user'],
      credentials: [],
    }).then(async (user) => {
      await this.collection.updateOne({ _id: new mongoose.Types.ObjectId(user.id) }, { $set: { githubId: identity.subject } });
      return user;
    });
  }
}

async function start(): Promise<void> {
  const environment = loadGatewayEnvironment();
  const mongoUri = process.env.MONGO_URI;
  if (!mongoUri) {
    throw new Error('MONGO_URI must be set');
  }
  await mongoose.connect(mongoUri);
  const users = new MongoUserRepository();
  const github = new GitHubAuthenticationService(
    createGitHubOidcVerifier({ issuer: environment.githubOidcIssuer, audience: environment.githubOidcAudience, jwksUrl: environment.githubOidcJwksUrl }),
    users,
  );
  const app = createProductionGatewayApp(environment, createSimpleWebAuthnProvider({ rpId: environment.webauthnRpId, rpName: environment.webauthnRpName, origin: environment.webauthnOrigin }), users, github);
  app.listen(4000, () => console.log('API Gateway listening on port 4000'));
}

start().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
