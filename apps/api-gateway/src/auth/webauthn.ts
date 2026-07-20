import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { randomUUID } from 'node:crypto';

export interface StoredCredential {
  credentialId: string;
  publicKey: string;
  counter: number;
  transports: string[];
}

export interface AuthUser {
  id: string;
  email: string;
  displayName: string;
  roles: string[];
  credentials: StoredCredential[];
}

export interface UserRepository {
  findByEmail(email: string): Promise<AuthUser | null>;
  create(user: AuthUser): Promise<AuthUser>;
  updateCredentialCounter(userId: string, credentialId: string, counter: number): Promise<void>;
}

export interface WebAuthnProvider {
  registrationOptions(input: { userId: string; email: string; displayName: string }): Promise<{ challenge: string; options: unknown }>;
  verifyRegistration(input: { response: unknown; challenge: string }): Promise<{ verified: boolean; credential?: StoredCredential }>;
  authenticationOptions(input: { credentials: StoredCredential[] }): Promise<{ challenge: string; options: unknown }>;
  verifyAuthentication(input: { response: unknown; challenge: string; credential: StoredCredential }): Promise<{ verified: boolean; newCounter?: number }>;
}

export interface WebAuthnConfiguration {
  rpId: string;
  rpName: string;
  origin: string;
}

export function createSimpleWebAuthnProvider(config: WebAuthnConfiguration): WebAuthnProvider {
  return {
    async registrationOptions(input) {
      const options = await generateRegistrationOptions({
        rpName: config.rpName,
        rpID: config.rpId,
        userName: input.email,
        userDisplayName: input.displayName,
        userID: new TextEncoder().encode(input.userId),
        attestationType: 'none',
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      });
      return { challenge: options.challenge, options };
    },
    async verifyRegistration(input) {
      const result = await verifyRegistrationResponse({
        response: input.response as never,
        expectedChallenge: input.challenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpId,
      });
      const credential = result.registrationInfo?.credential;
      return {
        verified: result.verified,
        credential: credential
          ? {
              credentialId: credential.id,
              publicKey: Buffer.from(credential.publicKey).toString('base64url'),
              counter: credential.counter,
              transports: credential.transports ?? [],
            }
          : undefined,
      };
    },
    async authenticationOptions(input) {
      const options = await generateAuthenticationOptions({
        rpID: config.rpId,
        allowCredentials: input.credentials.map((credential) => ({
          id: credential.credentialId,
          transports: credential.transports as never,
        })),
        userVerification: 'preferred',
      });
      return { challenge: options.challenge, options };
    },
    async verifyAuthentication(input) {
      const result = await verifyAuthenticationResponse({
        response: input.response as never,
        expectedChallenge: input.challenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpId,
        credential: {
          id: input.credential.credentialId,
          publicKey: Buffer.from(input.credential.publicKey, 'base64url'),
          counter: input.credential.counter,
          transports: input.credential.transports as never,
        },
      });
      return { verified: result.verified, newCounter: result.authenticationInfo?.newCounter };
    },
  };
}

interface RegistrationChallenge {
  email: string;
  displayName: string;
  userId: string;
  challenge: string;
}

interface AuthenticationChallenge {
  user: AuthUser;
  challenge: string;
}

export class WebAuthnService {
  private readonly registrations = new Map<string, RegistrationChallenge>();
  private readonly authentications = new Map<string, AuthenticationChallenge>();

  public constructor(
    private readonly users: UserRepository,
    private readonly provider: WebAuthnProvider,
  ) {}

  public async beginRegistration(email: string, displayName: string): Promise<unknown> {
    const normalizedEmail = email.trim().toLowerCase();
    const existing = await this.users.findByEmail(normalizedEmail);
    if (existing) {
      throw new Error('A user with this email already exists');
    }
    const userId = randomUUID();
    const generated = await this.provider.registrationOptions({ userId, email: normalizedEmail, displayName });
    this.registrations.set(normalizedEmail, { email: normalizedEmail, displayName, userId, challenge: generated.challenge });
    return generated.options;
  }

  public async completeRegistration(email: string, response: unknown): Promise<AuthUser> {
    const normalizedEmail = email.trim().toLowerCase();
    const pending = this.registrations.get(normalizedEmail);
    if (!pending) {
      throw new Error('No registration ceremony is pending for this user');
    }
    const verified = await this.provider.verifyRegistration({ response, challenge: pending.challenge });
    this.registrations.delete(normalizedEmail);
    if (!verified.verified || !verified.credential) {
      throw new Error('WebAuthn registration verification failed');
    }
    return this.users.create({
      id: pending.userId,
      email: pending.email,
      displayName: pending.displayName,
      roles: ['user'],
      credentials: [verified.credential],
    });
  }

  public async beginAuthentication(email: string): Promise<unknown> {
    const user = await this.users.findByEmail(email.trim().toLowerCase());
    if (!user || user.credentials.length === 0) {
      throw new Error('No registered WebAuthn credential exists for this user');
    }
    const generated = await this.provider.authenticationOptions({ credentials: user.credentials });
    this.authentications.set(user.email, { user, challenge: generated.challenge });
    return generated.options;
  }

  public async completeAuthentication(email: string, response: { credentialId: string; [key: string]: unknown }): Promise<AuthUser> {
    const normalizedEmail = email.trim().toLowerCase();
    const pending = this.authentications.get(normalizedEmail);
    if (!pending) {
      throw new Error('No authentication ceremony is pending for this user');
    }
    const credential = pending.user.credentials.find((candidate) => candidate.credentialId === response.credentialId);
    if (!credential) {
      throw new Error('The authentication credential is not registered to this user');
    }
    const verified = await this.provider.verifyAuthentication({ response, challenge: pending.challenge, credential });
    this.authentications.delete(normalizedEmail);
    if (!verified.verified) {
      throw new Error('WebAuthn authentication verification failed');
    }
    await this.users.updateCredentialCounter(pending.user.id, credential.credentialId, verified.newCounter ?? credential.counter);
    return pending.user;
  }
}
