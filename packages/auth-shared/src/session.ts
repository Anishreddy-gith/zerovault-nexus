import { EncryptJWT, jwtDecrypt } from 'jose';

export type AuthenticationMethod = 'webauthn' | 'github';

export interface SessionClaims {
  sub: string;
  email: string;
  roles: string[];
  authMethod: AuthenticationMethod;
}

export class SessionService {
  private readonly encryptionKey: Uint8Array;

  public constructor(
    keyBase64: string,
    private readonly ttlSeconds: number,
  ) {
    this.encryptionKey = Buffer.from(keyBase64, 'base64');
    if (this.encryptionKey.length !== 32) {
      throw new Error('SESSION_JWE_KEY_BASE64 must decode to 32 bytes');
    }
  }

  public async issue(claims: SessionClaims): Promise<string> {
    return new EncryptJWT({ email: claims.email, roles: claims.roles, authMethod: claims.authMethod })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', typ: 'JWT' })
      .setSubject(claims.sub)
      .setIssuedAt()
      .setExpirationTime(`${this.ttlSeconds}s`)
      .encrypt(this.encryptionKey);
  }

  public async verify(token: string): Promise<SessionClaims> {
    const { payload } = await jwtDecrypt(token, this.encryptionKey, {
      contentEncryptionAlgorithms: ['A256GCM'],
      keyManagementAlgorithms: ['dir'],
    });
    if (
      typeof payload.sub !== 'string' ||
      typeof payload.email !== 'string' ||
      !Array.isArray(payload.roles) ||
      !payload.roles.every((role) => typeof role === 'string') ||
      (payload.authMethod !== 'webauthn' && payload.authMethod !== 'github')
    ) {
      throw new Error('Session claims are invalid');
    }
    return {
      sub: payload.sub,
      email: payload.email,
      roles: payload.roles,
      authMethod: payload.authMethod,
    };
  }
}
