import { randomUUID } from 'node:crypto';

import { EncryptJWT, jwtDecrypt } from 'jose';
import { LeaseModel } from '../models/Lease';

export interface LeaseRedis {
  set(key: string, value: string, options: { EX: number }): Promise<unknown>;
  exists(key: string): Promise<number>;
  del(key: string): Promise<number>;
}

export interface LeaseClaims {
  jti: string;
  secretId: string;
  permissions: string[];
  issuedTo: string;
  expiresAt: number;
  taskId?: string;
}

export interface LeaseIssueRequest {
  secretId: string;
  ttlSeconds: number;
  permissions: string[];
  taskId?: string;
  issuedTo: string;
}

export class LeaseManager {
  private readonly encryptionKey: Uint8Array;

  public constructor(
    keyBase64: string,
    private readonly redis: LeaseRedis,
    private readonly maxTtlSeconds: number,
  ) {
    this.encryptionKey = Buffer.from(keyBase64, 'base64');
    if (this.encryptionKey.length !== 32) {
      throw new Error('SESSION_JWE_KEY_BASE64 must decode to 32 bytes');
    }
  }

  public async issue(request: LeaseIssueRequest): Promise<{ token: string; claims: LeaseClaims }> {
    if (!Number.isInteger(request.ttlSeconds) || request.ttlSeconds < 1 || request.ttlSeconds > this.maxTtlSeconds) {
      throw new Error(`ttlSeconds must be an integer between 1 and ${this.maxTtlSeconds}`);
    }
    if (!request.permissions.includes('read')) {
      throw new Error('A lease must include the read permission');
    }
    const jti = randomUUID();
    const expiresAt = Math.floor(Date.now() / 1000) + request.ttlSeconds;
    const claims: LeaseClaims = {
      jti,
      secretId: request.secretId,
      permissions: [...new Set(request.permissions)],
      issuedTo: request.issuedTo,
      expiresAt,
      taskId: request.taskId,
    };
    const token = await new EncryptJWT({
      secretId: claims.secretId,
      permissions: claims.permissions,
      issuedTo: claims.issuedTo,
      taskId: claims.taskId,
    })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', typ: 'ZV-LEASE' })
      .setJti(claims.jti)
      .setIssuedAt()
      .setExpirationTime(claims.expiresAt)
      .encrypt(this.encryptionKey);

    await LeaseModel.create({
      leaseId: claims.jti,
      secret: claims.secretId,
      subject: claims.issuedTo,
      operation: 'read',
      permissions: claims.permissions,
      taskId: claims.taskId,
      status: 'active',
      expiresAt: new Date(claims.expiresAt * 1000),
    });
    try {
      await this.redis.set(`lease:${claims.jti}`, 'active', { EX: request.ttlSeconds });
    } catch (error) {
      await LeaseModel.deleteOne({ leaseId: claims.jti });
      throw error;
    }
    return { token, claims };
  }

  public async isValidForSecret(token: string, secretId: string, subject: string): Promise<boolean> {
    try {
      const claims = await this.verifyToken(token);
      if (claims.secretId !== secretId || claims.issuedTo !== subject || !claims.permissions.includes('read')) {
        return false;
      }
      const keyExists = await this.redis.exists(`lease:${claims.jti}`);
      if (keyExists !== 1) {
        return false;
      }
      const lease = await LeaseModel.findOne({
        leaseId: claims.jti,
        secret: secretId,
        subject,
        status: 'active',
        expiresAt: { $gt: new Date() },
      }).lean();
      return Boolean(lease);
    } catch {
      return false;
    }
  }

  public async revoke(jti: string, subject: string): Promise<boolean> {
    const lease = (await LeaseModel.findOne({ leaseId: jti, subject, status: 'active' }).lean()) as unknown as { taskId?: string } | null;
    if (!lease) {
      return false;
    }
    await this.redis.del(`lease:${jti}`);
    await LeaseModel.updateOne({ leaseId: jti, subject, status: 'active' }, { $set: { status: 'revoked', revokedAt: new Date() } });
    return true;
  }

  public async complete(jti: string, subject: string): Promise<'completed' | 'not_found' | 'not_task_lease'> {
    const lease = (await LeaseModel.findOne({ leaseId: jti, subject, status: 'active' }).lean()) as unknown as { taskId?: string } | null;
    if (!lease) {
      return 'not_found';
    }
    if (!lease.taskId) {
      return 'not_task_lease';
    }
    await this.redis.del(`lease:${jti}`);
    await LeaseModel.updateOne({ leaseId: jti, subject, status: 'active' }, { $set: { status: 'completed', revokedAt: new Date() } });
    return 'completed';
  }

  public async verifyToken(token: string): Promise<LeaseClaims> {
    const { payload } = await jwtDecrypt(token, this.encryptionKey, {
      contentEncryptionAlgorithms: ['A256GCM'],
      keyManagementAlgorithms: ['dir'],
    });
    if (
      typeof payload.jti !== 'string' ||
      typeof payload.secretId !== 'string' ||
      typeof payload.issuedTo !== 'string' ||
      !Array.isArray(payload.permissions) ||
      !payload.permissions.every((permission) => typeof permission === 'string') ||
      typeof payload.exp !== 'number'
    ) {
      throw new Error('Lease claims are invalid');
    }
    return {
      jti: payload.jti,
      secretId: payload.secretId,
      permissions: payload.permissions,
      issuedTo: payload.issuedTo,
      expiresAt: payload.exp,
      taskId: typeof payload.taskId === 'string' ? payload.taskId : undefined,
    };
  }
}
