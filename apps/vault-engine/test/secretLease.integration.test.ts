import { randomUUID } from 'node:crypto';

import { SessionService } from '@zerovault/auth-shared';
import mongoose, { Types } from 'mongoose';
import { createClient } from 'redis';
import request from 'supertest';

import { createVaultApp } from '../src/app';
import { loadVaultEnvironment } from '../src/config/env';
import { LeaseExpiryListener } from '../src/leases/expiryListener';
import { LeaseManager } from '../src/leases/leaseManager';
import { LeaseModel } from '../src/models/Lease';
import { SecretModel } from '../src/models/Secret';

const environment = loadVaultEnvironment();
const subject = new Types.ObjectId().toString();
const foreignSubject = new Types.ObjectId().toString();
const sessionService = new SessionService(environment.sessionJweKeyBase64, 900);
const sessionTokenPromise = sessionService.issue({ sub: subject, email: 'phase3@example.test', roles: ['user'], authMethod: 'webauthn' });
const foreignSessionTokenPromise = sessionService.issue({ sub: foreignSubject, email: 'foreign@example.test', roles: ['user'], authMethod: 'webauthn' });

let redis: ReturnType<typeof createClient>;
let listener: LeaseExpiryListener;
let app: ReturnType<typeof createVaultApp>;

async function createSecret(): Promise<{ id: string; value: string }> {
  const value = `phase-three-${randomUUID()}`;
  const sessionToken = await sessionTokenPromise;
  const response = await request(app)
    .post('/secrets')
    .set('Authorization', `Bearer ${sessionToken}`)
    .send({ name: `secret-${randomUUID().slice(0, 8)}`, namespace: 'phase3test', type: 'credential', value })
    .expect(201);
  return { id: response.body.secret.id, value };
}

async function issueLease(secretId: string, options: { ttlSeconds?: number; taskId?: string; foreign?: boolean } = {}) {
  const token = options.foreign ? await foreignSessionTokenPromise : await sessionTokenPromise;
  return request(app)
    .post('/leases')
    .set('Authorization', `Bearer ${token}`)
    .send({ secretId, ttlSeconds: options.ttlSeconds ?? 30, permissions: ['read'], taskId: options.taskId })
    .expect(201);
}

beforeAll(async () => {
  await mongoose.connect(environment.mongoUri);
  await SecretModel.syncIndexes();
  await LeaseModel.syncIndexes();
  redis = createClient({ url: environment.valkeyUrl });
  await redis.connect();
  listener = new LeaseExpiryListener(redis);
  await listener.start();
  app = createVaultApp({
    sessions: sessionService,
    leases: new LeaseManager(environment.sessionJweKeyBase64, redis, environment.maxLeaseTtlSeconds),
    kekPublicKeyPem: environment.kekPublicKeyPem,
    kekPrivateKeyPem: environment.kekPrivateKeyPem,
    kekKeyId: environment.kekKeyId,
  });
});

afterEach(async () => {
  const leases = await LeaseModel.find({ subject: { $in: [subject, foreignSubject] } }).lean();
  await Promise.all(leases.map((lease) => redis.del(`lease:${lease.leaseId}`)));
  await LeaseModel.deleteMany({ subject: { $in: [subject, foreignSubject] } });
  await SecretModel.deleteMany({ namespace: 'phase3test' });
});

afterAll(async () => {
  await listener.stop();
  await redis.quit();
  await mongoose.disconnect();
});

describe('secret engine and lease manager integration', () => {
  it('stores only ciphertext and returns a metadata shape with no encryption material', async () => {
    const { id, value } = await createSecret();
    const stored = (await SecretModel.findById(id).lean()) as unknown as { ciphertext: string; wrappedDek: string } | null;
    expect(stored?.ciphertext).not.toEqual(value);
    expect(Buffer.from(stored!.ciphertext, 'base64').toString('utf8')).not.toEqual(value);
    expect(stored?.wrappedDek).toBeDefined();

    const sessionToken = await sessionTokenPromise;
    const metadata = await request(app).get(`/secrets/${id}`).set('Authorization', `Bearer ${sessionToken}`).expect(200);
    expect(Object.keys(metadata.body.secret).sort()).toEqual(['createdAt', 'id', 'name', 'namespace', 'status', 'type', 'updatedAt']);
    for (const forbidden of ['encryptedValue', 'ciphertext', 'iv', 'tag', 'authTag', 'dek', 'wrappedDek']) {
      expect(metadata.body.secret).not.toHaveProperty(forbidden);
    }
  });

  it('refuses reveal without a lease and with a lease belonging to another subject', async () => {
    const { id } = await createSecret();
    const sessionToken = await sessionTokenPromise;
    await request(app).get(`/secrets/${id}/reveal`).set('Authorization', `Bearer ${sessionToken}`).expect(403);

    const foreignLease = await issueLease(id, { foreign: true });
    await request(app)
      .get(`/secrets/${id}/reveal`)
      .set('Authorization', `Bearer ${sessionToken}`)
      .set('x-lease-token', foreignLease.body.token)
      .expect(403);
  });

  it('revokes a lease immediately and prevents further reveal without polling', async () => {
    const { id, value } = await createSecret();
    const lease = await issueLease(id);
    const sessionToken = await sessionTokenPromise;
    await request(app).get(`/secrets/${id}/reveal`).set('Authorization', `Bearer ${sessionToken}`).set('x-lease-token', lease.body.token).expect(200, { value });
    await request(app).delete(`/leases/${lease.body.lease.jti}`).set('Authorization', `Bearer ${sessionToken}`).expect(204);
    await request(app).get(`/secrets/${id}/reveal`).set('Authorization', `Bearer ${sessionToken}`).set('x-lease-token', lease.body.token).expect(403);
  });

  it('marks a naturally expired lease as expired through the Valkey keyspace listener', async () => {
    const { id } = await createSecret();
    const lease = await issueLease(id, { ttlSeconds: 2 });
    await new Promise((resolve) => setTimeout(resolve, 3500));
    const stored = await LeaseModel.findOne({ leaseId: lease.body.lease.jti }).lean() as unknown as { status: string } | null;
    expect(stored?.status).toBe('expired');
    const sessionToken = await sessionTokenPromise;
    await request(app).get(`/secrets/${id}/reveal`).set('Authorization', `Bearer ${sessionToken}`).set('x-lease-token', lease.body.token).expect(403);
  }, 10000);

  it('completes an agent lease before TTL expiry and persists completed status', async () => {
    const { id } = await createSecret();
    const lease = await issueLease(id, { ttlSeconds: 300, taskId: 'task-phase3' });
    const sessionToken = await sessionTokenPromise;
    await request(app).post(`/leases/${lease.body.lease.jti}/complete`).set('Authorization', `Bearer ${sessionToken}`).expect(200, { status: 'completed' });
    const stored = await LeaseModel.findOne({ leaseId: lease.body.lease.jti }).lean() as unknown as { status: string } | null;
    expect(stored?.status).toBe('completed');
    await request(app).get(`/secrets/${id}/reveal`).set('Authorization', `Bearer ${sessionToken}`).set('x-lease-token', lease.body.token).expect(403);
  });

  it('rejects task completion for a non-task lease', async () => {
    const { id } = await createSecret();
    const lease = await issueLease(id);
    const sessionToken = await sessionTokenPromise;
    await request(app).post(`/leases/${lease.body.lease.jti}/complete`).set('Authorization', `Bearer ${sessionToken}`).expect(400);
  });
});
