import { SessionService } from '@zerovault/auth-shared';
import { Router } from 'express';
import { Types } from 'mongoose';

import {
  decrypt,
  encrypt,
  generateDataEncryptionKey,
  unwrapDataEncryptionKey,
  wrapDataEncryptionKey,
} from '../crypto/envelopeEncryption';
import { LeaseManager } from '../leases/leaseManager';
import { SecretModel } from '../models/Secret';
import { createSessionAuthMiddleware } from '../middleware/sessionAuth';

export interface SecretControllerDependencies {
  sessions: SessionService;
  leases: LeaseManager;
  kekPublicKeyPem: string;
  kekPrivateKeyPem: string;
  kekKeyId: string;
}

interface StoredSecret {
  _id: Types.ObjectId;
  name: string;
  namespace: string;
  type: string;
  status: string;
  ciphertext: string;
  iv: string;
  authTag: string;
  wrappedDek: string;
  createdAt: Date;
  updatedAt: Date;
}

function isSafeSegment(value: unknown): value is string {
  return typeof value === 'string' && /^[a-zA-Z0-9._-]{1,128}$/.test(value);
}

function metadataFor(secret: StoredSecret) {
  return {
    id: secret._id.toString(),
    name: secret.name,
    namespace: secret.namespace,
    type: secret.type,
    status: secret.status,
    createdAt: secret.createdAt,
    updatedAt: secret.updatedAt,
  };
}

export function createSecretRouter(dependencies: SecretControllerDependencies): Router {
  const router = Router();
  router.use(createSessionAuthMiddleware(dependencies.sessions));

  router.post('/', async (request, response) => {
    const { name, namespace, type, value, metadata } = request.body;
    if (!isSafeSegment(name) || !isSafeSegment(namespace) || !isSafeSegment(type) || typeof value !== 'string') {
      response.status(400).json({ error: 'secret_input_invalid' });
      return;
    }
    if (!Types.ObjectId.isValid(response.locals.session!.sub)) {
      response.status(400).json({ error: 'session_subject_is_not_a_persisted_user' });
      return;
    }
    const dek = generateDataEncryptionKey();
    const encrypted = encrypt(Buffer.from(value, 'utf8'), dek);
    const wrappedDek = wrapDataEncryptionKey(dek, dependencies.kekPublicKeyPem);
    try {
      const secret = await SecretModel.create({
        path: `${namespace}/${name}`,
        name,
        namespace,
        type,
        status: 'active',
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        wrappedDek: wrappedDek.toString('base64'),
        kekKeyId: dependencies.kekKeyId,
        metadata: metadata && typeof metadata === 'object' && !Array.isArray(metadata) ? metadata : {},
        createdBy: response.locals.session!.sub,
      });
      response.status(201).json({ secret: metadataFor(secret) });
    } catch (error) {
      if (error instanceof Error && error.message.includes('duplicate key')) {
        response.status(409).json({ error: 'secret_name_already_exists_in_namespace' });
        return;
      }
      response.status(500).json({ error: 'secret_creation_failed' });
    }
  });

  router.get('/:id', async (request, response) => {
    if (!Types.ObjectId.isValid(request.params.id)) {
      response.status(404).json({ error: 'secret_not_found' });
      return;
    }
    const secret = (await SecretModel.findById(request.params.id).lean()) as unknown as StoredSecret | null;
    response.status(secret ? 200 : 404).json(secret ? { secret: metadataFor(secret) } : { error: 'secret_not_found' });
  });

  router.get('/:id/reveal', async (request, response) => {
    if (!Types.ObjectId.isValid(request.params.id)) {
      response.status(404).json({ error: 'secret_not_found' });
      return;
    }
    const leaseToken = request.header('x-lease-token');
    if (!leaseToken || !(await dependencies.leases.isValidForSecret(leaseToken, request.params.id, response.locals.session!.sub))) {
      response.status(403).json({ error: 'active_lease_required' });
      return;
    }
    const secret = (await SecretModel.findById(request.params.id).lean()) as unknown as StoredSecret | null;
    if (!secret || secret.status !== 'active') {
      response.status(404).json({ error: 'secret_not_found' });
      return;
    }
    try {
      const dek = unwrapDataEncryptionKey(Buffer.from(secret.wrappedDek, 'base64'), dependencies.kekPrivateKeyPem);
      const value = decrypt({ ciphertext: secret.ciphertext, iv: secret.iv, authTag: secret.authTag }, dek).toString('utf8');
      response.json({ value });
    } catch {
      response.status(500).json({ error: 'secret_decryption_failed' });
    }
  });

  router.delete('/:id', async (request, response) => {
    if (!Types.ObjectId.isValid(request.params.id)) {
      response.status(404).json({ error: 'secret_not_found' });
      return;
    }
    const result = await SecretModel.findOneAndUpdate(
      { _id: request.params.id, status: 'active' },
      { $set: { status: 'revoked' } },
      { new: true },
    );
    response.status(result ? 200 : 404).json(result ? { secret: metadataFor(result) } : { error: 'secret_not_found' });
  });

  return router;
}
