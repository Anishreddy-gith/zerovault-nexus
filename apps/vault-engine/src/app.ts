import { SessionService } from '@zerovault/auth-shared';
import express from 'express';
import { Types } from 'mongoose';

import { TaskCompletionHook } from './leases/taskCompletionHook';
import { LeaseManager } from './leases/leaseManager';
import { SecretModel } from './models/Secret';
import { createSessionAuthMiddleware } from './middleware/sessionAuth';
import { createSecretRouter } from './secrets/secretController';

export interface VaultAppDependencies {
  sessions: SessionService;
  leases: LeaseManager;
  kekPublicKeyPem: string;
  kekPrivateKeyPem: string;
  kekKeyId: string;
}

export function createVaultApp(dependencies: VaultAppDependencies) {
  const app = express();
  app.use(express.json({ limit: '64kb' }));
  app.use('/secrets', createSecretRouter(dependencies));

  const leases = express.Router();
  leases.use(createSessionAuthMiddleware(dependencies.sessions));
  leases.post('/', async (request, response) => {
    const { secretId, ttlSeconds, permissions, taskId } = request.body;
    if (!Types.ObjectId.isValid(secretId) || !Array.isArray(permissions) || !permissions.every((permission) => typeof permission === 'string') || (taskId !== undefined && typeof taskId !== 'string')) {
      response.status(400).json({ error: 'secretId_ttlSeconds_permissions_and_optional_taskId_are_invalid' });
      return;
    }
    const secret = await SecretModel.findOne({ _id: secretId, status: 'active' }).lean();
    if (!secret) {
      response.status(404).json({ error: 'secret_not_found' });
      return;
    }
    try {
      const issued = await dependencies.leases.issue({
        secretId,
        ttlSeconds,
        permissions,
        taskId,
        issuedTo: response.locals.session!.sub,
      });
      response.status(201).json({ token: issued.token, lease: issued.claims });
    } catch (error) {
      response.status(400).json({ error: error instanceof Error ? error.message : 'lease_issue_failed' });
    }
  });
  leases.delete('/:jti', async (request, response) => {
    response.status((await dependencies.leases.revoke(request.params.jti, response.locals.session!.sub)) ? 204 : 404).send();
  });
  leases.post('/:jti/complete', async (request, response) => {
    const completion = await new TaskCompletionHook(dependencies.leases).complete(request.params.jti, response.locals.session!.sub);
    if (completion === 'completed') {
      response.status(200).json({ status: 'completed' });
      return;
    }
    response.status(completion === 'not_task_lease' ? 400 : 404).json({ error: completion });
  });
  app.use('/leases', leases);

  return app;
}
