import mongoose from 'mongoose';
import { createClient } from 'redis';

import { SessionService } from '@zerovault/auth-shared';

import { createVaultApp } from './app';
import { loadVaultEnvironment } from './config/env';
import { LeaseExpiryListener } from './leases/expiryListener';
import { LeaseManager } from './leases/leaseManager';
import { LeaseModel } from './models/Lease';
import { SecretModel } from './models/Secret';

async function start(): Promise<void> {
  const environment = loadVaultEnvironment();
  await mongoose.connect(environment.mongoUri);
  await SecretModel.syncIndexes();
  await LeaseModel.syncIndexes();
  const redis = createClient({ url: environment.valkeyUrl });
  await redis.connect();
  const leaseExpiryListener = new LeaseExpiryListener(redis);
  await leaseExpiryListener.start();
  const sessions = new SessionService(environment.sessionJweKeyBase64, 900);
  const leases = new LeaseManager(environment.sessionJweKeyBase64, redis, environment.maxLeaseTtlSeconds);
  const app = createVaultApp({
    sessions,
    leases,
    kekPublicKeyPem: environment.kekPublicKeyPem,
    kekPrivateKeyPem: environment.kekPrivateKeyPem,
    kekKeyId: environment.kekKeyId,
  });
  const server = app.listen(4100, () => console.log('Vault Engine listening on port 4100'));
  const shutdown = async () => {
    server.close();
    await leaseExpiryListener.stop();
    await redis.quit();
    await mongoose.disconnect();
  };
  process.once('SIGINT', () => { void shutdown(); });
  process.once('SIGTERM', () => { void shutdown(); });
}

start().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
