import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { resolve } from 'node:path';

import {
  AgentIdentityModel,
  AnomalyScoreModel,
  AuditLogModel,
  LeaseModel,
  RoleModel,
  SecretModel,
  UserModel,
} from '../src/models';

dotenv.config({ path: resolve(__dirname, '../../../.env') });

const mongoUri: string = process.env.MONGO_URI ?? '';
if (!mongoUri) {
  throw new Error('MONGO_URI must be set in .env');
}

const models = [
  UserModel,
  RoleModel,
  SecretModel,
  LeaseModel,
  AuditLogModel,
  AnomalyScoreModel,
  AgentIdentityModel,
];

async function verifyIndexes(): Promise<void> {
  await mongoose.connect(mongoUri);
  for (const registeredModel of models) {
    await registeredModel.init();
    const indexes = await registeredModel.collection.indexes();
    console.log(`${registeredModel.collection.name}: ${JSON.stringify(indexes)}`);
  }
  await mongoose.disconnect();
}

verifyIndexes().catch(async (error: unknown) => {
  console.error(error);
  await mongoose.disconnect();
  process.exitCode = 1;
});
