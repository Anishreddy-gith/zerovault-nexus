import dotenv from 'dotenv';
import { resolve } from 'node:path';

dotenv.config({ path: resolve(__dirname, '../../../../.env') });

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} must be set`);
  }
  return value;
}

export interface VaultEnvironment {
  mongoUri: string;
  valkeyUrl: string;
  sessionJweKeyBase64: string;
  kekPublicKeyPem: string;
  kekPrivateKeyPem: string;
  kekKeyId: string;
  maxLeaseTtlSeconds: number;
}

export function loadVaultEnvironment(): VaultEnvironment {
  const maxLeaseTtlSeconds = Number(process.env.VAULT_MAX_LEASE_TTL_SECONDS ?? 3600);
  if (!Number.isInteger(maxLeaseTtlSeconds) || maxLeaseTtlSeconds < 1) {
    throw new Error('VAULT_MAX_LEASE_TTL_SECONDS must be a positive integer');
  }
  return {
    mongoUri: required('MONGO_URI'),
    valkeyUrl: required('VALKEY_URL'),
    sessionJweKeyBase64: required('SESSION_JWE_KEY_BASE64'),
    kekPublicKeyPem: Buffer.from(required('VAULT_KEK_PUBLIC_KEY_BASE64'), 'base64').toString('utf8'),
    kekPrivateKeyPem: Buffer.from(required('VAULT_KEK_PRIVATE_KEY_BASE64'), 'base64').toString('utf8'),
    kekKeyId: required('VAULT_KEK_KEY_ID'),
    maxLeaseTtlSeconds,
  };
}
