import {
  constants,
  createCipheriv,
  createDecipheriv,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
} from 'node:crypto';

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  authTag: string;
}

export const DATA_ENCRYPTION_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;

function assertDataEncryptionKey(dataEncryptionKey: Buffer): void {
  if (dataEncryptionKey.length !== DATA_ENCRYPTION_KEY_BYTES) {
    throw new RangeError('AES-256-GCM requires a 32-byte data encryption key');
  }
}

export function generateDataEncryptionKey(): Buffer {
  return randomBytes(DATA_ENCRYPTION_KEY_BYTES);
}

export function encrypt(plaintext: Buffer, dataEncryptionKey: Buffer): EncryptedPayload {
  assertDataEncryptionKey(dataEncryptionKey);
  const iv = randomBytes(GCM_IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', dataEncryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
  };
}

export function decrypt(payload: EncryptedPayload, dataEncryptionKey: Buffer): Buffer {
  assertDataEncryptionKey(dataEncryptionKey);
  const decipher = createDecipheriv('aes-256-gcm', dataEncryptionKey, Buffer.from(payload.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(payload.authTag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, 'base64')),
    decipher.final(),
  ]);
}

export function wrapDataEncryptionKey(dataEncryptionKey: Buffer, rsaPublicKeyPem: string): Buffer {
  assertDataEncryptionKey(dataEncryptionKey);
  return publicEncrypt(
    {
      key: rsaPublicKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    dataEncryptionKey,
  );
}

export function unwrapDataEncryptionKey(wrappedDataEncryptionKey: Buffer, rsaPrivateKeyPem: string): Buffer {
  const dataEncryptionKey = privateDecrypt(
    {
      key: rsaPrivateKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    wrappedDataEncryptionKey,
  );
  assertDataEncryptionKey(dataEncryptionKey);
  return dataEncryptionKey;
}
