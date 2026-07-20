import { generateKeyPairSync, randomBytes } from 'node:crypto';

import {
  decrypt,
  encrypt,
  generateDataEncryptionKey,
  unwrapDataEncryptionKey,
  wrapDataEncryptionKey,
} from '../src/crypto/envelopeEncryption';

const message = Buffer.from('ZeroVault protects this secret.');

describe('envelope encryption', () => {
  it('encrypts, decrypts, wraps, and unwraps a data encryption key', () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const dek = generateDataEncryptionKey();
    const encrypted = encrypt(message, dek);
    const wrappedDek = wrapDataEncryptionKey(dek, publicKey.export({ type: 'pkcs1', format: 'pem' }).toString());
    const unwrappedDek = unwrapDataEncryptionKey(
      wrappedDek,
      privateKey.export({ type: 'pkcs1', format: 'pem' }).toString(),
    );

    expect(decrypt(encrypted, unwrappedDek)).toEqual(message);
  });

  it('rejects tampered ciphertext because its authentication tag no longer matches', () => {
    const dek = generateDataEncryptionKey();
    const encrypted = encrypt(message, dek);
    const tampered = { ...encrypted, ciphertext: Buffer.from('tampered').toString('base64') };

    expect(() => decrypt(tampered, dek)).toThrow();
  });

  it('rejects a wrapped key with the wrong RSA private key', () => {
    const first = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const second = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const wrappedDek = wrapDataEncryptionKey(
      generateDataEncryptionKey(),
      first.publicKey.export({ type: 'pkcs1', format: 'pem' }).toString(),
    );

    expect(() =>
      unwrapDataEncryptionKey(wrappedDek, second.privateKey.export({ type: 'pkcs1', format: 'pem' }).toString()),
    ).toThrow();
  });

  it('uses a fresh IV for every encryption and rejects invalid AES key lengths', () => {
    const dek = generateDataEncryptionKey();
    expect(encrypt(message, dek).iv).not.toEqual(encrypt(message, dek).iv);
    expect(() => encrypt(message, randomBytes(31))).toThrow('32-byte');
  });
});
