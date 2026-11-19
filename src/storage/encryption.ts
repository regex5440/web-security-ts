import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export type EncryptedPayload = {
  nonce: Buffer;
  authTag: Buffer;
  ciphertext: Buffer;
};

function validateKey(key: Buffer, length = 32): void {
  if (!Buffer.isBuffer(key) || key.length !== length) {
    throw new Error("Invalid key type");
  }
}

function validatePayload(payload: EncryptedPayload): void {
  validateKey(payload.nonce, 12);
  validateKey(payload.authTag, 16);
  if (!Buffer.isBuffer(payload.ciphertext)) {
    throw new Error("Invalid ciphertext key type");
  }
}

export function encrypt(plaintext: Buffer, key: Buffer): EncryptedPayload {
  validateKey(key);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, {
    authTagLength: 16,
  });
  return {
    ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]),
    authTag: cipher.getAuthTag(),
    nonce,
  };
}

export function decrypt(payload: EncryptedPayload, key: Buffer): Buffer {
  validateKey(key);
  validatePayload(payload);
  const decipher = createDecipheriv("aes-256-gcm", key, payload.nonce);
  decipher.setAuthTag(payload.authTag);
  return Buffer.concat([decipher.update(payload.ciphertext), decipher.final()]);
}
