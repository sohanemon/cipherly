import { beforeEach, describe, expect, it } from 'vitest';
import Cipherly from '../src';

describe('Cipherly', () => {
  const secretKey = 'my-secret-key';
  let cipher: Cipherly;

  beforeEach(() => {
    cipher = new Cipherly(secretKey);
  });

  it('should encrypt and decrypt a string correctly', async () => {
    const original = 'Hello World';
    const encrypted = await cipher.encrypt(original);
    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toBe(original);

    const decrypted = await cipher.decrypt<string>(encrypted);
    expect(decrypted).toBe(original);
  });

  it('should encrypt and decrypt an object correctly', async () => {
    const original = { message: 'Hello World', count: 42 };
    const encrypted = await cipher.encrypt(original);
    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toEqual(JSON.stringify(original));

    const decrypted = await cipher.decrypt<typeof original>(encrypted);
    expect(decrypted).toEqual(original);
  });

  it('should throw error on unsupported data type', async () => {
    await expect(cipher.encrypt(undefined)).rejects.toThrow(
      'Unsupported data type',
    );
  });

  it('should work with custom IV length', async () => {
    const customCipher = new Cipherly(secretKey, { ivLength: 16 });
    const data = 'Test Data';
    const encrypted = await customCipher.encrypt(data);
    const decrypted = await customCipher.decrypt<string>(encrypted);
    expect(decrypted).toBe(data);
  });

  it('should produce different ciphertexts for the same input (due to random IV)', async () => {
    const data = 'Hello';
    const encrypted1 = await cipher.encrypt(data);
    const encrypted2 = await cipher.encrypt(data);
    expect(encrypted1).not.toBe(encrypted2);
    const decrypted1 = await cipher.decrypt<string>(encrypted1);
    const decrypted2 = await cipher.decrypt<string>(encrypted2);
    expect(decrypted1).toBe(data);
    expect(decrypted2).toBe(data);
  });

  it('should encrypt and decrypt a large object', async () => {
    const data = { items: Array.from({ length: 1000 }, (_, i) => `item${i}`) };
    const encrypted = await cipher.encrypt(data);
    const decrypted = await cipher.decrypt<typeof data>(encrypted);
    expect(decrypted).toEqual(data);
  });
});
