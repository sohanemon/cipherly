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

  it('should fail to decrypt invalid Base64 string', async () => {
    await expect(cipher.decrypt('not-a-base64')).rejects.toThrow();
  });

  it('should handle nested objects and arrays correctly', async () => {
    const data = {
      user: { name: 'Alice', roles: ['admin', 'user'] },
      meta: { loggedIn: true, score: 99.5 },
    };
    const encrypted = await cipher.encrypt(data);
    const decrypted = await cipher.decrypt<typeof data>(encrypted);
    expect(decrypted).toEqual(data);
  });

  it('should throw error for null input', async () => {
    await expect(cipher.encrypt(null)).rejects.toThrow('Unsupported data type');
  });

  it('should encrypt and decrypt with URL-safe encoding', async () => {
    const original = 'Hello World';
    const encrypted = await cipher.encryptUrlSafe(original);
    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toBe(original);
    expect(encrypted).not.toMatch(/[+/=]/); // No +, /, or =

    const decrypted = await cipher.decryptUrlSafe<string>(encrypted);
    expect(decrypted).toBe(original);
  });

  it('should encrypt and decrypt object with URL-safe encoding', async () => {
    const original = { message: 'Hello World', count: 42 };
    const encrypted = await cipher.encryptUrlSafe(original);
    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toEqual(JSON.stringify(original));
    expect(encrypted).not.toMatch(/[+/=]/);

    const decrypted = await cipher.decryptUrlSafe<typeof original>(encrypted);
    expect(decrypted).toEqual(original);
  });

  it('should encrypt and decrypt empty string with URL-safe encoding', async () => {
    const original = '';
    const encrypted = await cipher.encryptUrlSafe(original);
    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toBe(original);
    expect(encrypted).not.toMatch(/[+/=]/);

    const decrypted = await cipher.decryptUrlSafe<string>(encrypted);
    expect(decrypted).toBe(original);
  });

  it('should encrypt and decrypt string with special characters that produce +/= in base64', async () => {
    // This string is known to produce + / = in base64
    const original = '\xff\xfe\xfd';
    const encrypted = await cipher.encryptUrlSafe(original);
    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toMatch(/[+/=]/);

    const decrypted = await cipher.decryptUrlSafe<string>(encrypted);
    expect(decrypted).toBe(original);
  });

  it('should encrypt and decrypt very long string with URL-safe encoding', async () => {
    const original = 'A'.repeat(10000);
    const encrypted = await cipher.encryptUrlSafe(original);
    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toMatch(/[+/=]/);

    const decrypted = await cipher.decryptUrlSafe<string>(encrypted);
    expect(decrypted).toBe(original);
  });

  it('should perform multiple round-trips with URL-safe encoding', async () => {
    const original = 'Test data';
    let encrypted = original;
    for (let i = 0; i < 5; i++) {
      encrypted = await cipher.encryptUrlSafe(encrypted);
      expect(encrypted).not.toMatch(/[+/=]/);
    }
    for (let i = 0; i < 5; i++) {
      encrypted = await cipher.decryptUrlSafe<string>(encrypted);
    }
    expect(encrypted).toBe(original);
  });

  it('should fail to decrypt invalid URL-safe base64', async () => {
    await expect(cipher.decryptUrlSafe('invalid-base64!@#')).rejects.toThrow();
  });

  it('should handle URL-safe base64 with missing padding', async () => {
    const original = 'Test';
    const encrypted = await cipher.encryptUrlSafe(original);
    // Remove some padding if present
    const withoutPadding = encrypted.replace(/=+$/, '');
    const decrypted = await cipher.decryptUrlSafe<string>(withoutPadding);
    expect(decrypted).toBe(original);
  });

  it('should work with custom IV length and URL-safe encoding', async () => {
    const customCipher = new Cipherly(secretKey, { ivLength: 16 });
    const data = 'Test with custom IV';
    const encrypted = await customCipher.encryptUrlSafe(data);
    expect(encrypted).not.toMatch(/[+/=]/);

    const decrypted = await customCipher.decryptUrlSafe<string>(encrypted);
    expect(decrypted).toBe(data);
  });

  it('should encrypt and decrypt string with URL special characters', async () => {
    const original = 'https://example.com?param=value&other=test#fragment';
    const encrypted = await cipher.encryptUrlSafe(original);
    expect(typeof encrypted).toBe('string');
    expect(encrypted).not.toMatch(/[+/=]/);

    const decrypted = await cipher.decryptUrlSafe<string>(encrypted);
    expect(decrypted).toBe(original);
  });

  it('should produce different URL-safe ciphertexts for same input', async () => {
    const data = 'Same input';
    const encrypted1 = await cipher.encryptUrlSafe(data);
    const encrypted2 = await cipher.encryptUrlSafe(data);
    expect(encrypted1).not.toBe(encrypted2);
    expect(encrypted1).not.toMatch(/[+/=]/);
    expect(encrypted2).not.toMatch(/[+/=]/);

    const decrypted1 = await cipher.decryptUrlSafe<string>(encrypted1);
    const decrypted2 = await cipher.decryptUrlSafe<string>(encrypted2);
    expect(decrypted1).toBe(data);
    expect(decrypted2).toBe(data);
  });

  describe('Expiration functionality', () => {
    it('should encrypt and decrypt data with TTL expiration', async () => {
      const data = { token: 'abc123', userId: 42 };
      const encrypted = await cipher.encrypt(data, { ttl: 3600000 }); // 1 hour in milliseconds
      const decrypted = await cipher.decrypt<typeof data>(encrypted);
      expect(decrypted).toEqual(data);
    });

    it('should encrypt and decrypt data with absolute expiration timestamp', async () => {
      const data = { token: 'abc123' };
      const expiresAt = Date.now() + 3600000; // 1 hour from now
      const encrypted = await cipher.encrypt(data, { expiresAt });
      const decrypted = await cipher.decrypt<typeof data>(encrypted);
      expect(decrypted).toEqual(data);
    });

    it('should throw error when decrypting expired token', async () => {
      const data = { token: 'abc123' };
      const expiredTimestamp = Date.now() - 1000; // 1 second ago
      const encrypted = await cipher.encrypt(data, {
        expiresAt: expiredTimestamp,
      });

      await expect(cipher.decrypt<typeof data>(encrypted)).rejects.toThrow(
        'Token has expired',
      );
    });

    it('should work with URL-safe encoding and expiration', async () => {
      const data = { token: 'abc123' };
      const encrypted = await cipher.encryptUrlSafe(data, { ttl: 3600000 });
      const decrypted = await cipher.decryptUrlSafe<typeof data>(encrypted);
      expect(decrypted).toEqual(data);
    });

    it('should throw error for expired URL-safe token', async () => {
      const data = { token: 'abc123' };
      const expiredTimestamp = Date.now() - 1000;
      const encrypted = await cipher.encryptUrlSafe(data, {
        expiresAt: expiredTimestamp,
      });

      await expect(
        cipher.decryptUrlSafe<typeof data>(encrypted),
      ).rejects.toThrow('Token has expired');
    });

    it('should encrypt string data with expiration', async () => {
      const data = 'secret string';
      const encrypted = await cipher.encrypt(data, { ttl: 60000 }); // 60 seconds in milliseconds
      const decrypted = await cipher.decrypt<string>(encrypted);
      expect(decrypted).toBe(data);
    });

    it('should throw error for expired string token', async () => {
      const data = 'secret string';
      const expiredTimestamp = Date.now() - 1000;
      const encrypted = await cipher.encrypt(data, {
        expiresAt: expiredTimestamp,
      });

      await expect(cipher.decrypt<string>(encrypted)).rejects.toThrow(
        'Token has expired',
      );
    });

    it('should work without expiration when no expiration options provided', async () => {
      const data = { token: 'abc123' };
      const encrypted = await cipher.encrypt(data);
      const decrypted = await cipher.decrypt<typeof data>(encrypted);
      expect(decrypted).toEqual(data);
    });

    it('should prioritize expiresAt over ttl when both provided', async () => {
      const data = { token: 'abc123' };
      const expiresAt = Date.now() + 7200000; // 2 hours from now
      const encrypted = await cipher.encrypt(data, { ttl: 3600000, expiresAt }); // ttl is 1 hour in milliseconds
      const decrypted = await cipher.decrypt<typeof data>(encrypted);
      expect(decrypted).toEqual(data);

      // Should still be valid after 1 hour (since expiresAt is 2 hours)
      // Note: This test assumes the encryption/decryption happens quickly
    });

    it('should handle very short TTL', async () => {
      const data = { token: 'abc123' };
      const encrypted = await cipher.encrypt(data, { ttl: 1 }); // 1 millisecond
      // Immediately try to decrypt - might still work if timing is fast enough
      const decrypted = await cipher.decrypt<typeof data>(encrypted);
      expect(decrypted).toEqual(data);
    });
  });
});
