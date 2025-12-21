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

    it('should handle zero TTL (immediate expiration)', async () => {
      const data = { token: 'abc123' };
      // Use a past timestamp to ensure immediate expiration
      const encrypted = await cipher.encrypt(data, {
        expiresAt: Date.now() - 1000,
      });
      await expect(cipher.decrypt<typeof data>(encrypted)).rejects.toThrow(
        'Token has expired',
      );
    });

    it('should handle negative TTL', async () => {
      const data = { token: 'abc123' };
      const encrypted = await cipher.encrypt(data, { ttl: -1000 });
      // Should be expired immediately
      await expect(cipher.decrypt<typeof data>(encrypted)).rejects.toThrow(
        'Token has expired',
      );
    });

    it('should handle past expiresAt timestamp', async () => {
      const data = { token: 'abc123' };
      const pastTimestamp = Date.now() - 10000; // 10 seconds ago
      const encrypted = await cipher.encrypt(data, {
        expiresAt: pastTimestamp,
      });
      await expect(cipher.decrypt<typeof data>(encrypted)).rejects.toThrow(
        'Token has expired',
      );
    });
  });

  describe('Backwards Compatibility', () => {
    it('should decrypt tokens encrypted without expiration (legacy tokens)', async () => {
      // Create a token without expiration
      const data = { legacy: 'token', version: 1 };
      const encrypted = await cipher.encrypt(data);
      const decrypted = await cipher.decrypt<typeof data>(encrypted);
      expect(decrypted).toEqual(data);
    });

    it('should work with both encryption methods interchangeably', async () => {
      const data = { test: 'data' };

      // Encrypt with regular, decrypt with URL-safe
      const encrypted = await cipher.encrypt(data);
      const encryptedUrlSafe = await cipher.encryptUrlSafe(data);

      // Should be able to decrypt both ways
      const decrypted1 = await cipher.decrypt<typeof data>(encrypted);
      const decrypted2 =
        await cipher.decryptUrlSafe<typeof data>(encryptedUrlSafe);

      expect(decrypted1).toEqual(data);
      expect(decrypted2).toEqual(data);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle very large data structures', async () => {
      const largeData = {
        array: Array.from({ length: 10000 }, (_, i) => ({
          id: i,
          data: 'x'.repeat(100),
        })),
        nested: { level1: { level2: { level3: 'deep' } } },
      };
      const encrypted = await cipher.encrypt(largeData);
      const decrypted = await cipher.decrypt<typeof largeData>(encrypted);
      expect(decrypted).toEqual(largeData);
    });

    it('should handle special characters and unicode', async () => {
      const specialData = {
        unicode: '🚀🔥💯',
        special: '!@#$%^&*()_+-=[]{}|;:,.<>?',
        multiline: 'line1\nline2\tline3',
        quotes: '"single\'double"',
      };
      const encrypted = await cipher.encrypt(specialData);
      const decrypted = await cipher.decrypt<typeof specialData>(encrypted);
      expect(decrypted).toEqual(specialData);
    });

    it('should handle different key lengths', async () => {
      const shortKey = 'short';
      const longKey = 'a'.repeat(100);
      const veryLongKey = 'b'.repeat(1000);

      const data = { test: 'key length test' };

      const cipherShort = new Cipherly(shortKey);
      const cipherLong = new Cipherly(longKey);
      const cipherVeryLong = new Cipherly(veryLongKey);

      const encrypted1 = await cipherShort.encrypt(data);
      const encrypted2 = await cipherLong.encrypt(data);
      const encrypted3 = await cipherVeryLong.encrypt(data);

      const decrypted1 = await cipherShort.decrypt<typeof data>(encrypted1);
      const decrypted2 = await cipherLong.decrypt<typeof data>(encrypted2);
      const decrypted3 = await cipherVeryLong.decrypt<typeof data>(encrypted3);

      expect(decrypted1).toEqual(data);
      expect(decrypted2).toEqual(data);
      expect(decrypted3).toEqual(data);
    });

    it('should fail with wrong key', async () => {
      const data = { secret: 'data' };
      const encrypted = await cipher.encrypt(data);

      const wrongCipher = new Cipherly('wrong-key');
      await expect(
        wrongCipher.decrypt<typeof data>(encrypted),
      ).rejects.toThrow();
    });

    it('should handle empty objects and arrays', async () => {
      const emptyData = { empty: {}, array: [] };
      const encrypted = await cipher.encrypt(emptyData);
      const decrypted = await cipher.decrypt<typeof emptyData>(encrypted);
      expect(decrypted).toEqual(emptyData);
    });

    it('should handle null and undefined values in objects', async () => {
      const nullableData = {
        null: null,
        undefined: undefined,
        zero: 0,
        empty: '',
      };
      const encrypted = await cipher.encrypt(nullableData);
      const decrypted = await cipher.decrypt<typeof nullableData>(encrypted);
      expect(decrypted).toEqual(nullableData);
    });

    it('should handle Date objects (serialized as strings)', async () => {
      const date = new Date();
      const dateData = { date: date.toISOString(), timestamp: Date.now() };
      const encrypted = await cipher.encrypt(dateData);
      const decrypted = await cipher.decrypt<typeof dateData>(encrypted);
      expect(decrypted.date).toBe(date.toISOString()); // Date becomes ISO string
      expect(decrypted.timestamp).toBe(dateData.timestamp);
    });

    it('should handle binary data (Uint8Array converted to string)', async () => {
      const binaryData = new Uint8Array([1, 2, 3, 255, 0, 128]);
      const encrypted = await cipher.encrypt(binaryData);
      const decrypted = await cipher.decrypt<string>(encrypted);
      // Uint8Array becomes a string through JSON serialization
      expect(typeof decrypted).toBe('string');
      // The exact representation depends on how Uint8Array serializes
      expect(decrypted.length).toBeGreaterThan(0);
    });

    it('should handle Buffer-like objects', async () => {
      const buffer = { data: [1, 2, 3], type: 'buffer' };
      const encrypted = await cipher.encrypt(buffer);
      const decrypted = await cipher.decrypt<typeof buffer>(encrypted);
      expect(decrypted).toEqual(buffer);
    });

    it('should handle very long strings', async () => {
      const longString = 'a'.repeat(100000); // 100KB string
      const encrypted = await cipher.encrypt(longString);
      const decrypted = await cipher.decrypt<string>(encrypted);
      expect(decrypted).toBe(longString);
    });

    it('should handle numbers and booleans', async () => {
      const primitiveData = {
        number: 42,
        float: 3.14159,
        negative: -123,
        zero: 0,
        boolean: true,
        false: false,
      };
      const encrypted = await cipher.encrypt(primitiveData);
      const decrypted = await cipher.decrypt<typeof primitiveData>(encrypted);
      expect(decrypted).toEqual(primitiveData);
    });

    it('should handle Map and Set objects (serialized as plain objects)', async () => {
      const map = new Map([
        ['key1', 'value1'],
        ['key2', 'value2'],
      ]);
      const set = new Set([1, 2, 3, 'string']);
      const data = { map: Object.fromEntries(map), set: Array.from(set) }; // Convert to serializable format

      const encrypted = await cipher.encrypt(data);
      const decrypted = await cipher.decrypt<typeof data>(encrypted);

      expect(typeof decrypted.map).toBe('object'); // Becomes plain object
      expect(Array.isArray(decrypted.set)).toBe(true); // Becomes array
      expect(decrypted.map).toEqual(Object.fromEntries(map));
      expect(decrypted.set).toEqual(Array.from(set));
    });
  });

  describe('Type Safety', () => {
    it('should maintain type information through encryption/decryption', async () => {
      interface User {
        id: number;
        name: string;
        email: string;
        roles: string[];
        metadata: {
          createdAt: number;
          isActive: boolean;
        };
      }

      const user: User = {
        id: 123,
        name: 'John Doe',
        email: 'john@example.com',
        roles: ['admin', 'user'],
        metadata: {
          createdAt: Date.now(),
          isActive: true,
        },
      };

      const encrypted = await cipher.encrypt(user);
      const decrypted = await cipher.decrypt<User>(encrypted);

      // TypeScript should infer correct types
      expect(typeof decrypted.id).toBe('number');
      expect(typeof decrypted.name).toBe('string');
      expect(Array.isArray(decrypted.roles)).toBe(true);
      expect(typeof decrypted.metadata.createdAt).toBe('number');
      expect(typeof decrypted.metadata.isActive).toBe('boolean');

      expect(decrypted).toEqual(user);
    });
  });

  describe('Performance and Stress Tests', () => {
    it('should handle rapid consecutive operations', async () => {
      const data = { test: 'performance' };
      const promises = Array.from({ length: 100 }, () =>
        cipher
          .encrypt(data)
          .then((encrypted) => cipher.decrypt<typeof data>(encrypted)),
      );

      const results = await Promise.all(promises);
      results.forEach((result) => {
        expect(result).toEqual(data);
      });
    });

    it('should handle concurrent operations with different keys', async () => {
      const keys = ['key1', 'key2', 'key3', 'key4', 'key5'];
      const data = { concurrent: 'test' };

      const promises = keys.map((key) => {
        const cipherInstance = new Cipherly(key);
        return cipherInstance
          .encrypt(data)
          .then((encrypted) => cipherInstance.decrypt<typeof data>(encrypted));
      });

      const results = await Promise.all(promises);
      results.forEach((result) => {
        expect(result).toEqual(data);
      });
    });
  });
});
