/**
 * A utility class for encrypting and decrypting data using AES-GCM.
 * Handles all binary encoding internally and exposes string-based methods.
 */
export class Encryption {
  private key: string;
  private ivLength = 12;

  /**
   * Creates a new Encryption instance with a secret key.
   * @param key - The secret key used for encryption and decryption.
   */
  constructor(key: string) {
    this.key = key;
  }

  /**
   * Encrypts any supported data (string or object) and returns a Base64 string.
   * @param data - The data to encrypt.
   * @returns A Promise that resolves to a Base64-encoded string.
   *
   * @example
   * ```ts
   * const enc = new Encryption('my-secret-key');
   * const encrypted = await enc.encrypt({ message: 'Hello World' });
   * console.log(encrypted); // 'BASE64_ENCRYPTED_STRING'
   * ```
   */
  async encrypt<T>(data: T): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      await this.getCryptoKey(this.key),
      this.toArrayBuffer(data),
    );

    const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), iv.byteLength);

    return this.toBase64(combined);
  }

  /**
   * Decrypts a Base64-encoded string and returns the original data.
   * @param encryptedData - The Base64 string containing encrypted data.
   * @returns A Promise that resolves to the decrypted data.
   *
   * @example
   * ```ts
   * const enc = new Encryption('my-secret-key');
   * const decrypted = await enc.decrypt<{ message: string }>(encryptedBase64String);
   * console.log(decrypted.message); // 'Hello World'
   * ```
   */
  async decrypt<T>(encryptedData: string): Promise<T> {
    const combined = this.fromBase64(encryptedData);
    const iv = combined.slice(0, this.ivLength);
    const ciphertext = combined.slice(this.ivLength);

    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      await this.getCryptoKey(this.key),
      ciphertext,
    );

    return this.fromArrayBuffer(decryptedBuffer);
  }

  /** ================= Private Helpers ================= */

  private async getCryptoKey(secret: string) {
    const hashed = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(secret),
    );
    return await crypto.subtle.importKey(
      'raw',
      hashed,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt'],
    );
  }

  private toArrayBuffer<T>(data: T): ArrayBuffer {
    if (typeof data === 'string') return new TextEncoder().encode(data);
    if (data instanceof ArrayBuffer) return data;
    if (data instanceof Uint8Array) return data;
    if (typeof data === 'object' && data !== null)
      return new TextEncoder().encode(JSON.stringify(data));
    throw new Error('Unsupported data type');
  }

  private fromArrayBuffer<T>(buffer: ArrayBuffer): T {
    const text = new TextDecoder().decode(buffer);
    try {
      return JSON.parse(text) as T;
    } catch {
      return text as unknown as T;
    }
  }

  private toBase64(array: Uint8Array): string {
    let binary = '';
    array.forEach((b) => (binary += String.fromCharCode(b)));
    return btoa(binary);
  }

  private fromBase64(base64: string): Uint8Array {
    const binary = atob(base64);
    const array = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      array[i] = binary.charCodeAt(i);
    }
    return array;
  }
}
