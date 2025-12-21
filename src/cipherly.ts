/**
 * A utility class for encrypting and decrypting data using AES-GCM.
 * Handles all binary encoding internally and exposes string-based methods.
 */

type Opts = {
  ivLength: number;
};

type ExpirationOpts = {
  ttl?: number; // Time to live in seconds from now
  expiresAt?: number; // Absolute expiration timestamp (milliseconds since epoch)
};

export class Cipherly {
  private key: string;
  private opts: Opts;

  /**
   * Creates a new Encryption instance with a secret key.
   * @param key - The secret key used for encryption and decryption.
   */
  constructor(key: string, opts?: Opts) {
    this.key = key;
    this.opts = { ivLength: 12, ...(opts ?? {}) };
  }

  private prepareDataForEncryption<T>(
    data: T,
    expirationOpts?: ExpirationOpts,
  ): T | { data: T; __cipherly_expires: number } {
    if (!expirationOpts) {
      return data;
    }

    const expiresAt =
      expirationOpts.expiresAt ??
      (expirationOpts.ttl ? Date.now() + expirationOpts.ttl : undefined);

    if (!expiresAt) {
      return data;
    }

    return {
      data,
      __cipherly_expires: expiresAt,
    };
  }

  private processDecryptedData<T>(decryptedData: unknown): T {
    // Check if this is wrapped data with expiration
    if (
      typeof decryptedData === 'object' &&
      decryptedData !== null &&
      '__cipherly_expires' in decryptedData
    ) {
      const wrapped = decryptedData as { data: T; __cipherly_expires: number };
      if (Date.now() > wrapped.__cipherly_expires) {
        throw new Error('Token has expired');
      }
      return wrapped.data;
    }

    return decryptedData as T;
  }

  /**
   * Encrypts any supported data (string or object) and returns a Base64 string.
   * @param data - The data to encrypt.
   * @param expirationOpts - Optional expiration settings for the token.
   * @returns A Promise that resolves to a Base64-encoded string.
   *
   * @example
   * ```ts
   * const enc = new Encryption('my-secret-key');
   * const encrypted = await enc.encrypt({ message: 'Hello World' });
   * console.log(encrypted); // 'BASE64_ENCRYPTED_STRING'
   * ```
   *
   * @example
   * ```ts
   * // Encrypt with 1 hour TTL
   * const encrypted = await enc.encrypt({ token: 'abc123' }, { ttl: 3600 });
   *
   * // Encrypt with absolute expiration
   * const encrypted = await enc.encrypt({ token: 'abc123' }, { expiresAt: Date.now() + 3600000 });
   * ```
   */
  async encrypt<T>(data: T, expirationOpts?: ExpirationOpts): Promise<string> {
    const dataToEncrypt = this.prepareDataForEncryption(data, expirationOpts);

    const iv = crypto.getRandomValues(new Uint8Array(this.opts?.ivLength));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      await this.getCryptoKey(this.key),
      this.toArrayBuffer(dataToEncrypt),
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
    const iv = combined.slice(0, this.opts.ivLength);
    const ciphertext = combined.slice(this.opts.ivLength);

    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      await this.getCryptoKey(this.key),
      ciphertext,
    );

    const decryptedData = this.fromArrayBuffer(decryptedBuffer);
    return this.processDecryptedData<T>(decryptedData);
  }

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
    // @ts-expect-error ;
    if (typeof data === 'string') return new TextEncoder().encode(data);
    if (data instanceof ArrayBuffer) return data;
    // @ts-expect-error ;
    if (data instanceof Uint8Array) return data;
    if (typeof data === 'object' && data !== null)
      // @ts-expect-error ;
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
    array.forEach((b) => {
      binary += String.fromCharCode(b);
    });
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

  private toBase64Url(base64: string): string {
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  private fromBase64Url(base64Url: string): string {
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    return base64;
  }

  /**
   * Encrypts data and returns a URL-safe Base64 string.
   * @param data - The data to encrypt.
   * @param expirationOpts - Optional expiration settings for the token.
   * @returns A Promise that resolves to a URL-safe Base64-encoded string.
   */
  async encryptUrlSafe<T>(
    data: T,
    expirationOpts?: ExpirationOpts,
  ): Promise<string> {
    const encrypted = await this.encrypt(data, expirationOpts);
    return this.toBase64Url(encrypted);
  }

  /**
   * Decrypts a URL-safe Base64-encoded string and returns the original data.
   * @param encryptedData - The URL-safe Base64 string containing encrypted data.
   * @returns A Promise that resolves to the decrypted data.
   */
  async decryptUrlSafe<T>(encryptedData: string): Promise<T> {
    const base64 = this.fromBase64Url(encryptedData);
    return this.decrypt<T>(base64);
  }
}

export default Cipherly;
