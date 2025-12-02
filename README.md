# 🧩 Cipherly

![npm version](https://img.shields.io/npm/v/cipherly)
![npm downloads](https://img.shields.io/npm/dm/cipherly)
![License](https://img.shields.io/npm/l/cipherly)
![Tests](https://github.com/sohanemon/sohanemon-utils/actions/workflows/test.yml/badge.svg)

> A lightweight, developer-friendly AES-GCM encryption library built with TypeScript and Web Crypto API — **simple**, **secure**, and **typed**.

---

## ✨ Features

* 🔒 **AES-GCM Encryption** — Uses AES-GCM for authenticated encryption with integrity checks.
* 🧠 **String-Based API** — Encrypts and decrypts strings seamlessly (perfect for JSON, tokens, or secrets).
* 🔁 **Automatic IV Generation** — Secure random IV created for every encryption operation.
* 🪪 **Secure Key Derivation** — Derives 256-bit keys from passphrases using SHA-256.
* 🧩 **Fully Typed** — 100% TypeScript for better DX and autocompletion.
* ⚡ **Zero Dependencies** — Built directly on the Web Crypto API.

---

## 📦 Installation

```bash
npm install cipherly
# or
yarn add cipherly
# or
pnpm add cipherly
```

---

## 🚀 Quick Start

### Encrypting a String

```typescript
import { Cipherly } from 'cipherly';

const cipher = new Cipherly('my-super-secret-key');

const encrypted = await cipher.encrypt('Hello, World!');
console.log(encrypted);
// 👉 eyJpdiI6IjQ1c2xZV2pRbEciLCJkYXRhIjoiU2Y3b3A5... 
```

### Decrypting a String

```typescript
import { Cipherly } from 'cipherly';

const cipher = new Cipherly('my-super-secret-key');

const decrypted = await cipher.decrypt(encrypted);
console.log(decrypted);
// 👉 'Hello, World!'
```

---

## 🧪 Advanced Examples

### 1. Encrypting and Decrypting Object

```typescript
import { Cipherly } from 'cipherly';

const cipher = new Cipherly('api-key-123');

const userData = {
  id: 42,
  name: 'Alice',
  email: 'alice@example.com',
};

const encrypted = await cipher.encrypt(userData);
console.log('Encrypted JSON:', encrypted);

// const decrypted = await cipher.decrypt(encrypted); // if not using typescript

const decrypted = await cipher.decrypt<typeof userData>(encrypted);
console.log('Decrypted object:', decrypted);
```


---

### 2. URL-Safe Encryption

```typescript
import { Cipherly } from 'cipherly';

const cipher = new Cipherly('secure-key');

const data = { token: 'abc123', expires: Date.now() };

const encrypted = await cipher.encryptUrlSafe(data);
console.log('URL-safe encrypted:', encrypted);
// 👉 eyJpdiI6IjQ1c2xZV2pRbEciLCJkYXRhIjoiU2Y3b3A5... (URL-safe)

const decrypted = await cipher.decryptUrlSafe<typeof data>(encrypted);
console.log('Decrypted:', decrypted);
```

---

### 3. Handling Errors Gracefully

```typescript
import { Cipherly } from 'cipherly';

const cipher = new Cipherly('secure-key');

try {
  const decrypted = await cipher.decrypt('invalid-data');
  console.log(decrypted);
} catch (error) {
  console.error('Decryption failed:', error);
}
```

> 🔥 Common causes of errors:
>
> * Wrong decryption key
> * Corrupted ciphertext
> * Truncated or tampered encrypted string

---

## 🧰 API Reference

### `class Cipherly`

#### **Constructor**

```typescript
new Cipherly(secretKey: string, options?: { ivLength?: number})
```

* `secretKey` — Your secret passphrase (used to derive AES-GCM key)
* `options.iv` — Optional custom 12-byte IV

#### **Methods**

##### `encrypt(data: string): Promise<string>`

Encrypts a string.

```typescript
const encrypted = await cipher.encrypt('hello');
```

##### `decrypt(encryptedData: string): Promise<string>`

Decrypts an encrypted string.

```typescript
const decrypted = await cipher.decrypt(encrypted);
```

##### `encryptUrlSafe(data: any): Promise<string>`

Encrypts data and returns a URL-safe Base64 string.

```typescript
const encrypted = await cipher.encryptUrlSafe('hello');
```

##### `decryptUrlSafe(encryptedData: string): Promise<any>`

Decrypts a URL-safe Base64 string.

```typescript
const decrypted = await cipher.decryptUrlSafe(encrypted);
```

---

## 🔐 Security Notes

* Always use a **strong, random key** — at least 16 characters.
* Keep your secret key **out of client-side code** if encrypting sensitive data.

---

## 🧾 License

Licensed under the **ISC License** — see the [LICENSE](LICENSE) file for details.

---

## ❤️ Contributing

Pull requests, issues, and discussions are welcome!
If you encounter a bug or want to suggest an enhancement, feel free to open an issue.

