# cipherly

![npm version](https://img.shields.io/npm/v/cipherly)
![npm downloads](https://img.shields.io/npm/dm/cipherly)
![License](https://img.shields.io/npm/l/cipherly)

## Description

`cipherly` is a lightweight, developer-friendly AES-GCM encryption library for securely encrypting and decrypting strings. Built with TypeScript and Web Crypto API, it ensures high performance and security.

## Features

- **AES-GCM Encryption**: Uses AES-GCM for authenticated encryption.
- **String-Based Input and Output**: Accepts and returns strings, making it easy to use with JSON and text data.
- **Automatic IV Generation**: Generates a unique initialization vector (IV) for each encryption operation.
- **Secure Key Management**: Derives cryptographic keys using SHA-256 hashing.
- **Fully Typed**: Written in TypeScript for enhanced developer experience.

## Installation

You can install `cipherly` using npm:

```bash
npm install cipherly
````

## Usage

### Encrypting a String

```javascript
import { Cipherly } from 'cipherly';

const cipher = new Cipherly('your-secret-key');
const encrypted = await cipher.encrypt('Hello, World!');
console.log(encrypted); // Encrypted string
```

### Decrypting a String

```javascript
import { Cipherly } from 'cipherly';

const cipher = new Cipherly('your-secret-key');
const decrypted = await cipher.decrypt(encrypted);
console.log(decrypted); // 'Hello, World!'
```

## API Documentation

### `Cipherly`

#### `new Cipherly(key: string)`

Creates a new instance of the `Cipherly` class.

* `key`: The secret key used for encryption and decryption.

#### `encrypt(data: string): Promise<string>`

Encrypts the provided string.

* `data`: The string to encrypt.
* Returns: A promise that resolves to the encrypted string.

#### `decrypt(encryptedData: string): Promise<string>`

Decrypts the provided encrypted string.

* `encryptedData`: The encrypted string to decrypt.
* Returns: A promise that resolves to the decrypted string.

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

