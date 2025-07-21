<div align="center">
<br/>
<p>
<img src="[https://i.ibb.co/zTbYxsX9/image.jpg](https://i.ibb.co/JWm2mntv/544ca322-a760-4745-a2f4-24df32321f33-removalai-preview.png)" width="200" alt="Super Crypto" />
</p>
<br/>
<p>
<a href="https://www.npmjs.com/package/react-native-super-crypto"><img src="https://img.shields.io/npm/v/react-native-super-crypto.svg" alt="npm version"/></a>
<a href="https://www.npmjs.com/package/react-native-super-crypto"><img src="https://img.shields.io/npm/dm/react-native-super-crypto.svg" alt="npm downloads"/></a>
<a href="https://github.com/SAM-AEL/react-native-super-crypto/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"/></a>
<a href="https://github.com/SAM-AEL/react-native-super-crypto/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/SAM-AEL/react-native-super-crypto/ci.yml?branch=main" alt="GitHub Workflow Status"/></a>
</p>
<h1>React Native Super Crypto</h1>
<p>A robust and secure React Native module providing essential cryptographic functions for your mobile applications. Leveraging native platform capabilities, <code>react-native-super-crypto</code> offers high-performance and secure implementations of common cryptographic primitives, including hashing, HMAC, AES encryption, key derivation functions (PBKDF2, Scrypt), and secure random number generation.</p>
</div>

---

## 📖 Table of Contents

- [✨ Features](#-features)
- [🚀 Installation](#-installation)
- [💡 Usage](#-usage)
  - [Importing the Module](#importing-the-module)
  - [Base64 Encoding/Decoding](#base64-encodingdecoding)
  - [Hex Encoding/Decoding](#hex-encodingdecoding)
  - [AES Encryption/Decryption (GCM & CBC)](#aes-encryptiondecryption-gcm--cbc)
  - [SHA-256 / SHA-512 Hashing](#sha-256--sha-512-hashing)
  - [HMAC-SHA256 / HMAC-SHA512](#hmac-sha256--hmac-sha512)
  - [PBKDF2 Key Derivation](#pbkdf2-key-derivation)
  - [Scrypt Key Derivation](#scrypt-key-derivation)
  - [Generate Random Bytes](#generate-random-bytes)
  - [Verify Hash](#verify-hash)
- [📚 API Reference](#-api-reference)
- [⚠️ Warnings and Limitations](#️-warnings-and-limitations)
- [🔒 Security Considerations](#-security-considerations)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙌 Support](#-support)

---

## ✨ Features

`react-native-super-crypto` provides the following cryptographic functionalities:

*   **Hashing**: SHA-256, SHA-512, and SHA-1.
*   **HMAC**: HMAC-SHA256, HMAC-SHA512 for message authentication.
*   **Symmetric Encryption**: AES-256-GCM and AES-256-CBC for secure data encryption and decryption.
*   **Key Derivation Functions**:
    *   **PBKDF2**: Password-Based Key Derivation Function 2 for securely deriving keys from passwords.
    *   **Scrypt**: A memory-hard key derivation function designed to be resistant to brute-force attacks.
*   **Secure Randomness**: Generation of cryptographically secure random bytes and salts.
*   **Encoding/Decoding**: Base64 and Hex encoding/decoding utilities.

---

## 🚀 Installation

To install `react-native-super-crypto` in your React Native project, follow these steps:

```bash
npm install react-native-super-crypto
# or
yarn add react-native-super-crypto
```

For React Native versions 0.60 and above, autolinking should handle the native module linking automatically.

For **iOS**, navigate to your `ios` directory and install the pods:

```bash
cd ios && pod install && cd ..
```

---

## 💡 Usage

### Importing the Module

```typescript
import SuperCrypto from 'react-native-super-crypto';
```

### Base64 Encoding/Decoding

```typescript
import SuperCrypto from 'react-native-super-crypto';

async function handleBase64() {
  const originalText = 'Hello, SuperCrypto!';
  try {
    const encoded = await SuperCrypto.base64Encode(originalText);
    console.log('Base64 Encoded:', encoded); // e.g., "SGVsbG8sIFN1cGVyQ3J5cHRvIQ=="

    const decoded = await SuperCrypto.base64Decode(encoded);
    console.log('Base64 Decoded:', decoded); // "Hello, SuperCrypto!"
  } catch (error) {
    console.error('Base64 Error:', error);
  }
}
```

### Hex Encoding/Decoding

```typescript
import SuperCrypto from 'react-native-super-crypto';

async function handleHex() {
  const originalText = 'Hello, Hex!';
  try {
    const encoded = await SuperCrypto.hexEncode(originalText);
    console.log('Hex Encoded:', encoded); // e.g., "48656c6c6f2c2048657821"

    const decoded = await SuperCrypto.hexDecode(encoded);
    console.log('Hex Decoded:', decoded); // "Hello, Hex!"
  } catch (error) {
    console.error('Hex Error:', error);
  }
}
```

### AES Encryption/Decryption (GCM & CBC)

AES encryption requires a 32-byte (256-bit) key.
*   **GCM (Galois/Counter Mode)**: Requires a 12-byte IV (Initialization Vector). GCM provides authenticated encryption, meaning it ensures both confidentiality and integrity. It is generally recommended for modern applications.
*   **CBC (Cipher Block Chaining)**: Requires a 16-byte IV. CBC provides confidentiality but does not inherently provide integrity. If using CBC, you should combine it with an HMAC for message authentication.

<font color="yellow" size="2"><strong>⚠️ Important:</strong> All keys and IVs should be base64 encoded strings.</font>

```typescript
import SuperCrypto from 'react-native-super-crypto';

async function handleAesGcm() {
  const plaintext = 'This is a secret message using GCM.';
  try {
    // Generate a secure key and IV for GCM
    const key = await SuperCrypto.generateRandomBytes(32); // 32 bytes for AES-256
    const iv = await SuperCrypto.generateRandomBytes(12); // 12 bytes for GCM

    const encrypted = await SuperCrypto.aesEncrypt(plaintext, key, iv, 'GCM');
    const decrypted = await SuperCrypto.aesDecrypt(encrypted, key, iv, 'GCM');
    console.log('AES-GCM Decrypted:', decrypted);
  } catch (error) {
    console.error('AES-GCM Error:', error);
  }
}

async function handleAesCbc() {
  const plaintext = 'This is a secret message using CBC.';
  try {
    // Generate a secure key and IV for CBC
    const key = await SuperCrypto.generateRandomBytes(32); // 32 bytes for AES-256
    const iv = await SuperCrypto.generateRandomBytes(16); // 16 bytes for CBC

    const encrypted = await SuperCrypto.aesEncrypt(plaintext, key, iv, 'CBC');
    const decrypted = await SuperCrypto.aesDecrypt(encrypted, key, iv, 'CBC');
    console.log('AES-CBC Decrypted:', decrypted);
  } catch (error) {
    console.error('AES-CBC Error:', error);
  }
}
```

### SHA-256 / SHA-512 Hashing

```typescript
import SuperCrypto from 'react-native-super-crypto';

async function handleShaHash() {
  const data = 'data to hash';
  try {
    const sha256Hash = await SuperCrypto.sha256(data);
    console.log('SHA256 Hash:', sha256Hash);

    const sha512Hash = await SuperCrypto.sha512(data);
    console.log('SHA512 Hash:', sha512Hash);

    ⚠️ Deprecation Warning: SHA-1 is available but deprecated for security-sensitive applications. Use with caution.
    const sha1Hash = await SuperCrypto.sha1(data);
    console.warn('SHA1 Hash (DEPRECATED):', sha1Hash);
  } catch (error) {
    console.error('Hash Error:', error);
  }
}
```

### HMAC-SHA256 / HMAC-SHA512

```typescript
import SuperCrypto from 'react-native-super-crypto';

async function handleHmac() {
  const data = 'message for HMAC';
  const key = 'supersecretkey'; // In a real app, derive this securely!
  try {
    const hmac256 = await SuperCrypto.hmacSha256(data, key);
    console.log('HMAC-SHA256:', hmac256);

    const hmac512 = await SuperCrypto.hmacSha512(data, key);
    console.log('HMAC-SHA512:', hmac512);
  } catch (error) {
    console.error('HMAC Error:', error);
  }
}
```

### PBKDF2 Key Derivation

```typescript
import SuperCrypto from 'react-native-super-crypto';

async function handlePbkdf2() {
  const password = 'myStrongPassword123!';
  try {
    const salt = await SuperCrypto.generateSalt(16); // 16 bytes salt
    const derivedKey = await SuperCrypto.pbkdf2(
      password,
      salt,
      10000, // iterations (recommend 10,000 or more)
      32,    // keyLen (32 bytes for 256-bit key)
      'SHA256' // algorithm
    );
    console.log('PBKDF2 Derived Key (base64):', derivedKey);
  } catch (error) {
    console.error('PBKDF2 Error:', error);
  }
}
```

### Scrypt Key Derivation

```typescript
import SuperCrypto from 'react-native-super-crypto';

async function handleScrypt() {
  const password = 'anotherStrongPassword!';
  try {
    const salt = await SuperCrypto.generateSalt(16); // 16 bytes salt
    const derivedKey = await SuperCrypto.scrypt(
      password,
      salt,
      16384, // N (CPU/memory cost parameter, power of 2, minimum 16384)
      8,     // r (block size parameter)
      1,     // p (parallelization parameter)
      32     // keyLen (32 bytes for 256-bit key)
    );
    console.log('Scrypt Derived Key (base64):', derivedKey);
  } catch (error) {
    console.error('Scrypt Error:', error);
  }
}
```

### Generate Random Bytes

```typescript
import SuperCrypto from 'react-native-super-crypto';

async function handleRandomBytes() {
  try {
    const randomBytes = await SuperCrypto.generateRandomBytes(64); // Generate 64 random bytes
    console.log('Random Bytes (base64):', randomBytes);
  } catch (error) {
    console.error('Random Bytes Error:', error);
  }
}
```

### Verify Hash

This function allows you to verify if a given data string matches a provided hash using a specified algorithm.

```typescript
import SuperCrypto from 'react-native-super-crypto';

async function handleVerifyHash() {
  const data = 'my secret data';
  const algorithm = 'SHA256';

  try {
    const hash = await SuperCrypto.sha256(data);
    const isValid = await SuperCrypto.verifyHash(data, hash, algorithm);
    console.log('Hash is valid:', isValid); // true

    const tamperedData = 'my secret data altered';
    const isInvalid = await SuperCrypto.verifyHash(tamperedData, hash, algorithm);
    console.log('Hash is valid for tampered data:', isInvalid); // false
  } catch (error) {
    console.error('Verify Hash Error:', error);
  }
}
```

---

## 📚 API Reference

All functions return a `Promise<string>` unless otherwise specified. Errors are thrown as `Error` objects.

<details>
<summary><strong>pbkdf2(password: string, salt: string, iterations: number, keyLen: number, algorithm: string): Promise&lt;string&gt;</strong></summary>
<p>

Derives a cryptographic key from a password using PBKDF2.

-   `password`: The password to derive the key from.
-   `salt`: The salt (base64 encoded string). Should be unique per password.
-   `iterations`: The number of iterations. Higher values increase security but also computation time.
-   `keyLen`: The desired length of the derived key in bytes.
-   `algorithm`: The PRF (Pseudo-Random Function) algorithm to use, e.g., `'SHA256'`, `'SHA512'`.

</p>
</details>

<details>
<summary><strong>sha256(data: string): Promise&lt;string&gt;</strong></summary>
<p>

Computes the SHA-256 hash of the input data.

-   `data`: The string data to hash.

</p>
</details>

<details>
<summary><strong>sha512(data: string): Promise&lt;string&gt;</strong></summary>
<p>

Computes the SHA-512 hash of the input data.

-   `data`: The string data to hash.

</p>
</details>

<details>
<summary><strong>sha1(data: string): Promise&lt;string&gt;</strong></summary>
<p>

<font color="orange" size="2"><strong>⚠️ WARNING:</strong> SHA-1 is cryptographically broken and should not be used for new security-sensitive applications. It is provided for compatibility reasons only.</font>

Computes the SHA-1 hash of the input data.

-   `data`: The string data to hash.

</p>
</details>

<details>
<summary><strong>hmacSha256(data: string, key: string): Promise&lt;string&gt;</strong></summary>
<p>

Computes the HMAC-SHA256 of the input data using a secret key.

-   `data`: The string data to authenticate.
-   `key`: The secret key (string).

</p>
</details>

<details>
<summary><strong>hmacSha512(data: string, key: string): Promise&lt;string&gt;</strong></summary>
<p>

Computes the HMAC-SHA512 of the input data using a secret key.

-   `data`: The string data to authenticate.
-   `key`: The secret key (string).

</p>
</details>

<details>
<summary><strong>aesEncrypt(data: string, key: string, iv: string | null, mode: 'GCM' | 'CBC'): Promise&lt;string&gt;</strong></summary>
<p>

Encrypts data using AES-256 with the specified mode. The output is a base64 encoded string containing the ciphertext and authentication tag (for GCM).

-   `data`: The plaintext string to encrypt.
-   `key`: The 32-byte (256-bit) AES key (base64 encoded string).
-   `iv`: The IV (Initialization Vector) for the chosen mode (base64 encoded string). Must be 12 bytes for GCM, 16 bytes for CBC.
-   `mode`: The AES encryption mode to use: `'GCM'` or `'CBC'`.

</p>
</details>

<details>
<summary><strong>aesDecrypt(encryptedData: string, key: string, iv: string | null, mode: 'GCM' | 'CBC'): Promise&lt;string&gt;</strong></summary>
<p>

Decrypts data encrypted with AES-256 with the specified mode.

-   `encryptedData`: The base64 encoded string containing the ciphertext and authentication tag (for GCM).
-   `key`: The 32-byte (256-bit) AES key (base64 encoded string) used for encryption.
-   `iv`: The IV (base64 encoded string) used during encryption. Must be 12 bytes for GCM, 16 bytes for CBC.
-   `mode`: The AES encryption mode used: `'GCM'` or `'CBC'`.

</p>
</details>

<details>
<summary><strong>generateRandomBytes(length: number): Promise&lt;string&gt;</strong></summary>
<p>

Generates cryptographically secure random bytes.

-   `length`: The number of bytes to generate.
-   Returns: A base64 encoded string of the random bytes.

</p>
</details>

<details>
<summary><strong>generateSalt(length: number): Promise&lt;string&gt;</strong></summary>
<p>

Generates a cryptographically secure salt. This is a convenience wrapper around `generateRandomBytes`.

-   `length`: The number of bytes for the salt.
-   Returns: A base64 encoded string of the salt.

</p>
</details>

<details>
<summary><strong>base64Encode(data: string): Promise&lt;string&gt;</strong></summary>
<p>

Encodes a string to its Base64 representation.

-   `data`: The string to encode.

</p>
</details>

<details>
<summary><strong>base64Decode(data: string): Promise&lt;string&gt;</strong></summary>
<p>

Decodes a Base64 encoded string back to its original form.

-   `data`: The Base64 encoded string to decode.

</p>
</details>

<details>
<summary><strong>hexEncode(data: string): Promise&lt;string&gt;</strong></summary>
<p>

Encodes a string to its hexadecimal representation.

-   `data`: The string to encode.

</p>
</details>

<details>
<summary><strong>hexDecode(data: string): Promise&lt;string&gt;</strong></summary>
<p>

Decodes a hexadecimal string back to its original form.

-   `data`: The hexadecimal string to decode.

</p>
</details>

<details>
<summary><strong>scrypt(password: string, salt: string, n: number, r: number, p: number, keyLen: number): Promise&lt;string&gt;</strong></summary>
<p>

Derives a cryptographic key from a password using Scrypt.

-   `password`: The password to derive the key from.
-   `salt`: The salt (base64 encoded string).
-   `n`: CPU/memory cost parameter (**must be a power of 2, minimum 16384**; enforced on both iOS and Android).
-   `r`: Block size parameter.
-   `p`: Parallelization parameter.
-   `keyLen`: The desired length of the derived key in bytes.

</p>
</details>

<details>
<summary><strong>verifyHash(data: string, hash: string, algorithm: string): Promise&lt;boolean&gt;</strong></summary>
<p>

Verifies if the hash of the given data matches the provided hash string.

-   `data`: The original data string.
-   `hash`: The hash string to compare against.
-   `algorithm`: The hashing algorithm used to generate the hash (e.g., `'SHA256'`, `'SHA512'`, `'SHA1'`).
-   Returns: `true` if the hash matches, `false` otherwise.

</p>
</details>

---

## ⚠️ Warnings and Limitations

*   <font color="yellow" size="2">**Platform Specifics**: This module relies on native implementations. While efforts are made to ensure cross-platform consistency (iOS and Android), subtle differences in underlying cryptographic libraries might exist. Always test thoroughly on all target platforms.</font>
*   <font color="yellow" size="2">**Error Handling**: Functions return Promises that will reject on error. Implement robust `try-catch` blocks to handle potential cryptographic failures (e.g., invalid keys, corrupted data, incorrect IVs).</font>
*   <font color="yellow" size="2">**Performance**: While native implementations are generally fast, complex operations like Scrypt with high parameters can be computationally intensive and may block the UI thread if not handled asynchronously. All functions are asynchronous and return Promises, which helps mitigate this.</font>
*   <font color="orange" size="2">**SHA-1 Deprecation**: The `sha1` function is included for legacy compatibility only. **Do not use SHA-1 for new security-sensitive applications** due to known cryptographic weaknesses. Prefer SHA-256 or SHA-512.</font>
*   <font color="orange" size="2">**AES Modes**:</font>
    *   <font color="orange" size="2">**GCM is generally preferred** over CBC for authenticated encryption.</font>
    *   <font color="orange" size="2">If using **CBC**, you **must** implement a separate mechanism for message authentication (e.g., HMAC) to protect against tampering. CBC alone only provides confidentiality.</font>

---

## 🔒 Security Considerations

Using cryptographic functions correctly is paramount for security. Misuse can lead to severe vulnerabilities.

*   <font color="red" size="2">**Key Management**:</font>
    *   <font color="red" size="2">**Never hardcode keys or IVs** in your application code.</font>
    *   <font color="red" size="2">Store keys securely, preferably using platform-specific secure storage mechanisms (e.g., Android Keystore, iOS Keychain) or derived from user credentials using strong KDFs.</font>
    *   <font color="red" size="2">Ensure keys and IVs are generated using cryptographically secure random number generators (like `generateRandomBytes`).</font>
    *   <font color="red" size="2">Protect keys from unauthorized access and disclosure.</font>
*   <font color="red" size="2">**IV Usage (AES)**:</font>
    *   <font color="red" size="2">For both GCM and CBC, the IV (Initialization Vector) does not need to be secret, but it **must be unique for each encryption** with the same key. Reusing an IV with the same key is a critical security vulnerability.</font>
    *   <font color="red" size="2">For GCM, the IV must be 12 bytes. For CBC, the IV must be 16 bytes.</font>
*   <font color="red" size="2">**Password Hashing**:</font>
    *   <font color="red" size="2">Always use strong, adaptive key derivation functions like **PBKDF2 or Scrypt** for hashing passwords. Never use simple hash functions (like SHA-256 directly) for passwords, as they are vulnerable to rainbow table and brute-force attacks.</font>
    *   <font color="red" size="2">Always use a **unique, cryptographically secure salt** for each password.</font>
    *   <font color="red" size="2">Choose sufficiently high iteration counts (for PBKDF2) or cost parameters (for Scrypt) to make brute-force attacks computationally infeasible. **For Scrypt, N must be a power of 2 and at least 16384 (enforced on both iOS and Android).** These parameters should be tuned based on current hardware capabilities and security recommendations.</font>
*   **Data Integrity**: HMAC functions provide message authentication, ensuring that data has not been tampered with. Use them when you need to verify the integrity and authenticity of a message.
*   **Input Validation**: Always validate and sanitize inputs to cryptographic functions to prevent unexpected behavior or potential attacks.
*   **Hash Comparison Security**: The `verifyHash` method uses constant-time comparison functions to prevent timing attacks.
*   **String Encoding/Decoding Robustness**: All string encoding/decoding operations (UTF-8, Base64, Hex) are robustly checked for errors, and any encoding/decoding failures are reported with clear error codes and messages.

---

## 🤝 Contributing

Contributions are welcome! If you find a bug, have a feature request, or want to improve the documentation, please open an issue or submit a pull request on the [GitHub repository](https://github.com/SAM-AEL/react-native-super-crypto).

Please ensure your contributions adhere to the existing code style and include appropriate tests.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/SAM-AEL/react-native-super-crypto/blob/main/LICENSE) file for details.

---

## 🙌 Support

For questions, bug reports, or feature requests, please open an issue on the [GitHub Issues page](https://github.com/SAM-AEL/react-native-super-crypto/issues).
