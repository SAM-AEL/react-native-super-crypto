import { TurboModuleRegistry, type TurboModule } from 'react-native';

export interface Spec extends TurboModule {
  /**
   * Derives a cryptographic key from a password using PBKDF2.
   * @param password The password to derive the key from.
   * @param salt The salt (base64 encoded string).
   * @param iterations Number of iterations (should be >= 10,000 for security).
   * @param keyLen The desired length of the derived key in bytes.
   * @param algorithm Hash algorithm to use ('SHA256', 'SHA512').
   * @returns A promise that resolves to the derived key (base64 encoded).
   */
  pbkdf2(
    password: string,
    salt: string,
    iterations: number,
    keyLen: number,
    algorithm: string
  ): Promise<string>;

  /**
   * Computes the SHA-256 hash of the input data.
   * @param data The input string to hash.
   * @returns A promise that resolves to the hash (base64 encoded).
   */
  sha256(data: string): Promise<string>;

  /**
   * Computes the SHA-512 hash of the input data.
   * @param data The input string to hash.
   * @returns A promise that resolves to the hash (base64 encoded).
   */
  sha512(data: string): Promise<string>;

  /**
   * Computes the SHA-1 hash of the input data (deprecated, insecure).
   * @param data The input string to hash.
   * @returns A promise that resolves to the hash (base64 encoded).
   */
  sha1(data: string): Promise<string>;

  /**
   * Computes the HMAC-SHA256 of the input data using the provided key.
   * @param data The input string to authenticate.
   * @param key The key to use (string).
   * @returns A promise that resolves to the HMAC (base64 encoded).
   */
  hmacSha256(data: string, key: string): Promise<string>;

  /**
   * Computes the HMAC-SHA512 of the input data using the provided key.
   * @param data The input string to authenticate.
   * @param key The key to use (string).
   * @returns A promise that resolves to the HMAC (base64 encoded).
   */
  hmacSha512(data: string, key: string): Promise<string>;

  /**
   * Encrypts data using AES (GCM or CBC mode).
   * @param data The plaintext to encrypt.
   * @param key The encryption key (base64 encoded, 16/24/32 bytes).
   * @param iv The initialization vector (base64 encoded, 12 bytes for GCM, 16 for CBC) or null to auto-generate.
   * @param mode The AES mode ('GCM' or 'CBC').
   * @returns A promise that resolves to the encrypted data (base64 encoded).
   */
  aesEncrypt(
    data: string,
    key: string,
    iv: string | null,
    mode: 'GCM' | 'CBC'
  ): Promise<string>;

  /**
   * Decrypts AES-encrypted data (GCM or CBC mode).
   * @param encryptedData The encrypted data (base64 encoded).
   * @param key The decryption key (base64 encoded, 16/24/32 bytes).
   * @param iv The initialization vector (base64 encoded, 12 bytes for GCM, 16 for CBC) or null if included in data.
   * @param mode The AES mode ('GCM' or 'CBC').
   * @returns A promise that resolves to the decrypted plaintext string.
   */
  aesDecrypt(
    encryptedData: string,
    key: string,
    iv: string | null,
    mode: 'GCM' | 'CBC'
  ): Promise<string>;

  /**
   * Generates cryptographically secure random bytes.
   * @param length The number of bytes to generate.
   * @returns A promise that resolves to the random bytes (base64 encoded).
   */
  generateRandomBytes(length: number): Promise<string>;

  /**
   * Generates a cryptographically secure salt.
   * @param length The number of bytes for the salt.
   * @returns A promise that resolves to the salt (base64 encoded).
   */
  generateSalt(length: number): Promise<string>;

  /**
   * Encodes a string to its Base64 representation.
   * @param data The string to encode.
   * @returns A promise that resolves to the Base64 encoded string.
   */
  base64Encode(data: string): Promise<string>;

  /**
   * Decodes a Base64 encoded string back to its original form.
   * @param data The Base64 encoded string to decode.
   * @returns A promise that resolves to the decoded string.
   */
  base64Decode(data: string): Promise<string>;

  /**
   * Encodes a string to its hexadecimal representation.
   * @param data The string to encode.
   * @returns A promise that resolves to the hex encoded string.
   */
  hexEncode(data: string): Promise<string>;

  /**
   * Decodes a hexadecimal string back to its original form.
   * @param data The hexadecimal string to decode.
   * @returns A promise that resolves to the decoded string.
   */
  hexDecode(data: string): Promise<string>;

  /**
   * Derives a cryptographic key from a password using Scrypt.
   * @param password The password to derive the key from.
   * @param salt The salt (base64 encoded string).
   * @param n CPU/memory cost parameter (must be a power of 2, minimum 16384; enforced on both iOS and Android).
   * @param r Block size parameter.
   * @param p Parallelization parameter.
   * @param keyLen The desired length of the derived key in bytes.
   * @returns A promise that resolves to the derived key (base64 encoded).
   */
  scrypt(
    password: string,
    salt: string,
    n: number,
    r: number,
    p: number,
    keyLen: number
  ): Promise<string>;

  /**
   * Verifies if the hash of the given data matches the provided hash string.
   * @param data The original data string.
   * @param hash The hash string to compare against (base64 encoded).
   * @param algorithm The hashing algorithm used ('SHA256', 'SHA512', 'SHA1').
   * @returns A promise that resolves to true if the hash matches, false otherwise.
   */
  verifyHash(data: string, hash: string, algorithm: string): Promise<boolean>;
}

const SuperCrypto = TurboModuleRegistry.get<Spec>('SuperCrypto');

if (!SuperCrypto) {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error(
      'SuperCrypto native module is not available. Make sure it is properly linked and built.'
    );
  }
}

export default SuperCrypto as Spec;
