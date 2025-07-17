import { TurboModuleRegistry, type TurboModule } from 'react-native';

export interface Spec extends TurboModule {
  pbkdf2(
    password: string,
    salt: string,
    iterations: number,
    keyLen: number,
    algorithm: string
  ): Promise<string>;
  sha256(data: string): Promise<string>;
  sha512(data: string): Promise<string>;
  sha1(data: string): Promise<string>;
  hmacSha256(data: string, key: string): Promise<string>;
  hmacSha512(data: string, key: string): Promise<string>;
  aesEncrypt(
    data: string,
    key: string,
    iv: string | null,
    mode: 'GCM' | 'CBC'
  ): Promise<string>;
  aesDecrypt(
    encryptedData: string,
    key: string,
    iv: string | null,
    mode: 'GCM' | 'CBC'
  ): Promise<string>;
  generateRandomBytes(length: number): Promise<string>;
  generateSalt(length: number): Promise<string>;
  base64Encode(data: string): Promise<string>;
  base64Decode(data: string): Promise<string>;
  hexEncode(data: string): Promise<string>;
  hexDecode(data: string): Promise<string>;
  scrypt(
    password: string,
    salt: string,
    n: number,
    r: number,
    p: number,
    keyLen: number
  ): Promise<string>;
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
