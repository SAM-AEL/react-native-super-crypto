#import "RCTSuperCrypto.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import "crypto_scrypt.h"
#import "SuperCryptoGCM.swift.h"
#import "libscrypt.h"
#import "slowequals.h"

// Error code and message constants
#define ERR_INVALID_INPUT_CODE @"INVALID_INPUT"
#define ERR_INVALID_INPUT_MSG @"Input data cannot be empty"
#define ERR_INVALID_BASE64_MSG @"Input must be valid Base64"
#define ERR_INVALID_HEX_MSG @"Input must be a valid hex string"
#define ERR_UNSUPPORTED_ALGO_CODE @"UNSUPPORTED_ALGORITHM"
#define ERR_UNSUPPORTED_ALGO_MSG @"Unsupported hash algorithm"
#define ERR_DEPRECATED_CODE @"DEPRECATED_FUNCTION"
#define ERR_DEPRECATED_MSG @"SHA1 is deprecated and should not be used for security purposes. Please use SHA256 or SHA512 instead."
#define ERR_AES_ENCRYPT_CODE @"AES_ENCRYPT_ERROR"
#define ERR_AES_DECRYPT_CODE @"AES_DECRYPT_ERROR"
#define ERR_PBKDF2_CODE @"PBKDF2_ERROR"
#define ERR_SCRYPT_CODE @"SCRYPT_ERROR"
#define ERR_RANDOM_BYTES_CODE @"RANDOM_BYTES_ERROR"
#define ERR_SALT_GEN_CODE @"SALT_GENERATION_ERROR"
#define ERR_BASE64_ENCODE_CODE @"BASE64_ENCODE_ERROR"
#define ERR_BASE64_DECODE_CODE @"BASE64_DECODE_ERROR"
#define ERR_HEX_ENCODE_CODE @"HEX_ENCODE_ERROR"
#define ERR_HEX_DECODE_CODE @"HEX_DECODE_ERROR"
// Add a helper for encoding errors
#define ERR_UTF8_ENCODE_CODE @"UTF8_ENCODE_ERROR"
#define ERR_UTF8_ENCODE_MSG @"Failed to encode string as UTF-8"
#define ERR_UTF8_DECODE_CODE @"UTF8_DECODE_ERROR"
#define ERR_UTF8_DECODE_MSG @"Failed to decode data as UTF-8"

@implementation SuperCrypto

// Helper validation methods
- (BOOL)isValidBase64:(NSString *)input {
    // Only check if NSData can decode it
    return input.length > 0 && [[NSData alloc] initWithBase64EncodedString:input options:0] != nil;
}
- (BOOL)isValidHex:(NSString *)input {
    if (input.length == 0) return NO;
    NSCharacterSet *hexSet = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet];
    return [input rangeOfCharacterFromSet:hexSet].location == NSNotFound;
}

#define RUN_CRYPTO_ASYNC(block) \
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), block)

- (void)pbkdf2:(NSString *)password salt:(NSString *)salt iterations:(double)iterations keyLen:(double)keyLen algorithm:(NSString *)algorithm resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject {
    RUN_CRYPTO_ASYNC(^{
        if (password.length == 0 || salt.length == 0) {
            reject(ERR_INVALID_INPUT_CODE, @"Password and salt cannot be empty", nil);
            return;
        }
        if (![self isValidBase64:salt]) {
            reject(ERR_INVALID_INPUT_CODE, @"Salt must be valid Base64", nil);
            return;
        }
        if (iterations < 1) {
            reject(ERR_INVALID_INPUT_CODE, @"Iterations must be a positive number", nil);
            return;
        }
        if (keyLen < 1 || keyLen > 512) {
            reject(ERR_INVALID_INPUT_CODE, @"Key length must be between 1 and 512 bytes", nil);
            return;
        }
        NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
        NSData *saltData = [[NSData alloc] initWithBase64EncodedString:salt options:0];
        uint32_t prf = kCCPRFHmacAlgSHA256;
        if ([algorithm.uppercaseString isEqualToString:@"SHA512"]) {
            prf = kCCPRFHmacAlgSHA512;
        } else if (![algorithm.uppercaseString isEqualToString:@"SHA256"]) {
            reject(ERR_UNSUPPORTED_ALGO_CODE, @"Unsupported hash algorithm", nil);
            return;
        }
        NSMutableData *keyData = [NSMutableData dataWithLength:(NSUInteger)keyLen];
        CCCryptorStatus result = CCKeyDerivationPBKDF(kCCPBKDF2,
                                                     passwordData.bytes,
                                                     passwordData.length,
                                                     saltData.bytes,
                                                     saltData.length,
                                                     prf,
                                                     (uint)iterations,
                                                     keyData.mutableBytes,
                                                     keyData.length);
        if (result == kCCSuccess) {
            resolve([keyData base64EncodedStringWithOptions:0]);
        } else {
            reject(ERR_PBKDF2_CODE, [NSString stringWithFormat:@"PBKDF2 failed with error code %d", result], nil);
        }
    });
}

- (void)sha256:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    RUN_CRYPTO_ASYNC(^{
        if (data.length == 0) {
            reject(ERR_INVALID_INPUT_CODE, @"Input data cannot be empty", nil);
            return;
        }
        NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
        uint8_t digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(dataData.bytes, (CC_LONG)dataData.length, digest);
        NSData *hash = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
        resolve([hash base64EncodedStringWithOptions:0]);
    });
}

- (void)sha512:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    RUN_CRYPTO_ASYNC(^{
        if (data.length == 0) {
            reject(ERR_INVALID_INPUT_CODE, @"Input data cannot be empty", nil);
            return;
        }
        NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
        uint8_t digest[CC_SHA512_DIGEST_LENGTH];
        CC_SHA512(dataData.bytes, (CC_LONG)dataData.length, digest);
        NSData *hash = [NSData dataWithBytes:digest length:CC_SHA512_DIGEST_LENGTH];
        resolve([hash base64EncodedStringWithOptions:0]);
    });
}

- (void)sha1:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    NSLog(@"[SuperCrypto] SHA1 is deprecated and insecure. Use SHA256 or SHA512 instead.");
    reject(ERR_DEPRECATED_CODE, ERR_DEPRECATED_MSG, nil);
}

- (void)hmacSha256:(NSString *)data key:(NSString *)key resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    RUN_CRYPTO_ASYNC(^{
        if (data.length == 0 || key.length == 0) {
            reject(ERR_INVALID_INPUT_CODE, @"Data and key cannot be empty", nil);
            return;
        }
        NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
        NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
        uint8_t cHMAC[CC_SHA256_DIGEST_LENGTH];
        CCHmac(kCCHmacAlgSHA256, keyData.bytes, keyData.length, dataData.bytes, dataData.length, cHMAC);
        NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
        resolve([HMAC base64EncodedStringWithOptions:0]);
    });
}

- (void)hmacSha512:(NSString *)data key:(NSString *)key resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    RUN_CRYPTO_ASYNC(^{
        if (data.length == 0 || key.length == 0) {
            reject(ERR_INVALID_INPUT_CODE, @"Data and key cannot be empty", nil);
            return;
        }
        NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
        NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
        uint8_t cHMAC[CC_SHA512_DIGEST_LENGTH];
        CCHmac(kCCHmacAlgSHA512, keyData.bytes, keyData.length, dataData.bytes, dataData.length, cHMAC);
        NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
        resolve([HMAC base64EncodedStringWithOptions:0]);
    });
}

// Helper for key validation
- (NSData *)validatedAESKey:(NSString *)key reject:(RCTPromiseRejectBlock)reject {
    if (![self isValidBase64:key]) {
        reject(ERR_INVALID_INPUT_CODE, @"Key must be valid Base64", nil);
        return nil;
    }
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
    if (keyData.length != 16 && keyData.length != 24 && keyData.length != 32) {
        reject(ERR_INVALID_INPUT_CODE, @"Key must be 16, 24, or 32 bytes for AES", nil);
        return nil;
    }
    return keyData;
}

// Helper for IV handling
- (NSData *)ivDataForMode:(NSString *)mode providedIV:(NSString *)iv isEncrypt:(BOOL)isEncrypt reject:(RCTPromiseRejectBlock)reject {
    NSUInteger ivLength = [mode.uppercaseString isEqualToString:@"GCM"] ? 12 : 16;
    if (iv == nil || iv.length == 0) {
        if (isEncrypt) {
            NSMutableData *randomIv = [NSMutableData dataWithLength:ivLength];
            SecRandomCopyBytes(kSecRandomDefault, ivLength, randomIv.mutableBytes);
            return randomIv;
        } else {
            // For decrypt, IV must be extracted from ciphertext, not generated
            return nil;
        }
    } else {
        if (![self isValidBase64:iv]) {
            reject(ERR_INVALID_INPUT_CODE, @"IV must be valid Base64", nil);
            return nil;
        }
        NSData *ivData = [[NSData alloc] initWithBase64EncodedString:iv options:0];
        if (ivData.length != ivLength) {
            reject(ERR_INVALID_INPUT_CODE, [NSString stringWithFormat:@"IV must be %lu bytes for AES-%@", (unsigned long)ivLength, mode.uppercaseString], nil);
            return nil;
        }
        return ivData;
    }
}

- (void)aesEncrypt:(NSString *)data key:(NSString *)key iv:(NSString *)iv mode:(NSString *)mode resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    RUN_CRYPTO_ASYNC(^{
        if (data.length == 0 || key.length == 0 || mode.length == 0) {
            reject(ERR_INVALID_INPUT_CODE, @"Data, key, and mode cannot be empty", nil);
            return;
        }
        NSData *keyData = [self validatedAESKey:key reject:reject];
        if (!keyData) return;
        NSString *modeUpper = [mode uppercaseString];
        NSData *ivData = [self ivDataForMode:modeUpper providedIV:iv isEncrypt:YES reject:reject];
        if (!ivData) return;
        NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
        if (!dataData) {
            reject(ERR_UTF8_ENCODE_CODE, ERR_UTF8_ENCODE_MSG, nil);
            return;
        }
        if ([modeUpper isEqualToString:@"GCM"]) {
            NSError *error = nil;
            NSData *encryptedData = [SuperCryptoGCM encrypt:dataData key:keyData iv:[ivData base64EncodedStringWithOptions:0] error:&error];
            if (error) {
                reject(ERR_AES_ENCRYPT_CODE, [NSString stringWithFormat:@"AES-GCM encryption failed: %@", error.localizedDescription], error);
                return;
            }
            resolve([encryptedData base64EncodedStringWithOptions:0]);
        } else if ([modeUpper isEqualToString:@"CBC"]) {
            size_t outLength;
            NSMutableData *cipherData = [NSMutableData dataWithLength:dataData.length + kCCBlockSizeAES128];
            CCCryptorStatus result = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                             keyData.bytes, keyData.length,
                                             ivData.bytes,
                                             dataData.bytes, dataData.length,
                                             cipherData.mutableBytes, cipherData.length,
                                             &outLength);
            if (result == kCCSuccess) {
                cipherData.length = outLength;
                NSMutableData *combined = [NSMutableData dataWithData:ivData];
                [combined appendData:cipherData];
                resolve([combined base64EncodedStringWithOptions:0]);
            } else {
                reject(ERR_AES_ENCRYPT_CODE, [NSString stringWithFormat:@"AES-CBC encryption failed: %d", result], nil);
            }
        } else {
            reject(ERR_UNSUPPORTED_ALGO_CODE, ERR_UNSUPPORTED_ALGO_MSG, nil);
        }
    });
}

- (void)aesDecrypt:(NSString *)encryptedData key:(NSString *)key iv:(NSString *)iv mode:(NSString *)mode resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    RUN_CRYPTO_ASYNC(^{
        if (encryptedData.length == 0 || key.length == 0 || mode.length == 0) {
            reject(ERR_INVALID_INPUT_CODE, @"Encrypted data, key, and mode cannot be empty", nil);
            return;
        }
        NSData *keyData = [self validatedAESKey:key reject:reject];
        if (!keyData) return;
        NSString *modeUpper = [mode uppercaseString];
        NSData *encryptedDataData = [[NSData alloc] initWithBase64EncodedString:encryptedData options:0];
        NSData *ivData = nil;
        NSData *cipherData = nil;
        if ([modeUpper isEqualToString:@"GCM"]) {
            // Always expect the combined format (nonce|ciphertext|tag)
            NSError *error = nil;
            NSData *decryptedData = [SuperCryptoGCM decrypt:encryptedDataData key:keyData error:&error];
            if (error) {
                reject(ERR_AES_DECRYPT_CODE, [NSString stringWithFormat:@"AES-GCM decryption failed: %@", error.localizedDescription], error);
                return;
            }
            NSString *result = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
            if (!result) {
                reject(ERR_UTF8_DECODE_CODE, ERR_UTF8_DECODE_MSG, nil);
                return;
            }
            resolve(result);
        } else if ([modeUpper isEqualToString:@"CBC"]) {
            // Always expect the combined format (IV|ciphertext) for CBC
            if (iv != nil && iv.length > 0) {
                reject(ERR_INVALID_INPUT_CODE, @"For CBC mode, the IV must not be provided separately. The encrypted data must be in the combined format (IV|ciphertext).", nil);
                return;
            }
            if (encryptedDataData.length < 16) {
                reject(ERR_INVALID_INPUT_CODE, @"Encrypted data too short to contain IV", nil);
                return;
            }
            NSData *ivData = [encryptedDataData subdataWithRange:NSMakeRange(0, 16)];
            NSData *cipherData = [encryptedDataData subdataWithRange:NSMakeRange(16, encryptedDataData.length - 16)];
            size_t outLength;
            NSMutableData *plainData = [NSMutableData dataWithLength:cipherData.length + kCCBlockSizeAES128];
            CCCryptorStatus result = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                             keyData.bytes, keyData.length,
                                             ivData.bytes,
                                             cipherData.bytes, cipherData.length,
                                             plainData.mutableBytes, plainData.length,
                                             &outLength);
            if (result == kCCSuccess) {
                plainData.length = outLength;
                NSString *resultStr = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
                if (!resultStr) {
                    reject(ERR_AES_DECRYPT_CODE, @"Failed to decode decrypted data as UTF-8", nil);
                    return;
                }
                resolve(resultStr);
            } else {
                reject(ERR_AES_DECRYPT_CODE, [NSString stringWithFormat:@"AES-CBC decryption failed: %d", result], nil);
            }
        } else {
            reject(ERR_UNSUPPORTED_ALGO_CODE, ERR_UNSUPPORTED_ALGO_MSG, nil);
        }
    });
}

// Add back the missing methods for compatibility with the header
- (void)aesEncrypt:(NSString *)data key:(NSString *)key resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    [self aesEncrypt:data key:key iv:nil mode:@"GCM" resolver:resolve rejecter:reject];
}

- (void)aesDecrypt:(NSString *)encryptedData key:(NSString *)key resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    [self aesDecrypt:encryptedData key:key iv:nil mode:@"GCM" resolver:resolve rejecter:reject];
}

- (void)generateRandomBytes:(NSInteger)length resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (length <= 0 || length > 1000000) {
        reject(ERR_INVALID_INPUT_CODE, @"Length must be between 1 and 1000000 bytes", nil);
        return;
    }
    NSMutableData *data = [NSMutableData dataWithLength:length];
    if (SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes) == errSecSuccess) {
        resolve([data base64EncodedStringWithOptions:0]);
    } else {
        reject(ERR_RANDOM_BYTES_CODE, @"Failed to generate random bytes", nil);
    }
}

- (void)generateSalt:(NSInteger)length resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (length <= 0 || length > 1000000) {
        reject(ERR_INVALID_INPUT_CODE, @"Length must be between 1 and 1000000 bytes", nil);
        return;
    }
    NSMutableData *data = [NSMutableData dataWithLength:length];
    if (SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes) == errSecSuccess) {
        resolve([data base64EncodedStringWithOptions:0]);
    } else {
        reject(ERR_SALT_GEN_CODE, @"Failed to generate salt", nil);
    }
}



- (void)base64Encode:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0) {
        reject(ERR_INVALID_INPUT_CODE, @"Input data cannot be empty", nil);
        return;
    }
    NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
    resolve([dataData base64EncodedStringWithOptions:0]);
}

- (void)base64Decode:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0) {
        reject(ERR_INVALID_INPUT_CODE, @"Input data cannot be empty", nil);
        return;
    }
    if (![self isValidBase64:data]) {
        reject(ERR_INVALID_BASE64_MSG, nil);
        return;
    }
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:data options:0];
    if (!decodedData) {
        reject(ERR_BASE64_DECODE_CODE, @"Failed to decode Base64 string", nil);
        return;
    }
    NSString *result = [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
    if (!result) {
        reject(ERR_BASE64_DECODE_CODE, @"Failed to decode data as UTF-8", nil);
        return;
    }
    resolve(result);
}

- (void)hexEncode:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0) {
        reject(ERR_INVALID_INPUT_CODE, @"Input data cannot be empty", nil);
        return;
    }
    NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
    const unsigned char *bytes = (const unsigned char *)[dataData bytes];
    NSMutableString *hex = [NSMutableString new];
    for (NSUInteger i = 0; i < dataData.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    resolve(hex);
}

- (void)hexDecode:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0 || data.length % 2 != 0) {
        reject(ERR_INVALID_INPUT_CODE, @"Invalid hex string", nil);
        return;
    }
    if (![self isValidHex:data]) {
        reject(ERR_INVALID_HEX_MSG, nil);
        return;
    }
    NSMutableData *stringData = [NSMutableData data];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    for (NSUInteger i = 0; i < data.length / 2; i++) {
        byte_chars[0] = [data characterAtIndex:i*2];
        byte_chars[1] = [data characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [stringData appendBytes:&whole_byte length:1];
    }
    NSString *result = [[NSString alloc] initWithData:stringData encoding:NSUTF8StringEncoding];
    if (!result) {
        reject(ERR_HEX_DECODE_CODE, @"Failed to decode hex data as UTF-8", nil);
        return;
    }
    resolve(result);
}

- (void)scrypt:(NSString *)password
           salt:(NSString *)salt
              N:(nonnull NSNumber *)N
              r:(nonnull NSNumber *)r
              p:(nonnull NSNumber *)p
         keyLen:(nonnull NSNumber *)keyLen
        resolver:(RCTPromiseResolveBlock)resolve
        rejecter:(RCTPromiseRejectBlock)reject {
    RUN_CRYPTO_ASYNC(^{
        if (password.length == 0 || salt.length == 0) {
            reject(ERR_INVALID_INPUT_CODE, @"Password and salt cannot be empty", nil);
            return;
        }
        NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
        NSData *saltData = [[NSData alloc] initWithBase64EncodedString:salt options:0];
        if (!saltData) {
            reject(ERR_INVALID_INPUT_CODE, @"Salt must be valid Base64", nil);
            return;
        }
        NSUInteger keyLenValue = [keyLen unsignedIntegerValue];
        NSMutableData *keyData = [NSMutableData dataWithLength:keyLenValue];
        if ([N unsignedLongLongValue] < 16384 || ([N unsignedLongLongValue] & ([N unsignedLongLongValue] - 1)) != 0) {
            reject(ERR_INVALID_INPUT_CODE, @"scrypt N must be a power of 2 and at least 16384", nil);
            return;
        }
        int result = libscrypt_scrypt(
            passwordData.bytes, passwordData.length,
            saltData.bytes, saltData.length,
            [N unsignedLongLongValue], [r unsignedIntValue], [p unsignedIntValue],
            keyData.mutableBytes, keyLenValue
        );
        if (result == 0) {
            resolve([keyData base64EncodedStringWithOptions:0]);
        } else {
            reject(ERR_SCRYPT_CODE, @"libscrypt_scrypt failed", nil);
        }
    });
}

- (void)verifyHash:(NSString *)data hash:(NSString *)hash algorithm:(NSString *)algorithm resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    RUN_CRYPTO_ASYNC(^{
        if (data.length == 0 || hash.length == 0) {
            reject(ERR_INVALID_INPUT_CODE, @"Data and hash cannot be empty", nil);
            return;
        }
        if (![self isValidBase64:hash]) {
            reject(ERR_INVALID_INPUT_CODE, @"Hash must be valid Base64", nil);
            return;
        }
        NSData *computedHashData = nil;
        if ([algorithm.uppercaseString isEqualToString:@"SHA256"]) {
            uint8_t digest[CC_SHA256_DIGEST_LENGTH];
            NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
            if (!dataData) {
                reject(ERR_UTF8_ENCODE_CODE, ERR_UTF8_ENCODE_MSG, nil);
                return;
            }
            CC_SHA256(dataData.bytes, (CC_LONG)dataData.length, digest);
            computedHashData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
        } else if ([algorithm.uppercaseString isEqualToString:@"SHA512"]) {
            uint8_t digest[CC_SHA512_DIGEST_LENGTH];
            NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
            if (!dataData) {
                reject(ERR_UTF8_ENCODE_CODE, ERR_UTF8_ENCODE_MSG, nil);
                return;
            }
            CC_SHA512(dataData.bytes, (CC_LONG)dataData.length, digest);
            computedHashData = [NSData dataWithBytes:digest length:CC_SHA512_DIGEST_LENGTH];
        } else {
            reject(ERR_UNSUPPORTED_ALGO_CODE, ERR_UNSUPPORTED_ALGO_MSG, nil);
            return;
        }
        NSData *providedHashData = [[NSData alloc] initWithBase64EncodedString:hash options:0];
        if (!providedHashData) {
            reject(ERR_INVALID_INPUT_CODE, @"Failed to decode base64 hash", nil);
            return;
        }
        if (computedHashData.length != providedHashData.length) {
            resolve(@(NO));
            return;
        }
        BOOL result = slow_equals(computedHashData.bytes, providedHashData.bytes, providedHashData.length) == 0;
        resolve(@(result));
    });
}

@end