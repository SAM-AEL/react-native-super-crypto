#import "RCTSuperCrypto.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import "crypto_scrypt.h"
#import "SuperCryptoGCM.swift.h"
#import "libscrypt.h"
#import "slowequals.h"

@implementation SuperCrypto

// Helper validation methods
- (BOOL)isValidBase64:(NSString *)input {
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^[A-Za-z0-9+/=]*$" options:0 error:nil];
    NSUInteger matches = [regex numberOfMatchesInString:input options:0 range:NSMakeRange(0, input.length)];
    return matches > 0 && [[NSData alloc] initWithBase64EncodedString:input options:0] != nil;
}
- (BOOL)isValidHex:(NSString *)input {
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"^[0-9a-fA-F]*$" options:0 error:nil];
    NSUInteger matches = [regex numberOfMatchesInString:input options:0 range:NSMakeRange(0, input.length)];
    return matches > 0;
}

- (void)pbkdf2:(NSString *)password salt:(NSString *)salt iterations:(double)iterations keyLen:(double)keyLen algorithm:(NSString *)algorithm resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject {
    if (password.length == 0 || salt.length == 0) {
        reject(@"INVALID_INPUT", @"Password and salt cannot be empty", nil);
        return;
    }
    if (![self isValidBase64:salt]) {
        reject(@"INVALID_INPUT", @"Salt must be valid Base64", nil);
        return;
    }
    if (iterations < 1) {
        reject(@"INVALID_INPUT", @"Iterations must be a positive number", nil);
        return;
    }
    if (keyLen < 1 || keyLen > 512) {
        reject(@"INVALID_INPUT", @"Key length must be between 1 and 512 bytes", nil);
        return;
    }
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSData *saltData = [[NSData alloc] initWithBase64EncodedString:salt options:0];
    uint32_t prf = kCCPRFHmacAlgSHA256;
    if ([algorithm.uppercaseString isEqualToString:@"SHA512"]) {
        prf = kCCPRFHmacAlgSHA512;
    } else if (![algorithm.uppercaseString isEqualToString:@"SHA256"]) {
        reject(@"UNSUPPORTED_ALGORITHM", @"Unsupported hash algorithm", nil);
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
        reject(@"PBKDF2_ERROR", [NSString stringWithFormat:@"PBKDF2 failed with error code %d", result], nil);
    }
}

- (void)sha256:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0) {
        reject(@"INVALID_INPUT", @"Input data cannot be empty", nil);
        return;
    }
    NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(dataData.bytes, (CC_LONG)dataData.length, digest);
    NSData *hash = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    resolve([hash base64EncodedStringWithOptions:0]);
}

- (void)sha512:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0) {
        reject(@"INVALID_INPUT", @"Input data cannot be empty", nil);
        return;
    }
    NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t digest[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(dataData.bytes, (CC_LONG)dataData.length, digest);
    NSData *hash = [NSData dataWithBytes:digest length:CC_SHA512_DIGEST_LENGTH];
    resolve([hash base64EncodedStringWithOptions:0]);
}

- (void)sha1:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    reject(@"DEPRECATED_FUNCTION", @"SHA1 is deprecated and should not be used for security purposes", nil);
}

- (void)hmacSha256:(NSString *)data key:(NSString *)key resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0 || key.length == 0) {
        reject(@"INVALID_INPUT", @"Data and key cannot be empty", nil);
        return;
    }
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, keyData.bytes, keyData.length, dataData.bytes, dataData.length, cHMAC);
    NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    resolve([HMAC base64EncodedStringWithOptions:0]);
}

- (void)hmacSha512:(NSString *)data key:(NSString *)key resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0 || key.length == 0) {
        reject(@"INVALID_INPUT", @"Data and key cannot be empty", nil);
        return;
    }
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t cHMAC[CC_SHA512_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA512, keyData.bytes, keyData.length, dataData.bytes, dataData.length, cHMAC);
    NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    resolve([HMAC base64EncodedStringWithOptions:0]);
}

- (void)aesEncrypt:(NSString *)data key:(NSString *)key iv:(NSString *)iv mode:(NSString *)mode resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0 || key.length == 0 || mode.length == 0) {
        reject(@"INVALID_INPUT", @"Data, key, and mode cannot be empty", nil);
        return;
    }
    if (![self isValidBase64:key]) {
        reject(@"INVALID_INPUT", @"Key must be valid Base64", nil);
        return;
    }
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
    if (keyData.length != 16 && keyData.length != 24 && keyData.length != 32) {
        reject(@"INVALID_KEY", @"Key must be 16, 24, or 32 bytes for AES", nil);
        return;
    }
    NSString *modeUpper = [mode uppercaseString];
    if ([modeUpper isEqualToString:@"GCM"]) {
        NSData *ivData;
        if (iv == nil || iv.length == 0) {
            NSMutableData *randomIv = [NSMutableData dataWithLength:12];
            SecRandomCopyBytes(kSecRandomDefault, 12, randomIv.mutableBytes);
            ivData = randomIv;
        } else {
            if (![self isValidBase64:iv]) {
                reject(@"INVALID_INPUT", @"IV must be valid Base64", nil);
                return;
            }
            ivData = [[NSData alloc] initWithBase64EncodedString:iv options:0];
            if (ivData.length != 12) {
                reject(@"INVALID_IV", @"IV must be 12 bytes for AES-GCM", nil);
                return;
            }
        }
        NSError *error = nil;
        NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
        NSData *encryptedData = [SuperCryptoGCM encrypt:dataData key:keyData iv:[ivData base64EncodedStringWithOptions:0] error:&error];
        if (error) {
            reject(@"AES_ENCRYPT_ERROR", [NSString stringWithFormat:@"AES-GCM encryption failed: %@", error.localizedDescription], error);
            return;
        }
        resolve([encryptedData base64EncodedStringWithOptions:0]);
    } else if ([modeUpper isEqualToString:@"CBC"]) {
        NSData *ivData;
        if (iv == nil || iv.length == 0) {
            NSMutableData *randomIv = [NSMutableData dataWithLength:16];
            SecRandomCopyBytes(kSecRandomDefault, 16, randomIv.mutableBytes);
            ivData = randomIv;
        } else {
            if (![self isValidBase64:iv]) {
                reject(@"INVALID_INPUT", @"IV must be valid Base64", nil);
                return;
            }
            ivData = [[NSData alloc] initWithBase64EncodedString:iv options:0];
            if (ivData.length != 16) {
                reject(@"INVALID_IV", @"IV must be 16 bytes for AES-CBC", nil);
                return;
            }
        }
        NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
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
            reject(@"AES_ENCRYPT_ERROR", [NSString stringWithFormat:@"AES-CBC encryption failed: %d", result], nil);
        }
    } else {
        reject(@"UNSUPPORTED_MODE", @"Only GCM and CBC modes are supported", nil);
    }
}

- (void)aesDecrypt:(NSString *)encryptedData key:(NSString *)key iv:(NSString *)iv mode:(NSString *)mode resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (encryptedData.length == 0 || key.length == 0 || mode.length == 0) {
        reject(@"INVALID_INPUT", @"Encrypted data, key, and mode cannot be empty", nil);
        return;
    }
    if (![self isValidBase64:key] || ![self isValidBase64:encryptedData]) {
        reject(@"INVALID_INPUT", @"Key and encrypted data must be valid Base64", nil);
        return;
    }
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
    if (keyData.length != 16 && keyData.length != 24 && keyData.length != 32) {
        reject(@"INVALID_KEY", @"Key must be 16, 24, or 32 bytes for AES", nil);
        return;
    }
    NSData *encryptedDataData = [[NSData alloc] initWithBase64EncodedString:encryptedData options:0];
    NSString *modeUpper = [mode uppercaseString];
    if ([modeUpper isEqualToString:@"GCM"]) {
        NSData *ivData;
        NSData *cipherData;
        if (iv == nil || iv.length == 0) {
            if (encryptedDataData.length < 12) {
                reject(@"INVALID_INPUT", @"Encrypted data too short to contain IV", nil);
                return;
            }
            ivData = [encryptedDataData subdataWithRange:NSMakeRange(0, 12)];
            cipherData = [encryptedDataData subdataWithRange:NSMakeRange(12, encryptedDataData.length - 12)];
        } else {
            if (![self isValidBase64:iv]) {
                reject(@"INVALID_INPUT", @"IV must be valid Base64", nil);
                return;
            }
            ivData = [[NSData alloc] initWithBase64EncodedString:iv options:0];
            if (ivData.length != 12) {
                reject(@"INVALID_IV", @"IV must be 12 bytes for AES-GCM", nil);
                return;
            }
            cipherData = encryptedDataData;
        }
        NSError *error = nil;
        NSData *decryptedData = [SuperCryptoGCM decrypt:cipherData key:keyData iv:ivData error:&error];
        if (error) {
            reject(@"AES_DECRYPT_ERROR", [NSString stringWithFormat:@"AES-GCM decryption failed: %@", error.localizedDescription], error);
            return;
        }
        NSString *result = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
        if (!result) {
            reject(@"AES_DECRYPT_ERROR", @"Failed to decode decrypted data as UTF-8", nil);
            return;
        }
        resolve(result);
    } else if ([modeUpper isEqualToString:@"CBC"]) {
        NSData *ivData;
        NSData *cipherData;
        if (iv == nil || iv.length == 0) {
            if (encryptedDataData.length < 16) {
                reject(@"INVALID_INPUT", @"Encrypted data too short to contain IV", nil);
                return;
            }
            ivData = [encryptedDataData subdataWithRange:NSMakeRange(0, 16)];
            cipherData = [encryptedDataData subdataWithRange:NSMakeRange(16, encryptedDataData.length - 16)];
        } else {
            if (![self isValidBase64:iv]) {
                reject(@"INVALID_INPUT", @"IV must be valid Base64", nil);
                return;
            }
            ivData = [[NSData alloc] initWithBase64EncodedString:iv options:0];
            if (ivData.length != 16) {
                reject(@"INVALID_IV", @"IV must be 16 bytes for AES-CBC", nil);
                return;
            }
            cipherData = encryptedDataData;
        }
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
                reject(@"AES_DECRYPT_ERROR", @"Failed to decode decrypted data as UTF-8", nil);
                return;
            }
            resolve(resultStr);
        } else {
            reject(@"AES_DECRYPT_ERROR", [NSString stringWithFormat:@"AES-CBC decryption failed: %d", result], nil);
        }
    } else {
        reject(@"UNSUPPORTED_MODE", @"Only GCM and CBC modes are supported", nil);
    }
}

// Patch: Add method forwarding to allow aesEncrypt and aesDecrypt to be called with or without iv
- (void)aesEncrypt:(NSString *)data key:(NSString *)key resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    [self aesEncrypt:data key:key iv:nil mode:@"GCM" resolver:resolve rejecter:reject];
}

- (void)aesDecrypt:(NSString *)encryptedData key:(NSString *)key resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    [self aesDecrypt:encryptedData key:key iv:nil mode:@"GCM" resolver:resolve rejecter:reject];
}

- (void)generateRandomBytes:(NSInteger)length resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (length <= 0 || length > 1000000) {
        reject(@"INVALID_INPUT", @"Length must be between 1 and 1000000 bytes", nil);
        return;
    }
    NSMutableData *data = [NSMutableData dataWithLength:length];
    if (SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes) == errSecSuccess) {
        resolve([data base64EncodedStringWithOptions:0]);
    } else {
        reject(@"RANDOM_BYTES_ERROR", @"Failed to generate random bytes", nil);
    }
}

- (void)generateSalt:(double)length resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (length <= 0 || length > 1000000) {
        reject(@"INVALID_INPUT", @"Length must be between 1 and 1000000 bytes", nil);
        return;
    }
    NSInteger intLength = (NSInteger)length;
    NSMutableData *data = [NSMutableData dataWithLength:intLength];
    if (SecRandomCopyBytes(kSecRandomDefault, intLength, data.mutableBytes) == errSecSuccess) {
        resolve([data base64EncodedStringWithOptions:0]);
    } else {
        reject(@"SALT_GENERATION_ERROR", @"Failed to generate salt", nil);
    }
}



- (void)base64Encode:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0) {
        reject(@"INVALID_INPUT", @"Input data cannot be empty", nil);
        return;
    }
    NSData *dataData = [data dataUsingEncoding:NSUTF8StringEncoding];
    resolve([dataData base64EncodedStringWithOptions:0]);
}

- (void)base64Decode:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0) {
        reject(@"INVALID_INPUT", @"Input data cannot be empty", nil);
        return;
    }
    if (![self isValidBase64:data]) {
        reject(@"INVALID_INPUT", @"Invalid Base64 string", nil);
        return;
    }
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:data options:0];
    if (!decodedData) {
        reject(@"BASE64_DECODE_ERROR", @"Failed to decode Base64 string", nil);
        return;
    }
    NSString *result = [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
    if (!result) {
        reject(@"BASE64_DECODE_ERROR", @"Failed to decode data as UTF-8", nil);
        return;
    }
    resolve(result);
}

- (void)hexEncode:(NSString *)data resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0) {
        reject(@"INVALID_INPUT", @"Input data cannot be empty", nil);
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
        reject(@"INVALID_INPUT", @"Invalid hex string", nil);
        return;
    }
    if (![self isValidHex:data]) {
        reject(@"INVALID_INPUT", @"Invalid hex characters detected", nil);
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
        reject(@"HEX_DECODE_ERROR", @"Failed to decode hex data as UTF-8", nil);
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
    if (password.length == 0 || salt.length == 0) {
        reject(@"INVALID_INPUT", @"Password and salt cannot be empty", nil);
        return;
    }
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSData *saltData = [[NSData alloc] initWithBase64EncodedString:salt options:0];
    if (!saltData) {
        reject(@"INVALID_INPUT", @"Salt must be valid Base64", nil);
        return;
    }
    NSUInteger keyLenValue = [keyLen unsignedIntegerValue];
    NSMutableData *keyData = [NSMutableData dataWithLength:keyLenValue];
    if ([N unsignedLongLongValue] < 16384 || ([N unsignedLongLongValue] & ([N unsignedLongLongValue] - 1)) != 0) {
        reject(@"INVALID_INPUT", @"scrypt N must be a power of 2 and at least 16384", nil);
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
        reject(@"SCRYPT_ERROR", @"libscrypt_scrypt failed", nil);
    }
}

- (void)verifyHash:(NSString *)data hash:(NSString *)hash algorithm:(NSString *)algorithm resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject {
    if (data.length == 0 || hash.length == 0) {
        reject(@"INVALID_INPUT", @"Data and hash cannot be empty", nil);
        return;
    }
    if (![self isValidBase64:hash]) {
        reject(@"INVALID_INPUT", @"Hash must be valid Base64", nil);
        return;
    }

    void (^compareBlock)(NSString *) = ^(NSString *computedHash) {
        NSData *computedHashData = [[NSData alloc] initWithBase64EncodedString:computedHash options:0];
        NSData *providedHashData = [[NSData alloc] initWithBase64EncodedString:hash options:0];
        
        if (computedHashData.length != providedHashData.length) {
            resolve(@(NO));
            return;
        }
        
        BOOL result = slow_equals(computedHashData.bytes, providedHashData.bytes, providedHashData.length) == 0;
        resolve(@(result));
    };

    if ([algorithm.uppercaseString isEqualToString:@"SHA256"]) {
        [self sha256:data resolver:compareBlock rejecter:reject];
    } else if ([algorithm.uppercaseString isEqualToString:@"SHA512"]) {
        [self sha512:data resolver:compareBlock rejecter:reject];
    } else {
        reject(@"UNSUPPORTED_ALGORITHM", @"Unsupported hash algorithm", nil);
    }
}

@end