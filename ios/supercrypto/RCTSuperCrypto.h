#import <Foundation/Foundation.h>
#import <SuperCryptoSpec/SuperCryptoSpec.h>

NS_ASSUME_NONNULL_BEGIN

@interface RCTSuperCrypto : NSObject <SuperCryptoSpec>

- (void)pbkdf2:(NSString *)password 
           salt:(NSString *)salt 
      iterations:(double)iterations 
          keyLen:(double)keyLen 
       algorithm:(NSString *)algorithm 
         resolve:(RCTPromiseResolveBlock)resolve 
          reject:(RCTPromiseRejectBlock)reject;

- (void)sha256:(NSString *)data 
       resolver:(RCTPromiseResolveBlock)resolve 
        rejecter:(RCTPromiseRejectBlock)reject;

- (void)sha512:(NSString *)data 
       resolver:(RCTPromiseResolveBlock)resolve 
        rejecter:(RCTPromiseRejectBlock)reject;

- (void)sha1:(NSString *)data 
     resolver:(RCTPromiseResolveBlock)resolve 
      rejecter:(RCTPromiseRejectBlock)reject;

- (void)hmacSha256:(NSString *)data 
                key:(NSString *)key 
           resolver:(RCTPromiseResolveBlock)resolve 
            rejecter:(RCTPromiseRejectBlock)reject;

- (void)hmacSha512:(NSString *)data 
                key:(NSString *)key 
           resolver:(RCTPromiseResolveBlock)resolve 
            rejecter:(RCTPromiseRejectBlock)reject;

- (void)aesEncrypt:(NSString *)data 
                key:(NSString *)key 
                   iv:(NSString *)iv 
                  mode:(NSString *)mode 
             resolver:(RCTPromiseResolveBlock)resolve 
              rejecter:(RCTPromiseRejectBlock)reject;

- (void)aesDecrypt:(NSString *)encryptedData 
                key:(NSString *)key 
                   iv:(NSString *)iv 
                  mode:(NSString *)mode 
             resolver:(RCTPromiseResolveBlock)resolve 
              rejecter:(RCTPromiseRejectBlock)reject;

- (void)generateRandomBytes:(NSInteger)length 
                  resolver:(RCTPromiseResolveBlock)resolve 
                   rejecter:(RCTPromiseRejectBlock)reject;

- (void)generateSalt:(NSInteger)length 
           resolver:(RCTPromiseResolveBlock)resolve 
            rejecter:(RCTPromiseRejectBlock)reject;

- (void)base64Encode:(NSString *)data 
            resolver:(RCTPromiseResolveBlock)resolve 
             rejecter:(RCTPromiseRejectBlock)reject;

- (void)base64Decode:(NSString *)data 
            resolver:(RCTPromiseResolveBlock)resolve 
             rejecter:(RCTPromiseRejectBlock)reject;

- (void)hexEncode:(NSString *)data 
         resolver:(RCTPromiseResolveBlock)resolve 
          rejecter:(RCTPromiseRejectBlock)reject;

- (void)hexDecode:(NSString *)data 
         resolver:(RCTPromiseResolveBlock)resolve 
          rejecter:(RCTPromiseRejectBlock)reject;

- (void)scrypt:(NSString *)password
           salt:(NSString *)salt
              N:(nonnull NSNumber *)N
              r:(nonnull NSNumber *)r
              p:(nonnull NSNumber *)p
         keyLen:(nonnull NSNumber *)keyLen
        resolver:(RCTPromiseResolveBlock)resolve
        rejecter:(RCTPromiseRejectBlock)reject;

- (void)verifyHash:(NSString *)data 
              hash:(NSString *)hash 
         algorithm:(NSString *)algorithm 
          resolver:(RCTPromiseResolveBlock)resolve 
           rejecter:(RCTPromiseRejectBlock)reject;

@end

NS_ASSUME_NONNULL_END 