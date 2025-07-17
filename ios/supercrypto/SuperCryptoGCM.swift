
import Foundation
import CryptoKit

@objc(SuperCryptoGCM)
public class SuperCryptoGCM: NSObject {

    @objc
    public static func generateNonce(withError error: NSErrorPointer) -> Data? {
        return AES.GCM.Nonce().withUnsafeBytes { Data(Array($0)) }
    }

    @objc
    public static func encrypt(_ data: Data, key: Data, iv: String?, error: NSErrorPointer) -> Data? {
        do {
            let symmetricKey = SymmetricKey(data: key)
            let nonceData: Data
            
            if let iv = iv, let ivData = Data(base64Encoded: iv) {
                nonceData = ivData
            } else {
                nonceData = AES.GCM.Nonce().withUnsafeBytes { Data(Array($0)) }
            }
            
            let aesNonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.seal(data, using: symmetricKey, nonce: aesNonce)
            
            // Return the combined representation of the sealed box
            return sealedBox.combined
        } catch let catchedError {
            error?.pointee = catchedError as NSError
            return nil
        }
    }

    @objc
    public static func encrypt(withData data: Data, key: Data, nonce: Data, error: NSErrorPointer) -> Data? {
        do {
            let symmetricKey = SymmetricKey(data: key)
            let aesNonce = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.seal(data, using: symmetricKey, nonce: aesNonce)
            return sealedBox.combined
        } catch let catchedError {
            error?.pointee = catchedError as NSError
            return nil
        }
    }

    @objc
    public static func decrypt(_ encryptedData: Data, key: Data, iv: Data, error: NSErrorPointer) -> Data? {
        do {
            let symmetricKey = SymmetricKey(data: key)
            let aesNonce = try AES.GCM.Nonce(data: iv)
            let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
            return decryptedData
        } catch let catchedError {
            error?.pointee = catchedError as NSError
            return nil
        }
    }

    @objc
    public static func decryptWithCombined(_ combinedData: Data, key: Data, error: NSErrorPointer) -> Data? {
        do {
            let symmetricKey = SymmetricKey(data: key)
            let sealedBox = try AES.GCM.SealedBox(combined: combinedData)
            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
            return decryptedData
        } catch let catchedError {
            error?.pointee = catchedError as NSError
            return nil
        }
    }
}
