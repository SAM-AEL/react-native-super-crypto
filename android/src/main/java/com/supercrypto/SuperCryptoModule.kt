package com.supercrypto

import android.util.Base64
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactMethod
import com.supercrypto.NativeSuperCryptoSpec
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.security.NoSuchAlgorithmException
import java.security.InvalidKeyException

class SuperCryptoModule(reactContext: ReactApplicationContext) :
    NativeSuperCryptoSpec(reactContext) {

    init {
        // Add BouncyCastle provider for scrypt support
        Security.addProvider(BouncyCastleProvider())
    }

    override fun getName() = NAME

    /**
     * Validates if the input string is valid Base64.
     */
    private fun isValidBase64(input: String): Boolean {
        return try {
            Base64.decode(input, Base64.NO_WRAP)
            true
        } catch (e: IllegalArgumentException) {
            false
        }
    }

    /**
     * Validates if the input string is valid hexadecimal.
     */
    private fun isValidHex(input: String): Boolean {
        return input.matches(Regex("^[0-9a-fA-F]+$"))
    }

    @ReactMethod
    override fun pbkdf2(
        password: String,
        salt: String,
        iterations: Double,
        keyLen: Double,
        algorithm: String,
        promise: Promise
    ) {
        try {
            if (password.isEmpty() || salt.isEmpty()) {
                promise.reject("INVALID_INPUT", "Password and salt cannot be empty")
                return
            }
            if (!isValidBase64(salt)) {
                promise.reject("INVALID_INPUT", "Salt must be valid Base64")
                return
            }
            if (iterations < 1) {
                promise.reject("INVALID_INPUT", "Iterations must be a positive number")
                return
            }
            if (keyLen < 1 || keyLen > 512) {
                promise.reject("INVALID_INPUT", "Key length must be between 1 and 512 bytes")
                return
            }

            val hashAlgorithm =
                when (algorithm.uppercase()) {
                    "SHA256" -> "PBKDF2WithHmacSHA256"
                    "SHA512" -> "PBKDF2WithHmacSHA512"
                    else -> {
                        promise.reject("UNSUPPORTED_ALGORITHM", "Unsupported hash algorithm")
                        return
                    }
                }

            val spec =
                PBEKeySpec(
                    password.toCharArray(),
                    Base64.decode(salt, Base64.NO_WRAP),
                    iterations.toInt(),
                    keyLen.toInt() * 8
                )
            val factory = SecretKeyFactory.getInstance(hashAlgorithm)
            val hash = factory.generateSecret(spec).encoded
            promise.resolve(Base64.encodeToString(hash, Base64.NO_WRAP))
        } catch (e: NoSuchAlgorithmException) {
            promise.reject("ALGORITHM_ERROR", "Unsupported algorithm: $algorithm")
        } catch (e: Exception) {
            promise.reject("PBKDF2_ERROR", "An error occurred during PBKDF2 execution: ${e.message}")
        }
    }

    private fun sha256(data: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(data.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    private fun sha512(data: String): String {
        val digest = MessageDigest.getInstance("SHA-512")
        val hash = digest.digest(data.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    @ReactMethod
    override fun sha256(data: String, promise: Promise) {
        try {
            if (data.isEmpty()) {
                promise.reject("INVALID_INPUT", "Input data cannot be empty")
                return
            }
            promise.resolve(sha256(data))
        } catch (e: NoSuchAlgorithmException) {
            promise.reject("SHA256_ERROR", "SHA-256 algorithm not available")
        } catch (e: Exception) {
            promise.reject("SHA256_ERROR", "An error occurred during SHA256 hashing: ${e.message}")
        }
    }

    @ReactMethod
    override fun sha512(data: String, promise: Promise) {
        try {
            if (data.isEmpty()) {
                promise.reject("INVALID_INPUT", "Input data cannot be empty")
                return
            }
            promise.resolve(sha512(data))
        } catch (e: NoSuchAlgorithmException) {
            promise.reject("SHA512_ERROR", "SHA-512 algorithm not available")
        } catch (e: Exception) {
            promise.reject("SHA512_ERROR", "An error occurred during SHA512 hashing: ${e.message}")
        }
    }

    @ReactMethod
    override fun sha1(data: String, promise: Promise) {
        promise.reject(
            "DEPRECATED_FUNCTION",
            "SHA1 is deprecated and should not be used for security purposes"
        )
    }

    @ReactMethod
    override fun hmacSha256(data: String, key: String, promise: Promise) {
        try {
            if (data.isEmpty() || key.isEmpty()) {
                promise.reject("INVALID_INPUT", "Data and key cannot be empty")
                return
            }
            val mac = Mac.getInstance("HmacSHA256")
            val secretKeySpec =
                SecretKeySpec(key.toByteArray(StandardCharsets.UTF_8), "HmacSHA256")
            mac.init(secretKeySpec)
            val hash = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
            promise.resolve(Base64.encodeToString(hash, Base64.NO_WRAP))
        } catch (e: NoSuchAlgorithmException) {
            promise.reject("HMAC_SHA256_ERROR", "HMAC-SHA256 algorithm not available")
        } catch (e: Exception) {
            promise.reject("HMAC_SHA256_ERROR", "An error occurred during HMAC-SHA256 execution: ${e.message}")
        }
    }

    @ReactMethod
    override fun hmacSha512(data: String, key: String, promise: Promise) {
        try {
            if (data.isEmpty() || key.isEmpty()) {
                promise.reject("INVALID_INPUT", "Data and key cannot be empty")
                return
            }
            val mac = Mac.getInstance("HmacSHA512")
            val secretKeySpec =
                SecretKeySpec(key.toByteArray(StandardCharsets.UTF_8), "HmacSHA512")
            mac.init(secretKeySpec)
            val hash = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
            promise.resolve(Base64.encodeToString(hash, Base64.NO_WRAP))
        } catch (e: NoSuchAlgorithmException) {
            promise.reject("HMAC_SHA512_ERROR", "HMAC-SHA512 algorithm not available")
        } catch (e: Exception) {
            promise.reject("HMAC_SHA512_ERROR", "An error occurred during HMAC-SHA512 execution: ${e.message}")
        }
    }

    @ReactMethod
    override fun aesEncrypt(data: String, key: String, iv: String?, mode: String, promise: Promise) {
        try {
            if (data.isEmpty() || key.isEmpty() || mode.isEmpty()) {
                promise.reject("INVALID_INPUT", "Data, key, and mode cannot be empty")
                return
            }
            if (!isValidBase64(key)) {
                promise.reject("INVALID_INPUT", "Key must be valid Base64")
                return
            }
            val keyBytes = Base64.decode(key, Base64.NO_WRAP)
            if (keyBytes.size !in listOf(16, 24, 32)) {
                promise.reject("INVALID_KEY", "Key must be 16, 24, or 32 bytes for AES")
                return
            }
            val modeUpper = mode.uppercase()
            val cipher: Cipher
            val ivBytes: ByteArray
            when (modeUpper) {
                "GCM" -> {
                    cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    if (iv.isNullOrEmpty()) {
                        val random = SecureRandom()
                        ivBytes = ByteArray(12)
                        random.nextBytes(ivBytes)
                    } else {
                        if (!isValidBase64(iv)) {
                            promise.reject("INVALID_INPUT", "IV must be valid Base64")
                            return
                        }
                        ivBytes = Base64.decode(iv, Base64.NO_WRAP)
                        if (ivBytes.size != 12) {
                            promise.reject("INVALID_IV", "IV must be 12 bytes for AES-GCM")
                            return
                        }
                    }
                    val keySpec = SecretKeySpec(keyBytes, "AES")
                    val ivSpec = GCMParameterSpec(128, ivBytes)
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
                    val dataBytes = data.toByteArray(StandardCharsets.UTF_8)
                    val encryptedBytes = cipher.doFinal(dataBytes)
                    val combined = ivBytes + encryptedBytes
                    promise.resolve(Base64.encodeToString(combined, Base64.NO_WRAP))
                }
                "CBC" -> {
                    cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
                    if (iv.isNullOrEmpty()) {
                        val random = SecureRandom()
                        ivBytes = ByteArray(16)
                        random.nextBytes(ivBytes)
                    } else {
                        if (!isValidBase64(iv)) {
                            promise.reject("INVALID_INPUT", "IV must be valid Base64")
                            return
                        }
                        ivBytes = Base64.decode(iv, Base64.NO_WRAP)
                        if (ivBytes.size != 16) {
                            promise.reject("INVALID_IV", "IV must be 16 bytes for AES-CBC")
                            return
                        }
                    }
                    val keySpec = SecretKeySpec(keyBytes, "AES")
                    val ivSpec = IvParameterSpec(ivBytes)
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
                    val dataBytes = data.toByteArray(StandardCharsets.UTF_8)
                    val encryptedBytes = cipher.doFinal(dataBytes)
                    val combined = ivBytes + encryptedBytes
                    promise.resolve(Base64.encodeToString(combined, Base64.NO_WRAP))
                }
                else -> {
                    promise.reject("UNSUPPORTED_MODE", "Only GCM and CBC modes are supported")
                    return
                }
            }
        } catch (e: Exception) {
            promise.reject("AES_ENCRYPT_ERROR", "An error occurred during AES encryption: ${e.message}")
        }
    }

    @ReactMethod
    override fun aesDecrypt(encryptedData: String, key: String, iv: String?, mode: String, promise: Promise) {
        try {
            if (encryptedData.isEmpty() || key.isEmpty() || mode.isEmpty()) {
                promise.reject("INVALID_INPUT", "Encrypted data, key, and mode cannot be empty")
                return
            }
            if (!isValidBase64(key) || !isValidBase64(encryptedData)) {
                promise.reject("INVALID_INPUT", "Key and encrypted data must be valid Base64")
                return
            }
            val keyBytes = Base64.decode(key, Base64.NO_WRAP)
            if (keyBytes.size !in listOf(16, 24, 32)) {
                promise.reject("INVALID_KEY", "Key must be 16, 24, or 32 bytes for AES")
                return
            }
            val modeUpper = mode.uppercase()
            val cipher: Cipher
            val ivBytes: ByteArray
            val encryptedDataBytes: ByteArray
            when (modeUpper) {
                "GCM" -> {
                    cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    if (iv.isNullOrEmpty()) {
                        val combined = Base64.decode(encryptedData, Base64.NO_WRAP)
                        if (combined.size < 12) {
                            promise.reject("INVALID_INPUT", "Encrypted data too short to contain IV")
                            return
                        }
                        ivBytes = combined.copyOfRange(0, 12)
                        encryptedDataBytes = combined.copyOfRange(12, combined.size)
                    } else {
                        if (!isValidBase64(iv)) {
                            promise.reject("INVALID_INPUT", "IV must be valid Base64")
                            return
                        }
                        ivBytes = Base64.decode(iv, Base64.NO_WRAP)
                        if (ivBytes.size != 12) {
                            promise.reject("INVALID_IV", "IV must be 12 bytes for AES-GCM")
                            return
                        }
                        encryptedDataBytes = Base64.decode(encryptedData, Base64.NO_WRAP)
                    }
                    val keySpec = SecretKeySpec(keyBytes, "AES")
                    val ivSpec = GCMParameterSpec(128, ivBytes)
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
                    val decryptedBytes = cipher.doFinal(encryptedDataBytes)
                    val decryptedString = String(decryptedBytes, StandardCharsets.UTF_8)
                    promise.resolve(decryptedString)
                }
                "CBC" -> {
                    cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
                    if (iv.isNullOrEmpty()) {
                        val combined = Base64.decode(encryptedData, Base64.NO_WRAP)
                        if (combined.size < 16) {
                            promise.reject("INVALID_INPUT", "Encrypted data too short to contain IV")
                            return
                        }
                        ivBytes = combined.copyOfRange(0, 16)
                        encryptedDataBytes = combined.copyOfRange(16, combined.size)
                    } else {
                        if (!isValidBase64(iv)) {
                            promise.reject("INVALID_INPUT", "IV must be valid Base64")
                            return
                        }
                        ivBytes = Base64.decode(iv, Base64.NO_WRAP)
                        if (ivBytes.size != 16) {
                            promise.reject("INVALID_IV", "IV must be 16 bytes for AES-CBC")
                            return
                        }
                        encryptedDataBytes = Base64.decode(encryptedData, Base64.NO_WRAP)
                    }
                    val keySpec = SecretKeySpec(keyBytes, "AES")
                    val ivSpec = IvParameterSpec(ivBytes)
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
                    val decryptedBytes = cipher.doFinal(encryptedDataBytes)
                    val decryptedString = String(decryptedBytes, StandardCharsets.UTF_8)
                    promise.resolve(decryptedString)
                }
                else -> {
                    promise.reject("UNSUPPORTED_MODE", "Only GCM and CBC modes are supported")
                    return
                }
            }
        } catch (e: Exception) {
            promise.reject("AES_DECRYPT_ERROR", "An error occurred during AES decryption: ${e.message}")
        }
    }

    @ReactMethod
    override fun generateRandomBytes(length: Double, promise: Promise) {
        if (length % 1 != 0.0 || length <= 0) {
            promise.reject("INVALID_INPUT", "Length must be a positive integer")
                return
            }
        val intLength = length.toInt()
        if (intLength > 1_000_000) {
                promise.reject("INVALID_INPUT", "Requested length exceeds maximum allowed (1MB)")
                return
            }
        try {
            val random = SecureRandom()
            val bytes = ByteArray(intLength)
            random.nextBytes(bytes)
            promise.resolve(Base64.encodeToString(bytes, Base64.NO_WRAP))
        } catch (e: Exception) {
            promise.reject("RANDOM_BYTES_ERROR", "An error occurred while generating random bytes: ${e.message}")
        }
    }

    

    @ReactMethod
    override fun base64Encode(data: String, promise: Promise) {
        try {
            if (data.isEmpty()) {
                promise.reject("INVALID_INPUT", "Input data cannot be empty")
                return
            }
            promise.resolve(
                Base64.encodeToString(
                    data.toByteArray(StandardCharsets.UTF_8),
                    Base64.NO_WRAP
                )
            )
        } catch (e: Exception) {
            promise.reject("BASE64_ENCODE_ERROR", "An error occurred during Base64 encoding: ${e.message}")
        }
    }

    @ReactMethod
    override fun base64Decode(data: String, promise: Promise) {
        try {
            if (data.isEmpty()) {
                promise.reject("INVALID_INPUT", "Input data cannot be empty")
                return
            }
            if (!isValidBase64(data)) {
                promise.reject("INVALID_INPUT", "Input must be valid Base64")
                return
            }
            val decoded = Base64.decode(data, Base64.NO_WRAP)
            promise.resolve(String(decoded, StandardCharsets.UTF_8))
        } catch (e: IllegalArgumentException) {
            promise.reject("BASE64_DECODE_ERROR", "Invalid Base64 input")
        } catch (e: Exception) {
            promise.reject("BASE64_DECODE_ERROR", "An error occurred during Base64 decoding: ${e.message}")
        }
    }

    @ReactMethod
    override fun hexEncode(data: String, promise: Promise) {
        try {
            if (data.isEmpty()) {
                promise.reject("INVALID_INPUT", "Input data cannot be empty")
                return
            }
            val bytes = data.toByteArray(StandardCharsets.UTF_8)
            val hexChars = CharArray(bytes.size * 2)
            for (i in bytes.indices) {
                val v = bytes[i].toInt() and 0xFF
                hexChars[i * 2] = "0123456789abcdef"[v ushr 4]
                hexChars[i * 2 + 1] = "0123456789abcdef"[v and 0x0F]
            }
            promise.resolve(String(hexChars))
        } catch (e: Exception) {
            promise.reject("HEX_ENCODE_ERROR", "An error occurred during hex encoding: ${e.message}")
        }
    }

    @ReactMethod
    override fun hexDecode(data: String, promise: Promise) {
        try {
            if (data.isEmpty() || data.length % 2 != 0) {
                promise.reject("INVALID_INPUT", "Invalid hex string")
                return
            }
            if (!isValidHex(data)) {
                promise.reject("INVALID_INPUT", "Input must be a valid hex string")
                return
            }
            val len = data.length
            val bytes = ByteArray(len / 2)
            for (i in 0 until len step 2) {
                bytes[i / 2] =
                    ((Character.digit(data[i], 16) shl 4) +
                            Character.digit(data[i + 1], 16))
                        .toByte()
            }
            promise.resolve(String(bytes, StandardCharsets.UTF_8))
        } catch (e: Exception) {
            promise.reject("HEX_DECODE_ERROR", "An error occurred during hex decoding: ${e.message}")
        }
    }

    @ReactMethod
    override fun generateSalt(length: Double, promise: Promise) {
        if (length % 1 != 0.0 || length <= 0) {
            promise.reject("INVALID_INPUT", "Length must be a positive integer")
                return
            }
        val intLength = length.toInt()
        if (intLength > 1_000_000) {
                promise.reject("INVALID_INPUT", "Requested length exceeds maximum allowed (1MB)")
                return
            }
        try {
            val random = SecureRandom()
            val bytes = ByteArray(intLength)
            random.nextBytes(bytes)
            promise.resolve(Base64.encodeToString(bytes, Base64.NO_WRAP))
        } catch (e: Exception) {
            promise.reject("SALT_GENERATION_ERROR", "An error occurred while generating salt: ${e.message}")
        }
    }

    @ReactMethod
    override fun scrypt(
        password: String,
        salt: String,
        n: Double,
        r: Double,
        p: Double,
        keyLen: Double,
        promise: Promise
    ) {
        try {
            if (password.isEmpty() || salt.isEmpty()) {
                promise.reject("INVALID_INPUT", "Password and salt cannot be empty")
                return
            }
            if (!isValidBase64(salt)) {
                promise.reject("INVALID_INPUT", "Salt must be valid Base64")
                return
            }
            if (n < 65536 || n > 1048576 || n.toInt() and (n.toInt() - 1) != 0) {
                promise.reject("INVALID_INPUT", "scrypt n must be a power of 2 between 65536 and 1048576")
                return
            }
            if (r < 8 || r > 32) {
                promise.reject("INVALID_INPUT", "scrypt r must be between 8 and 32")
                return
            }
            if (p < 1) {
                promise.reject("INVALID_INPUT", "scrypt p must be positive")
                return
            }
            if (keyLen < 1) {
                promise.reject("INVALID_INPUT", "Key length must be positive")
                return
            }

            val passwordBytes = password.toByteArray(StandardCharsets.UTF_8)
            val saltBytes = Base64.decode(salt, Base64.NO_WRAP)
            val key =
                org.bouncycastle.crypto.generators.SCrypt.generate(
                    passwordBytes,
                    saltBytes,
                    n.toInt(),
                    r.toInt(),
                    p.toInt(),
                    keyLen.toInt()
                )
            promise.resolve(Base64.encodeToString(key, Base64.NO_WRAP))
        } catch (e: OutOfMemoryError) {
            promise.reject("SCRYPT_ERROR", "scrypt parameters too large for device memory")
        } catch (e: Exception) {
            promise.reject("SCRYPT_ERROR", "An error occurred during scrypt execution: ${e.message}")
        }
    }

    @ReactMethod
    override fun verifyHash(data: String, hash: String, algorithm: String, promise: Promise) {
        try {
            if (data.isEmpty() || hash.isEmpty()) {
                promise.reject("INVALID_INPUT", "Data and hash cannot be empty")
                return
            }
            if (!isValidBase64(hash)) {
                promise.reject("INVALID_INPUT", "Hash must be valid Base64")
                return
            }
            val computedHash = when (algorithm.uppercase()) {
                "SHA256" -> sha256(data)
                "SHA512" -> sha512(data)
                else -> {
                    promise.reject("UNSUPPORTED_ALGORITHM", "Unsupported hash algorithm")
                    return
                }
            }
            val computedHashBytes = Base64.decode(computedHash, Base64.NO_WRAP)
            val hashBytes = Base64.decode(hash, Base64.NO_WRAP)

            promise.resolve(MessageDigest.isEqual(computedHashBytes, hashBytes))
        } catch (e: NoSuchAlgorithmException) {
            promise.reject("VERIFY_HASH_ERROR", "Unsupported algorithm: $algorithm")
        } catch (e: Exception) {
            promise.reject("VERIFY_HASH_ERROR", "An error occurred during hash verification: ${e.message}")
        }
    }

    companion object {
        const val NAME = "SuperCrypto"
    }
}