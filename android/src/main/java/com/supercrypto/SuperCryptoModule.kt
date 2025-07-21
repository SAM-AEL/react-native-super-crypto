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
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

// Error code and message constants
private object Errors {
    const val INVALID_INPUT = "INVALID_INPUT"
    const val INVALID_INPUT_MSG = "Input data cannot be empty"
    const val INVALID_BASE64_MSG = "Input must be valid Base64"
    const val INVALID_HEX_MSG = "Input must be a valid hex string"
    const val UNSUPPORTED_ALGO = "UNSUPPORTED_ALGORITHM"
    const val UNSUPPORTED_ALGO_MSG = "Unsupported hash algorithm"
    const val DEPRECATED = "DEPRECATED_FUNCTION"
    const val DEPRECATED_MSG = "SHA1 is deprecated and should not be used for security purposes. Please use SHA256 or SHA512 instead."
    const val AES_ENCRYPT = "AES_ENCRYPT_ERROR"
    const val AES_DECRYPT = "AES_DECRYPT_ERROR"
    const val PBKDF2 = "PBKDF2_ERROR"
    const val SCRYPT = "SCRYPT_ERROR"
    const val RANDOM_BYTES = "RANDOM_BYTES_ERROR"
    const val SALT_GEN = "SALT_GENERATION_ERROR"
    const val BASE64_ENCODE = "BASE64_ENCODE_ERROR"
    const val BASE64_DECODE = "BASE64_DECODE_ERROR"
    const val HEX_ENCODE = "HEX_ENCODE_ERROR"
    const val HEX_DECODE = "HEX_DECODE_ERROR"
    const val UTF8_ENCODE = "UTF8_ENCODE_ERROR"
    const val UTF8_ENCODE_MSG = "Failed to encode string as UTF-8"
    const val UTF8_DECODE = "UTF8_DECODE_ERROR"
    const val UTF8_DECODE_MSG = "Failed to decode data as UTF-8"
}

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
        if (input.isEmpty()) return false
        return input.all { it in "0123456789abcdefABCDEF" }
    }

    // Helper to run crypto on background thread and return to main thread
    private fun runCrypto(block: () -> Unit) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                block()
            } catch (e: Exception) {
                // This should not be reached; all methods should handle their own errors
                Log.e("SuperCrypto", "Unexpected error in crypto operation", e)
            }
        }
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
        runCrypto {
            try {
                if (password.isEmpty() || salt.isEmpty()) {
                    promise.reject("INVALID_INPUT", "Password and salt cannot be empty")
                    return@runCrypto
                }
                if (!isValidBase64(salt)) {
                    promise.reject("INVALID_INPUT", "Salt must be valid Base64")
                    return@runCrypto
                }
                if (iterations < 1) {
                    promise.reject("INVALID_INPUT", "Iterations must be a positive number")
                    return@runCrypto
                }
                if (keyLen < 1 || keyLen > 512) {
                    promise.reject("INVALID_INPUT", "Key length must be between 1 and 512 bytes")
                    return@runCrypto
                }
                val hashAlgorithm =
                    when (algorithm.uppercase()) {
                        "SHA256" -> "PBKDF2WithHmacSHA256"
                        "SHA512" -> "PBKDF2WithHmacSHA512"
                        else -> {
                            promise.reject("UNSUPPORTED_ALGORITHM", "Unsupported hash algorithm")
                            return@runCrypto
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
        runCrypto {
            try {
                if (data.isEmpty()) {
                    promise.reject("INVALID_INPUT", "Input data cannot be empty")
                    return@runCrypto
                }
                promise.resolve(sha256(data))
            } catch (e: NoSuchAlgorithmException) {
                promise.reject("SHA256_ERROR", "SHA-256 algorithm not available")
            } catch (e: Exception) {
                promise.reject("SHA256_ERROR", "An error occurred during SHA256 hashing: ${e.message}")
            }
        }
    }

    @ReactMethod
    override fun sha512(data: String, promise: Promise) {
        runCrypto {
            try {
                if (data.isEmpty()) {
                    promise.reject("INVALID_INPUT", "Input data cannot be empty")
                    return@runCrypto
                }
                promise.resolve(sha512(data))
            } catch (e: NoSuchAlgorithmException) {
                promise.reject("SHA512_ERROR", "SHA-512 algorithm not available")
            } catch (e: Exception) {
                promise.reject("SHA512_ERROR", "An error occurred during SHA512 hashing: ${e.message}")
            }
        }
    }

    @ReactMethod
    override fun sha1(data: String, promise: Promise) {
        Log.w("SuperCrypto", "SHA1 is deprecated and insecure. Use SHA256 or SHA512 instead.")
        promise.reject(
            "DEPRECATED_FUNCTION",
            "SHA1 is deprecated and should not be used for security purposes. Please use SHA256 or SHA512 instead."
        )
    }

    @ReactMethod
    override fun hmacSha256(data: String, key: String, promise: Promise) {
        runCrypto {
            try {
                if (data.isEmpty() || key.isEmpty()) {
                    promise.reject("INVALID_INPUT", "Data and key cannot be empty")
                    return@runCrypto
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
    }

    @ReactMethod
    override fun hmacSha512(data: String, key: String, promise: Promise) {
        runCrypto {
            try {
                if (data.isEmpty() || key.isEmpty()) {
                    promise.reject("INVALID_INPUT", "Data and key cannot be empty")
                    return@runCrypto
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
    }

    // AES helpers
    private fun validateAESKey(key: String, promise: Promise): ByteArray? {
        if (!isValidBase64(key)) {
            promise.reject(Errors.INVALID_INPUT, "Key must be valid Base64")
            return null
        }
        val keyBytes = Base64.decode(key, Base64.NO_WRAP)
        if (keyBytes.size !in listOf(16, 24, 32)) {
            promise.reject(Errors.INVALID_INPUT, "Key must be 16, 24, or 32 bytes for AES")
            return null
        }
        return keyBytes
    }
    private fun ivBytesForMode(mode: String, iv: String?, isEncrypt: Boolean, promise: Promise): ByteArray? {
        val ivLength = if (mode.uppercase() == "GCM") 12 else 16
        return if (iv.isNullOrEmpty()) {
            if (isEncrypt) {
                val random = SecureRandom()
                ByteArray(ivLength).apply { random.nextBytes(this) }
            } else {
                null // For decrypt, IV must be extracted from ciphertext
            }
        } else {
            if (!isValidBase64(iv)) {
                promise.reject(Errors.INVALID_INPUT, "IV must be valid Base64")
                return null
            }
            val ivBytes = Base64.decode(iv, Base64.NO_WRAP)
            if (ivBytes.size != ivLength) {
                promise.reject(Errors.INVALID_INPUT, "IV must be $ivLength bytes for AES-${mode.uppercase()}")
                return null
            }
            ivBytes
        }
    }

    @ReactMethod
    override fun aesEncrypt(data: String, key: String, iv: String?, mode: String, promise: Promise) {
        runCrypto {
            try {
                if (data.isEmpty() || key.isEmpty() || mode.isEmpty()) {
                    promise.reject(Errors.INVALID_INPUT, "Data, key, and mode cannot be empty")
                    return@runCrypto
                }
                val keyBytes = validateAESKey(key, promise) ?: return@runCrypto
                val modeUpper = mode.uppercase()
                if (modeUpper == "GCM") {
                    // Always generate or use provided IV, prepend to ciphertext+tag, and return combined format
                    val ivBytes = if (iv.isNullOrEmpty()) {
                        val random = SecureRandom()
                        ByteArray(12).apply { random.nextBytes(this) }
                    } else {
                        if (!isValidBase64(iv)) {
                            promise.reject(Errors.INVALID_INPUT, "IV must be valid Base64")
                            return@runCrypto
                        }
                        val decoded = Base64.decode(iv, Base64.NO_WRAP)
                        if (decoded.size != 12) {
                            promise.reject(Errors.INVALID_INPUT, "IV must be 12 bytes for AES-GCM")
                            return@runCrypto
                        }
                        decoded
                    }
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    val keySpec = SecretKeySpec(keyBytes, "AES")
                    val ivSpec = GCMParameterSpec(128, ivBytes)
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
                    val dataBytes = data.toByteArray(StandardCharsets.UTF_8)
                    val encryptedBytes = cipher.doFinal(dataBytes)
                    // Return combined format: IV|ciphertext|tag
                    val combined = ivBytes + encryptedBytes
                    promise.resolve(Base64.encodeToString(combined, Base64.NO_WRAP))
                } else if (modeUpper == "CBC") {
                    val ivBytes = ivBytesForMode(modeUpper, iv, true, promise) ?: return@runCrypto
                    val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
                    val keySpec = SecretKeySpec(keyBytes, "AES")
                    val ivSpec = IvParameterSpec(ivBytes)
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
                    val dataBytes = data.toByteArray(StandardCharsets.UTF_8)
                    val encryptedBytes = cipher.doFinal(dataBytes)
                    val combined = ivBytes + encryptedBytes
                    promise.resolve(Base64.encodeToString(combined, Base64.NO_WRAP))
                } else {
                    promise.reject(Errors.UNSUPPORTED_ALGO, Errors.UNSUPPORTED_ALGO_MSG)
                    return@runCrypto
                }
            } catch (e: Exception) {
                promise.reject(Errors.AES_ENCRYPT, "An error occurred during AES encryption: ${e.message}")
            }
        }
    }

    @ReactMethod
    override fun aesDecrypt(encryptedData: String, key: String, iv: String?, mode: String, promise: Promise) {
        runCrypto {
            try {
                if (encryptedData.isEmpty() || key.isEmpty() || mode.isEmpty()) {
                    promise.reject(Errors.INVALID_INPUT, "Encrypted data, key, and mode cannot be empty")
                    return@runCrypto
                }
                if (!isValidBase64(key) || !isValidBase64(encryptedData)) {
                    promise.reject(Errors.INVALID_INPUT, "Key and encrypted data must be valid Base64")
                    return@runCrypto
                }
                val keyBytes = validateAESKey(key, promise) ?: return@runCrypto
                val modeUpper = mode.uppercase()
                if (modeUpper == "GCM") {
                    // Always expect combined format: IV|ciphertext|tag
                    val combined = Base64.decode(encryptedData, Base64.NO_WRAP)
                    if (combined.size < 12) {
                        promise.reject(Errors.INVALID_INPUT, "Encrypted data too short to contain IV")
                        return@runCrypto
                    }
                    val ivBytes = combined.copyOfRange(0, 12)
                    val encryptedDataBytes = combined.copyOfRange(12, combined.size)
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    val keySpec = SecretKeySpec(keyBytes, "AES")
                    val ivSpec = GCMParameterSpec(128, ivBytes)
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
                    val decryptedBytes = cipher.doFinal(encryptedDataBytes)
                    val decryptedString = String(decryptedBytes, StandardCharsets.UTF_8)
                    if (decryptedString == null) {
                        promise.reject(Errors.UTF8_DECODE, Errors.UTF8_DECODE_MSG)
                        return@runCrypto
                    }
                    promise.resolve(decryptedString)
                } else if (modeUpper == "CBC") {
                    // Always expect combined format: IV|ciphertext
                    if (!iv.isNullOrEmpty()) {
                        promise.reject(Errors.INVALID_INPUT, "For CBC mode, the IV must not be provided separately. The encrypted data must be in the combined format (IV|ciphertext).")
                        return@runCrypto
                    }
                    val combined = Base64.decode(encryptedData, Base64.NO_WRAP)
                    if (combined.size < 16) {
                        promise.reject(Errors.INVALID_INPUT, "Encrypted data too short to contain IV")
                        return@runCrypto
                    }
                    val ivBytes = combined.copyOfRange(0, 16)
                    val encryptedDataBytes = combined.copyOfRange(16, combined.size)
                    val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
                    val keySpec = SecretKeySpec(keyBytes, "AES")
                    val ivSpec = IvParameterSpec(ivBytes)
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
                    val decryptedBytes = cipher.doFinal(encryptedDataBytes)
                    val decryptedString = String(decryptedBytes, StandardCharsets.UTF_8)
                    if (decryptedString == null) {
                        promise.reject(Errors.UTF8_DECODE, Errors.UTF8_DECODE_MSG)
                        return@runCrypto
                    }
                    promise.resolve(decryptedString)
                } else {
                    promise.reject(Errors.UNSUPPORTED_ALGO, Errors.UNSUPPORTED_ALGO_MSG)
                    return@runCrypto
                }
            } catch (e: Exception) {
                promise.reject(Errors.AES_DECRYPT, "An error occurred during AES decryption: ${e.message}")
            }
        }
    }

    @ReactMethod
    override fun generateRandomBytes(length: Double, promise: Promise) {
        runCrypto {
            if (length % 1 != 0.0 || length <= 0) {
                promise.reject("INVALID_INPUT", "Length must be a positive integer")
                return@runCrypto
            }
            val intLength = length.toInt()
            if (intLength > 1_000_000) {
                promise.reject("INVALID_INPUT", "Requested length exceeds maximum allowed (1MB)")
                return@runCrypto
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
    }



    @ReactMethod
    override fun base64Encode(data: String, promise: Promise) {
        runCrypto {
            try {
                if (data.isEmpty()) {
                    promise.reject("INVALID_INPUT", "Input data cannot be empty")
                    return@runCrypto
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
    }

    @ReactMethod
    override fun base64Decode(data: String, promise: Promise) {
        runCrypto {
            try {
                if (data.isEmpty()) {
                    promise.reject("INVALID_INPUT", "Input data cannot be empty")
                    return@runCrypto
                }
                if (!isValidBase64(data)) {
                    promise.reject("INVALID_INPUT", "Input must be valid Base64")
                    return@runCrypto
                }
                val decoded = Base64.decode(data, Base64.NO_WRAP)
                promise.resolve(String(decoded, StandardCharsets.UTF_8))
            } catch (e: IllegalArgumentException) {
                promise.reject("BASE64_DECODE_ERROR", "Invalid Base64 input")
            } catch (e: Exception) {
                promise.reject("BASE64_DECODE_ERROR", "An error occurred during Base64 decoding: ${e.message}")
            }
        }
    }

    @ReactMethod
    override fun hexEncode(data: String, promise: Promise) {
        runCrypto {
            try {
                if (data.isEmpty()) {
                    promise.reject("INVALID_INPUT", "Input data cannot be empty")
                    return@runCrypto
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
    }

    @ReactMethod
    override fun hexDecode(data: String, promise: Promise) {
        runCrypto {
            try {
                if (data.isEmpty() || data.length % 2 != 0) {
                    promise.reject("INVALID_INPUT", "Invalid hex string")
                    return@runCrypto
                }
                if (!isValidHex(data)) {
                    promise.reject("INVALID_INPUT", "Input must be a valid hex string")
                    return@runCrypto
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
    }

    @ReactMethod
    override fun generateSalt(length: Double, promise: Promise) {
        runCrypto {
            if (length % 1 != 0.0 || length <= 0) {
                promise.reject("INVALID_INPUT", "Length must be a positive integer")
                return@runCrypto
            }
            val intLength = length.toInt()
            if (intLength > 1_000_000) {
                promise.reject("INVALID_INPUT", "Requested length exceeds maximum allowed (1MB)")
                return@runCrypto
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
        runCrypto {
            try {
                if (password.isEmpty() || salt.isEmpty()) {
                    promise.reject("INVALID_INPUT", "Password and salt cannot be empty")
                    return@runCrypto
                }
                if (!isValidBase64(salt)) {
                    promise.reject("INVALID_INPUT", "Salt must be valid Base64")
                    return@runCrypto
                }
                if (n < 16384 || n > 1048576 || n.toInt() and (n.toInt() - 1) != 0) {
                    promise.reject("INVALID_INPUT", "scrypt n must be a power of 2 between 16384 and 1048576")
                    return@runCrypto
                }
                if (r < 8 || r > 32) {
                    promise.reject("INVALID_INPUT", "scrypt r must be between 8 and 32")
                    return@runCrypto
                }
                if (p < 1) {
                    promise.reject("INVALID_INPUT", "scrypt p must be positive")
                    return@runCrypto
                }
                if (keyLen < 1) {
                    promise.reject("INVALID_INPUT", "Key length must be positive")
                    return@runCrypto
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
    }

    @ReactMethod
    override fun verifyHash(data: String, hash: String, algorithm: String, promise: Promise) {
        runCrypto {
            try {
                if (data.isEmpty() || hash.isEmpty()) {
                    promise.reject(Errors.INVALID_INPUT, "Data and hash cannot be empty")
                    return@runCrypto
                }
                if (!isValidBase64(hash)) {
                    promise.reject(Errors.INVALID_INPUT, "Hash must be valid Base64")
                    return@runCrypto
                }
                val computedHash = when (algorithm.uppercase()) {
                    "SHA256" -> sha256(data)
                    "SHA512" -> sha512(data)
                    else -> {
                        promise.reject(Errors.UNSUPPORTED_ALGO, Errors.UNSUPPORTED_ALGO_MSG)
                        return@runCrypto
                    }
                }
                val computedHashBytes = Base64.decode(computedHash, Base64.NO_WRAP)
                val hashBytes = Base64.decode(hash, Base64.NO_WRAP)
                promise.resolve(MessageDigest.isEqual(computedHashBytes, hashBytes))
            } catch (e: NoSuchAlgorithmException) {
                promise.reject(Errors.UNSUPPORTED_ALGO, "Unsupported algorithm: $algorithm")
            } catch (e: Exception) {
                promise.reject("VERIFY_HASH_ERROR", "An error occurred during hash verification: ${e.message}")
            }
        }
    }

    companion object {
        const val NAME = "SuperCrypto"
    }
}