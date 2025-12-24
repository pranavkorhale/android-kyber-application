package com.example.kyberchat.crypto

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.SecretWithEncapsulation
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

object CryptoManager {

    private val secureRandom = SecureRandom()

    // --- Kyber (KEM) ---
    private var kyberKeyPair: AsymmetricCipherKeyPair? = null

    fun generateKyberKeys(): String {
        val generator = KyberKeyPairGenerator()
        generator.init(KyberKeyGenerationParameters(secureRandom, KyberParameters.kyber512))
        kyberKeyPair = generator.generateKeyPair()
        
        val pubKey = kyberKeyPair!!.public as KyberPublicKeyParameters
        return Base64.getEncoder().encodeToString(pubKey.encoded)
    }

    fun decapsulate(ciphertextB64: String): ByteArray {
        if (kyberKeyPair == null) throw IllegalStateException("Kyber keys not generated")
        
        val ciphertext = Base64.getDecoder().decode(ciphertextB64)
        val privateKey = kyberKeyPair!!.private as KyberPrivateKeyParameters
        
        val extractor = KyberKEMExtractor(privateKey)
        
        val sharedSecret = extractor.extractSecret(ciphertext)
        return sharedSecret
    }

    fun encapsulate(recipientKyberPkB64: String): Pair<String, ByteArray> {
        val pubKeyBytes = Base64.getDecoder().decode(recipientKyberPkB64)
        val pubKey = KyberPublicKeyParameters(KyberParameters.kyber512, pubKeyBytes)
        
        val generator = KyberKEMGenerator(secureRandom)
        val encapsulation = generator.generateEncapsulated(pubKey)
        
        val ciphertextB64 = Base64.getEncoder().encodeToString(encapsulation.encapsulation)
        return Pair(ciphertextB64, encapsulation.secret)
    }

    // --- Dilithium (Signatures) ---
    private var dilithiumKeyPair: AsymmetricCipherKeyPair? = null

    fun generateDilithiumKeys(): String {
        val generator = DilithiumKeyPairGenerator()
        generator.init(DilithiumKeyGenerationParameters(secureRandom, DilithiumParameters.dilithium2))
        dilithiumKeyPair = generator.generateKeyPair()
        
        val pubKey = dilithiumKeyPair!!.public as DilithiumPublicKeyParameters
        return Base64.getEncoder().encodeToString(pubKey.encoded)
    }

    fun sign(message: ByteArray): String {
        if (dilithiumKeyPair == null) throw IllegalStateException("Dilithium keys not generated")
        
        val signer = DilithiumSigner()
        signer.init(true, dilithiumKeyPair!!.private)
        
        val signature = signer.generateSignature(message)
        return Base64.getEncoder().encodeToString(signature)
    }

    fun verify(message: ByteArray, signatureB64: String): Boolean {
        if (dilithiumKeyPair == null) return false
        val signer = DilithiumSigner()
        signer.init(false, dilithiumKeyPair!!.public)
        val signature = Base64.getDecoder().decode(signatureB64)
        return signer.verifySignature(message, signature)
    }

    // --- AES-GCM ---
    private const val AES_KEY_SIZE = 32 // 256 bits
    private const val GCM_TAG_LENGTH = 128
    private const val GCM_IV_LENGTH = 12

    fun deriveAesKey(sharedSecret: ByteArray): SecretKeySpec {
        val digest = MessageDigest.getInstance("SHA-256")
        val keyBytes = digest.digest(sharedSecret)
        return SecretKeySpec(keyBytes, "AES")
    }

    fun encrypt(message: String, key: SecretKeySpec): Pair<String, String> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(GCM_IV_LENGTH)
        secureRandom.nextBytes(iv)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
        val ciphertext = cipher.doFinal(message.toByteArray(Charsets.UTF_8))
        
        return Pair(
            Base64.getEncoder().encodeToString(ciphertext),
            Base64.getEncoder().encodeToString(iv)
        )
    }

    fun decrypt(ciphertextB64: String, ivB64: String, key: SecretKeySpec): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = Base64.getDecoder().decode(ivB64)
        val ciphertext = Base64.getDecoder().decode(ciphertextB64)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        val plaintext = cipher.doFinal(ciphertext)
        
        return String(plaintext, Charsets.UTF_8)
    }
}
