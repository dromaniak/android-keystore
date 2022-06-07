package com.sample.androidkeystore.utils

import java.security.*
import java.security.cert.X509Certificate
import javax.crypto.Cipher

abstract class SecurityUtils {
    abstract val securityProvider: Provider

    abstract fun generateKeyPair(): KeyPair
    abstract fun generateCsr(keyPair: KeyPair, cn: String?): ByteArray
    abstract fun createCertificate(
        dn: String,
        issuer: String,
        publicKey: PublicKey,
        privateKey: PrivateKey
    ): X509Certificate

    fun encrypt(publicKey: PublicKey, data: ByteArray): ByteArray {
        val cipherRsa = Cipher.getInstance(ENCRYPTION_TRANSFORMATION)
            .apply {
                init(Cipher.ENCRYPT_MODE, publicKey)
            }

        return cipherRsa.doFinal(data)
    }

    fun decrypt(privateKey: PrivateKey, data: ByteArray): ByteArray {
        val cipherRsa = Cipher.getInstance(ENCRYPTION_TRANSFORMATION)
            .apply {
                init(Cipher.DECRYPT_MODE, privateKey)
            }

        return cipherRsa.doFinal(data)
    }

    companion object {
        private const val ENCRYPTION_TRANSFORMATION = "RSA/NONE/PKCS1Padding"
    }
}