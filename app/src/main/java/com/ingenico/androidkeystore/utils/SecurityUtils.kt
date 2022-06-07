package com.ingenico.androidkeystore.utils

import java.security.*
import java.security.cert.X509Certificate

interface SecurityUtils {
    val securityProvider: Provider

    fun generateKeyPair(): KeyPair
    fun generateCsr(keyPair: KeyPair, cn: String?): ByteArray
    fun createCertificate(
        dn: String,
        issuer: String,
        publicKey: PublicKey,
        privateKey: PrivateKey
    ): X509Certificate
}