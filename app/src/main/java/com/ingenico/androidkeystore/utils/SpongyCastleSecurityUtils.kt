package com.ingenico.androidkeystore.utils


import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.spongycastle.asn1.x500.X500Name
import org.spongycastle.asn1.x509.BasicConstraints
import org.spongycastle.asn1.x509.Extension
import org.spongycastle.asn1.x509.ExtensionsGenerator
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.spongycastle.jce.provider.BouncyCastleProvider
import org.spongycastle.operator.ContentSigner
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.*

class SpongyCastleSecurityUtils: SecurityUtils() {
    override val securityProvider: Provider
        get() = provider
    override fun generateKeyPair(): KeyPair {
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(
            ALGORITHM_RSA, securityProvider.name
        )

        keyPairGenerator.initialize(2048)
        return keyPairGenerator.generateKeyPair()
    }

    //Create the certificate signing request (CSR) from private and public keys
    override fun generateCsr(keyPair: KeyPair, cn: String?): ByteArray {
        val CN_PATTERN = "CN=%s, O=Ingenico, OU=PSA"
        val principal: String = String.format(CN_PATTERN, cn)

        val signer: ContentSigner =
            JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.private)
        val csrBuilder: PKCS10CertificationRequestBuilder = JcaPKCS10CertificationRequestBuilder(
            X500Name(principal), keyPair.public
        )
        val extensionsGenerator = ExtensionsGenerator()
        extensionsGenerator.addExtension(
            Extension.basicConstraints, true, BasicConstraints(
                true
            )
        )
        csrBuilder.addAttribute(
            PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
            extensionsGenerator.generate()
        )
        return csrBuilder.build(signer).encoded
    }

    override fun createCertificate(
        dn: String,
        issuer: String,
        publicKey: PublicKey,
        privateKey: PrivateKey
    ): X509Certificate {

        val end: Calendar = Calendar.getInstance()
        end.add(Calendar.YEAR, 10)

        val certSerialNumber: BigInteger = BigInteger.ONE
        val startDate = Date() // now
        val calendar: Calendar = Calendar.getInstance()
        calendar.time = startDate
        calendar.add(Calendar.YEAR, 1)
        val endDate: Date = calendar.time
        val contentSigner = JcaContentSignerBuilder("SHA256WithRSA")
            .build(privateKey)
        val certBuilder = JcaX509v3CertificateBuilder(
            X500Name(issuer),
            certSerialNumber,
            startDate,
            endDate,
            X500Name(dn),
            publicKey
        )
        return JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner))
    }

    companion object {
        private val provider = BouncyCastleProvider()
        private const val ALGORITHM_RSA = "RSA"
    }
}