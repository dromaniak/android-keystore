package com.ingenico.androidkeystore

import android.os.Build
import android.os.Bundle
import android.os.Process
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.method.ScrollingMovementMethod
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.spongycastle.asn1.x500.X500Name
import org.spongycastle.asn1.x509.BasicConstraints
import org.spongycastle.asn1.x509.Extension
import org.spongycastle.asn1.x509.ExtensionsGenerator
import org.spongycastle.operator.ContentSigner
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder
import org.spongycastle.pkcs.PKCS10CertificationRequest
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.*
import kotlin.experimental.and


@Suppress("DEPRECATION")
@RequiresApi(Build.VERSION_CODES.M)
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val tv = findViewById<TextView>(R.id.log)
        tv.movementMethod = ScrollingMovementMethod()


        log("my uid is " + Process.myUid())
        val keyPair = generateKey()
        log(getKey().toString())

        log("CSR:")
        log(bytes2HexString(generateCSR(keyPair, "Test").encoded))
    }

    private fun log(s: String) {
        val tv = findViewById<TextView>(R.id.log)
        tv.text = "${tv.text}" + "\n" + s
    }

    fun getKey(): KeyStore.Entry {
        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        return ks.getEntry("key", null)
    }

    private fun generateKey(): KeyPair {
        val start: Calendar = Calendar.getInstance()
        val end: Calendar = Calendar.getInstance()
        end.add(Calendar.YEAR, 10)

        val spec = try {
                KeyGenParameterSpec.Builder(
                    "key",
                    KeyProperties.PURPOSE_SIGN
                )
                .setCertificateNotBefore(start.getTime())
                .setCertificateNotAfter(end.getTime())
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setDigests(
                    KeyProperties.DIGEST_SHA256,
                    KeyProperties.DIGEST_SHA384,
                    KeyProperties.DIGEST_SHA512
                )
                .setKeySize(2048)
                .build()

//            KeyPairGeneratorSpec.Builder(this@MainActivity)
//                .setAlias("key")
//                .setSubject(X500Principal("CN=whatever"))
//                .setStartDate(start.getTime())
//                .setEndDate(end.getTime())
//                .setKeySize(2048)
//                .setSerialNumber(BigInteger.valueOf(1))
//                .build()
        } catch (e: Exception) {
            throw Error("Cannot make a KeyPairGeneratorSpec", e)
        }

        val keyPair = try {
            val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(
                "RSA",
                "AndroidKeyStore"
            )
            keyPairGenerator.initialize(spec)
            keyPairGenerator.generateKeyPair()
        } catch (e: Exception) {
            throw Error("Cannot generate key", e)
        }
        return keyPair
    }

    //Create the certificate signing request (CSR) from private and public keys
//    @Throws(IOException::class, OperatorCreationException::class)
    fun generateCSR(keyPair: KeyPair, cn: String?): PKCS10CertificationRequest {
        val CN_PATTERN = "CN=%s, O=Aralink, OU=OrgUnit"
        val principal: String = java.lang.String.format(CN_PATTERN, cn)
        val signer: ContentSigner =
            JcaContentSignerBuilder("SHA512WITHRSA").build(keyPair.private)
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
        return csrBuilder.build(signer)
    }

    private fun bytes2HexString(data: ByteArray): String {
        if (isNullEmpty(data)) {
            return EMPTY_STRING
        }
        val buffer = StringBuilder()
        for (b in data) {
            buffer.append(String.format("%02X ", b));
        }
        return buffer.toString()
    }

    private fun isNullEmpty(array: ByteArray?): Boolean {
        return array == null || array.isEmpty()
    }

    companion object {
        const val EMPTY_STRING = ""
    }
}