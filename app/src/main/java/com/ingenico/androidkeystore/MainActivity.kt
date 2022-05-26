package com.ingenico.androidkeystore

import android.os.Build
import android.os.Bundle
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.method.ScrollingMovementMethod
import android.util.Base64
import android.view.Menu
import android.view.MenuItem
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.ingenico.androidkeystore.ssl.NettySocketClient
import com.ingenico.androidkeystore.ssl.SSLConnector
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
import java.io.*
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.security.auth.x500.X500Principal


@Suppress("DEPRECATION")
@RequiresApi(Build.VERSION_CODES.N)
class MainActivity : AppCompatActivity() {
    private var keyPair: KeyPair? = null

    @RequiresApi(Build.VERSION_CODES.N)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(findViewById(R.id.toolbar))

        findViewById<FloatingActionButton>(R.id.fab).setOnClickListener {
            showKeys()
        }

        val tv = findViewById<TextView>(R.id.log)
        tv.movementMethod = ScrollingMovementMethod()

        showKeys()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        when (item.itemId) {
            R.id.action_generate_keypair -> {
                logClear()
                keyPair = generateKeyPair()
                showKeys()
            }
            R.id.action_export_csr -> {
                exportCsr()
            }
            R.id.action_import_certificate -> {
                importCertificate()
                showKeys()
            }
            R.id.action_import_ca -> {
                importCA()
                showKeys()
            }
            R.id.action_show_pkcs12_certificate -> {
                showPkcsCertificate()
            }
            R.id.action_delete_all_keys -> {
                deleteKeys(all = true)
                showKeys()
            }
            R.id.action_delete_other_keys -> {
                deleteKeys(all = false)
                showKeys()
            }
            R.id.action_ssl_connect -> {
                sslConnect()
                showKeys()
            }
            else -> super.onOptionsItemSelected(item)
        }
        return true
    }

    private fun showKeys() {
        logClear()
        getKeys().forEach {
            log(it.toString())
        }
    }

    private fun exportCsr() {
        if (keyPair == null)
            return

        val keyPairCsr = generateCSR(keyPair!!, "TID SN").encoded
        logClear()
        log("CSR:")
        log(bytes2HexString(keyPairCsr))

        var csr: String? = "-----BEGIN CERTIFICATE REQUEST-----\n"
        csr += Base64.encodeToString(keyPairCsr, Base64.DEFAULT)
        csr += "-----END CERTIFICATE REQUEST-----"

        runOnUiThread {
            val fw = FileWriter(File(dataDir.path + "/client_base64.csr"))
            fw.write(csr)
            fw.close()

            val fos = FileOutputStream(File(dataDir.path + "/client.csr"))
            fos.write(keyPairCsr)
            fos.close()
        }
    }

    private fun importCertificate() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val cert: Certificate = certificateFactory.generateCertificate(FileInputStream(File(dataDir.path + "/client_signed.crt")))
        val certCA: Certificate = certificateFactory.generateCertificate(FileInputStream(File(dataDir.path + "/CAcert.pem")))

        val existingPrivateKeyEntry = keyStore.getEntry(RSA_KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        val newEntry = KeyStore.PrivateKeyEntry(existingPrivateKeyEntry.privateKey, arrayOf(cert, certCA))
        keyStore.setEntry(RSA_KEY_ALIAS, newEntry, null)
    }

    private fun importCA() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certCA: Certificate = certificateFactory.generateCertificate(FileInputStream(File(dataDir.path + "/CAcert.pem")))

        keyStore.setCertificateEntry("CA", certCA)
    }

    private fun showPkcsCertificate() {
        val ks = getCaKeyStore()

        logClear()
        for (alias in ks.aliases()) {
            val cert = ks.getEntry(alias, null)
            log(cert.toString())
        }
    }

    private fun getCaKeyStore(): KeyStore {
        val ks = KeyStore.getInstance("PKCS12")
        val inputStream = FileInputStream(File(dataDir.path + "/cert.p12"))
        inputStream.use { fis -> ks.load(fis, "pass".toCharArray()) }
        return ks
    }

    private fun log(s: String) {
        val tv = findViewById<TextView>(R.id.log)
        tv.text = "${tv.text}" + "\n" + s
    }

    private fun logClear() {
        val tv = findViewById<TextView>(R.id.log)
        tv.text = ""
    }

    private fun getKeys(): List<KeyStore.Entry> {
        val keyEntries = mutableListOf<KeyStore.Entry>()
        val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)
        for (alias in ks.aliases()) {
            keyEntries.add(ks.getEntry(alias, null))
        }
        return keyEntries
    }

    private fun deleteKeys(all: Boolean = false) {
        val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)
        for (alias in ks.aliases()) {
            if (all) {
                ks.deleteEntry(alias)
            } else {
                if (alias != RSA_KEY_ALIAS)
                    ks.deleteEntry(alias)
            }
        }
    }

    private fun sslConnect() {
//        val sslConnector = SSLConnector()
////        sslConnector.init(KeyStore.getInstance(ANDROID_KEYSTORE))
//        sslConnector.init(getCaKeyStore())
//        sslConnector.connect("10.0.2.2", 1443)

        val socketClient = NettySocketClient("10.0.2.2", 1443)
        socketClient.init(getCaKeyStore())
        socketClient.open()
        val response = socketClient.sendMessage("Hellloooooooooooooooooo".toByteArray())
        println(String(response!!))
        socketClient.close()
    }

    private fun generateKeyPair(): KeyPair {
        val start: Calendar = Calendar.getInstance()
        val end: Calendar = Calendar.getInstance()
        end.add(Calendar.YEAR, 10)

        val spec: AlgorithmParameterSpec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenParameterSpec.Builder(
                    RSA_KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN
            )
                    .setCertificateSubject(X500Principal("${RSA_CERT_SUBJECT_PREFIX}$RSA_KEY_ALIAS"))
//                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setDigests(
                            KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA384,
                            KeyProperties.DIGEST_SHA512
                    )
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(start.time)
                    .setCertificateNotAfter(end.time)
                    .setKeySize(RSA_KEY_SIZE)
                    .build()
        } else {
            KeyPairGeneratorSpec.Builder(applicationContext)
                    .setAlias(RSA_KEY_ALIAS)
                    .setSubject(X500Principal("${RSA_CERT_SUBJECT_PREFIX}$RSA_KEY_ALIAS"))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(Date())
                    .setEndDate(end.time)
                    .setKeySize(RSA_KEY_SIZE)
                    .build()
        }

        return try {
            val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(
                    ALGORITHM_RSA,
                    ANDROID_KEYSTORE
            )
            keyPairGenerator.initialize(spec)
            keyPairGenerator.generateKeyPair()
        } catch (e: Exception) {
            throw Error("Cannot generate key", e)
        }
    }

    //Create the certificate signing request (CSR) from private and public keys
//    @Throws(IOException::class, OperatorCreationException::class)
    fun generateCSR(keyPair: KeyPair, cn: String?): PKCS10CertificationRequest {
        val CN_PATTERN = "CN=%s, O=Ingenico, OU=PSA"
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
        private const val EMPTY_STRING = ""

        private const val RSA_KEY_ALIAS = "host_ssl"
        private const val RSA_KEY_SIZE = 2048
        private const val RSA_CERT_SUBJECT_PREFIX = "CN="
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ALGORITHM_RSA = "RSA"
    }
}