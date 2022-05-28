package com.ingenico.androidkeystore

import android.os.Build
import android.os.Bundle
import android.security.KeyChain
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.method.ScrollingMovementMethod
import android.util.Base64
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.ingenico.androidkeystore.ssl.NettySocketClient
import com.ingenico.androidkeystore.ssl.SSLConnector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.spongycastle.asn1.x500.X500Name
import org.spongycastle.asn1.x509.BasicConstraints
import org.spongycastle.asn1.x509.Extension
import org.spongycastle.asn1.x509.ExtensionsGenerator
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.spongycastle.crypto.tls.ConnectionEnd.server
import org.spongycastle.crypto.tls.KeyExchangeAlgorithm
import org.spongycastle.operator.ContentSigner
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder
import org.spongycastle.pkcs.PKCS10CertificationRequest
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.spongycastle.util.encoders.Hex
import java.io.*
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
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
                importSignedCertificate()
                showKeys()
            }
            R.id.action_import_ca -> {
                importCA()
                showKeys()
            }

            R.id.action_import_from_pkcs12 -> {
                importFromPkcsToKeystore()
                showKeys()
            }

            R.id.action_export_to_pkcs12 -> {
                exportFromKeystoreToPkcs()
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
            R.id.action_ssl_connect1 -> {
                sslConnect1()
                showKeys()
            }
            R.id.action_ssl_connect2 -> {
                sslConnect2()
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

    private fun importSignedCertificate() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val cert: Certificate = certificateFactory.generateCertificate(FileInputStream(File(dataDir.path + "/client_signed.crt")))

        val existingPrivateKeyEntry = keyStore.getEntry(RSA_KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        val newEntry = KeyStore.PrivateKeyEntry(
            existingPrivateKeyEntry.privateKey, arrayOf(
                cert
            )
        )
        keyStore.setEntry(RSA_KEY_ALIAS, newEntry, null)
    }

    private fun importCA() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certCA: Certificate = certificateFactory.generateCertificate(
            FileInputStream(
                File(
                    dataDir.path + "/CAcert.pem"
                )
            )
        )

        keyStore.setCertificateEntry("CA", certCA)
    }

    private fun showPkcsCertificate() {
        val keyStore = getPkcsKeyStore()

        logClear()
        for (alias in keyStore.aliases()) {
            val cert = keyStore.getEntry(alias, null)
            log(cert.toString())
        }
    }

    private fun importFromPkcsToKeystore() {
        val keyStoreFrom = KeyStore.getInstance("PKCS12")
        val inputStream = FileInputStream(File(dataDir.path + "/cert.p12"))
        inputStream.use {keyStoreFrom.load(it, KEYSTORE_PASSWORD.toCharArray()) }

        val keyStoreTo = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStoreTo.load(null)

        for (alias in keyStoreFrom.aliases()) {
            keyStoreTo.setEntry(alias, keyStoreFrom.getEntry(alias, null),null)
        }
    }

    private fun exportFromKeystoreToPkcs() {
        val keyStoreFrom = KeyStore.getInstance(ANDROID_KEYSTORE)
        val keyStoreTo = KeyStore.getInstance("PKCS12")

        keyStoreFrom.load(null)
        keyStoreTo.load(null)

        for (alias in keyStoreFrom.aliases()) {
            keyStoreTo.setEntry(alias, keyStoreFrom.getEntry(alias, null),null)
        }

        val fos = FileOutputStream(File(dataDir.path + "/cert_android.p12"))
        fos.use {keyStoreTo.store(it, "pass".toCharArray()) }
    }

    private fun getPkcsKeyStore(): KeyStore {
        val keyStoreFrom = KeyStore.getInstance("PKCS12")
        val inputStream = FileInputStream(File(dataDir.path + "/cert.p12"))
        inputStream.use {keyStoreFrom.load(it, KEYSTORE_PASSWORD.toCharArray()) }
        return keyStoreFrom
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
        val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        for (alias in keyStore.aliases()) {
            keyEntries.add(keyStore.getEntry(alias, null))
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

    private fun sslConnect1() {
        val sslConnector = SSLConnector()
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        sslConnector.init(keyStore, "")
//        sslConnector.init(getCaKeyStore(), KEYSTORE_PASSWORD)

        // Use coroutine to avoid NetworkOnMainThreadException
        GlobalScope.launch(Dispatchers.Default) {
            sslConnector.connect("10.0.2.2", 1443)
            sslConnector.sendMessage("SSLConnector Hello\n")
            sslConnector.close()
        }
    }

    private fun sslConnect2() {
        val socketClient = NettySocketClient("10.0.2.2", 1443)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        socketClient.init(keyStore, "")
//        socketClient.init(getKeyStore(), KEYSTORE_PASSWORD)
        socketClient.open()
        socketClient.sendMessage("NettySocketClient Hello\n")
        socketClient.close()
    }

    private fun generateKeyPair(): KeyPair {
        val start: Calendar = Calendar.getInstance()
        val end: Calendar = Calendar.getInstance()
        end.add(Calendar.YEAR, 10)

        val spec: AlgorithmParameterSpec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenParameterSpec.Builder(
                RSA_KEY_ALIAS,
//                KeyProperties.PURPOSE_SIGN
                    KeyProperties.PURPOSE_DECRYPT or
                            KeyProperties.PURPOSE_ENCRYPT or
                            KeyProperties.PURPOSE_SIGN or
                            KeyProperties.PURPOSE_VERIFY
            )
                    .setCertificateSubject(X500Principal("${RSA_CERT_SUBJECT_PREFIX}$RSA_KEY_ALIAS"))
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
        return csrBuilder.build(signer)
    }

    fun generatePkcsKeyPair() {
        // --- generate a key pair (you did this already it seems)
        val rsaGen: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
        val pair: KeyPair = rsaGen.generateKeyPair()

        // --- create the self signed cert
        val cert: Certificate = createSelfSigned(pair)

        // --- create a new pkcs12 key store in memory
        val pkcs12: KeyStore = KeyStore.getInstance("PKCS12")
        pkcs12.load(null, null)

        // --- create entry in PKCS12
        pkcs12.setKeyEntry(
                "privatekeyalias",
                pair.getPrivate(),
                "entrypassphrase".toCharArray(),
                arrayOf<Certificate>(cert)
        )
        FileOutputStream("mystore.p12").use { p12 ->
            pkcs12.store(
                    p12,
                    "p12passphrase".toCharArray()
            )
        }

        // --- read PKCS#12 as file
        val testp12: KeyStore = KeyStore.getInstance("PKCS12")
        FileInputStream("mystore.p12").use { p12 ->
            testp12.load(
                    p12,
                    "p12passphrase".toCharArray()
            )
        }

        // --- retrieve private key
        println(
                Hex.toHexString(
                        testp12.getKey("privatekeyalias", "entrypassphrase".toCharArray()).getEncoded()
                )
        )
    }

    private fun createSelfSigned(pair: KeyPair): X509Certificate {
        val dnName = X500Name("CN=publickeystorageonly")
        val certSerialNumber: BigInteger = BigInteger.ONE
        val startDate = Date() // now
        val calendar: Calendar = Calendar.getInstance()
        calendar.setTime(startDate)
        calendar.add(Calendar.YEAR, 1)
        val endDate: Date = calendar.getTime()
        val contentSigner = JcaContentSignerBuilder("SHA256WithRSA").build(pair.getPrivate())
        val certBuilder = JcaX509v3CertificateBuilder(
                dnName,
                certSerialNumber,
                startDate,
                endDate,
                dnName,
                pair.getPublic()
        )
        return JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner))
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
        private const val KEYSTORE_PASSWORD = "pass"
        private const val ALGORITHM_RSA = "RSA"
    }
}