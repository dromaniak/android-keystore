package com.ingenico.androidkeystore

import android.os.Build
import android.os.Bundle
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.method.ScrollingMovementMethod
import android.util.Base64
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.widget.TextView
import android.widget.Toast
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
import org.spongycastle.asn1.x509.X509Name
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.spongycastle.jce.provider.BouncyCastleProvider
import org.spongycastle.operator.ContentSigner
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder
import org.spongycastle.pkcs.PKCS10CertificationRequest
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.spongycastle.x509.X509V3CertificateGenerator
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FileWriter
import java.math.BigInteger
import java.security.*
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
    private var usePkcsKeyStore = false

    @RequiresApi(Build.VERSION_CODES.N)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(findViewById(R.id.toolbar))

        findViewById<FloatingActionButton>(R.id.fab).setOnClickListener {
            if (usePkcsKeyStore) {
                showPkcsCertificate()
            } else {
                showKeys()
            }
        }

        val tv = findViewById<TextView>(R.id.log)
        tv.movementMethod = ScrollingMovementMethod()

        Security.insertProviderAt(BouncyCastleProvider(), Security.getProviders().size)
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
            R.id.menu_use_pkcs -> {
                item.isChecked = !item.isChecked
                usePkcsKeyStore = item.isChecked

                if (usePkcsKeyStore) {
                    showPkcsCertificate()
                } else {
                    showKeys()
                }
            }
            R.id.action_generate_keypair -> {
                this.keyPair = generateKeyPair()
            }
            R.id.action_generate_keypair_to_store -> {
                if (usePkcsKeyStore) {
                    this.keyPair = generateCertificatesToPkcs()
                    showPkcsCertificate()
                } else {
                    this.keyPair = generateKeyPairToKeystore()
                    showKeys()
                }
            }
            R.id.action_export_csr -> {
                exportCsr()
            }
            R.id.action_import_signed_certificate_to_store -> {
                if (usePkcsKeyStore) {
                    importSignedCertToPkcs()
                    showPkcsCertificate()
                } else {
                    importSignedCertToKeystore()
                    showKeys()
                }
            }
            R.id.action_import_ca_to_store -> {
                if (usePkcsKeyStore) {
                    importCaToPkcs()
                    showPkcsCertificate()
                } else {
                    importCa()
                    showKeys()
                }
            }
            R.id.action_import_from_pkcs12_to_keystore -> {
                importFromPkcsToKeystore()
                showKeys()
            }

            R.id.action_export_from_keystore_to_pkcs12 -> {
                exportFromKeystoreToPkcs()
                showPkcsCertificate()
            }

            R.id.action_show_keys -> {
                if (usePkcsKeyStore) {
                    showPkcsCertificate()
                } else {
                    showKeys()
                }
            }
            R.id.action_delete_all_keys -> {
                if (usePkcsKeyStore) {
                    deleteKeysPkcs(all = true)
                    showPkcsCertificate()
                } else {
                    deleteKeys(all = true)
                    showKeys()
                }
            }
            R.id.action_delete_other_keys -> {
                if (usePkcsKeyStore) {
                    deleteKeysPkcs(all = false)
                    showPkcsCertificate()
                } else {
                    deleteKeys(all = false)
                    showKeys()
                }
            }
            R.id.action_ssl_connect1 -> {
                sslConnect1()
            }
            R.id.action_ssl_connect2 -> {
                sslConnect2()
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
        if (this.keyPair == null) {
            val toast = Toast.makeText(
                applicationContext,
                "No KeyPair available",
                Toast.LENGTH_LONG
            )
            toast.show()
            return
        }

        val keyPairCsr = generateCSR(this.keyPair!!, "TID SN").encoded
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

    private fun importSignedCertToKeystore() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certCA: Certificate = certificateFactory.generateCertificate(
            FileInputStream(File(dataDir.path + "/CAcert.pem"))
        )
        val cert: Certificate = certificateFactory.generateCertificate(
            FileInputStream(File(dataDir.path + "/client_signed.crt"))
        )

        val existingPrivateKeyEntry = keyStore.getEntry(KEY_ALIAS, null)
        if (keyPair == null && existingPrivateKeyEntry == null) {
            val toast = Toast.makeText(
                applicationContext,
                "No private keys available",
                Toast.LENGTH_LONG
            )
            toast.show()
            return
        }

        var privateKey: PrivateKey? = null
        if (keyPair != null) {
            privateKey = keyPair?.private
        } else if (existingPrivateKeyEntry != null) {
            if (existingPrivateKeyEntry is KeyStore.PrivateKeyEntry) {
                privateKey = existingPrivateKeyEntry.privateKey
            }
        }

        val newEntry = KeyStore.PrivateKeyEntry(
            privateKey,
            arrayOf(cert, certCA)
        )

        keyStore.setEntry(KEY_ALIAS, newEntry, null)
    }

    private fun importSignedCertToPkcs() {
        if (keyPair == null) {
            val toast = Toast.makeText(
                applicationContext,
                "No KeyPair available",
                Toast.LENGTH_LONG
            )
            toast.show()
            return
        }

        val keyStore = KeyStore.getInstance("PKCS12", PRIVIDER_NAME_SPONGY_CASTLE)
        keyStore.load(null)

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certCA: Certificate = certificateFactory.generateCertificate(
            FileInputStream(File(dataDir.path + "/CAcert.pem"))
        )
        val cert: Certificate = certificateFactory.generateCertificate(
            FileInputStream(File(dataDir.path + "/client_signed.crt"))
        )

        val newEntry = KeyStore.PrivateKeyEntry(
            keyPair!!.private,
            arrayOf(cert, certCA)
        )
        keyStore.setEntry(KEY_ALIAS, newEntry, null)
        savePkcsKeyStore(keyStore, "cert.p12", KEYSTORE_PASSWORD)
    }

    private fun importCa() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certCA: Certificate = certificateFactory.generateCertificate(
            FileInputStream(File(dataDir.path + "/CAcert.pem"))
        )

        keyStore.setCertificateEntry("CA", certCA)
    }

    private fun importCaToPkcs() {
        // Spongy Castle
//        val file = File(dataDir.path + "/CAcert.pem")
//        var certCA: X509Certificate? = null
//        val pemParser = PEMParser(FileReader(file))
//        val `object` = pemParser.readObject()
//        if (`object` is X509CertificateHolder) {
//            certCA = JcaX509CertificateConverter().setProvider(PRIVIDER_NAME_SPONGY_CASTLE).getCertificate(`object`)
//        }
//        if (certCA == null) {
//            throw Exception("CAcert.pem" + " doesn't contain X509Certificate!")
//        }

        val keyStore = loadPkcsKeyStore("cert.p12", KEYSTORE_PASSWORD)

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certCA: Certificate = certificateFactory.generateCertificate(
            FileInputStream(File(dataDir.path + "/CAcert.pem"))
        )

        keyStore.setCertificateEntry("CA", certCA)
        savePkcsKeyStore(keyStore, "cert.p12", KEYSTORE_PASSWORD)
    }

    private fun showPkcsCertificate() {
        if (File(dataDir.path + "/cert.p12").exists().not()) {
            logClear()
            log("cert.p12 not found")
            return
        }

        val keyStore = loadPkcsKeyStore("cert.p12", KEYSTORE_PASSWORD)

        logClear()
        for (alias in keyStore.aliases()) {
            val cert = keyStore.getEntry(alias, null)
            log(cert.toString())
        }
    }

    private fun importFromPkcsToKeystore() {
        val keyStoreFrom = loadPkcsKeyStore("cert.p12", KEYSTORE_PASSWORD)

        val keyStoreTo = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStoreTo.load(null)

        for (alias in keyStoreFrom.aliases()) {
            val entry = keyStoreFrom.getEntry(alias, null)
            keyStoreTo.setEntry(alias, entry, null)
        }
    }

    private fun exportFromKeystoreToPkcs() {
        try {
            val keyStoreFrom = KeyStore.getInstance(ANDROID_KEYSTORE)
            val keyStoreTo = KeyStore.getInstance("PKCS12")

            keyStoreFrom.load(null)
            keyStoreTo.load(null)

            for (alias in keyStoreFrom.aliases()) {
                keyStoreTo.setEntry(alias, keyStoreFrom.getEntry(alias, null), null)
            }

            savePkcsKeyStore(keyStoreTo, "cert.p12", KEYSTORE_PASSWORD)
        } catch (e: Exception) {
            val toast = Toast.makeText(
                    applicationContext,
                    e.message,
                    Toast.LENGTH_LONG
            )
            toast.show()
            File(dataDir.path + "/cert.p12").delete()
        }

    }

    private fun loadPkcsKeyStore(fileName: String, password: String): KeyStore {
        val keyStore = KeyStore.getInstance("PKCS12")
        val fis = FileInputStream(File(dataDir.path + "/" + fileName))
        fis.use {keyStore.load(it, password.toCharArray()) }
        return keyStore
    }

    private fun savePkcsKeyStore(keyStore: KeyStore, fileName: String, password: String) {
        val fos = FileOutputStream(File(dataDir.path + "/" + fileName))
        fos.use {keyStore.store(it, password.toCharArray()) }
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
            val entry = keyStore.getEntry(alias, null)
            keyEntries.add(entry)
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
                if (alias != KEY_ALIAS)
                    ks.deleteEntry(alias)
            }
        }
    }

    private fun deleteKeysPkcs(all: Boolean = false) {
        val ks = loadPkcsKeyStore("cert.p12", KEYSTORE_PASSWORD)
        for (alias in ks.aliases()) {
            if (all) {
                ks.deleteEntry(alias)
            } else {
                if (alias != KEY_ALIAS)
                    ks.deleteEntry(alias)
            }
        }
        savePkcsKeyStore(ks, "cert.p12", KEYSTORE_PASSWORD)
    }

    private fun sslConnect1() {
        val sslConnector = SSLConnector()

        if (usePkcsKeyStore) {
            sslConnector.init(loadPkcsKeyStore("cert.p12", KEYSTORE_PASSWORD),
                KEYSTORE_PASSWORD)

        } else {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            sslConnector.init(keyStore, "")
        }

        // Use coroutine to avoid NetworkOnMainThreadException
        GlobalScope.launch(Dispatchers.Default) {
            // connect from Virtual Device to local PC
            sslConnector.connect("10.0.2.2", 1443)
            sslConnector.sendMessage("SSLConnector Hello\n")
            sslConnector.close()
        }
    }

    private fun sslConnect2() {
        // connect from Virtual Device to local PC
        val socketClient = NettySocketClient("10.0.2.2", 1443)

        if (usePkcsKeyStore) {
            socketClient.init(loadPkcsKeyStore("cert.p12", KEYSTORE_PASSWORD),
                    KEYSTORE_PASSWORD)
        } else {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            socketClient.init(keyStore, "")
        }

        socketClient.open()
        socketClient.sendMessage("NettySocketClient Hello\n")
        socketClient.close()
    }

    private fun generateKeyPairToKeystore(): KeyPair {
        val start: Calendar = Calendar.getInstance()
        val end: Calendar = Calendar.getInstance()
        end.add(Calendar.YEAR, 10)

        val spec: AlgorithmParameterSpec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
//                KeyProperties.PURPOSE_SIGN
                KeyProperties.PURPOSE_DECRYPT or
                        KeyProperties.PURPOSE_ENCRYPT or
                        KeyProperties.PURPOSE_SIGN or
                        KeyProperties.PURPOSE_VERIFY
            )
                    .setCertificateSubject(X500Principal("${RSA_CERT_SUBJECT_PREFIX}$KEY_ALIAS"))
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setDigests(
                        KeyProperties.DIGEST_SHA256,
                    )
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(start.time)
                    .setCertificateNotAfter(end.time)
                    .setKeySize(RSA_KEY_SIZE)
                    .build()
        } else {
            KeyPairGeneratorSpec.Builder(applicationContext)
                    .setAlias(KEY_ALIAS)
                    .setSubject(X500Principal("${RSA_CERT_SUBJECT_PREFIX}$KEY_ALIAS"))
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

    fun generateKeyPair(): KeyPair {
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(
            ALGORITHM_RSA, PRIVIDER_NAME_SPONGY_CASTLE
        )

        keyPairGenerator.initialize(2048)
        return keyPairGenerator.generateKeyPair()
    }

    fun generateCertificatesToPkcs(): KeyPair {
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(
            ALGORITHM_RSA, PRIVIDER_NAME_SPONGY_CASTLE
        )

        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = keyPair.public
        val privateKey = keyPair.private

//        val certificateFactory = CertificateFactory.getInstance("X.509")
//        val certCA: Certificate = certificateFactory.generateCertificate(
//            FileInputStream(File(dataDir.path + "/CAcert.pem"))
//        )

        val certCA: Certificate = createCertificate("CN=CA", "CN=Ingenico", publicKey, privateKey)
        val issuerDn = (certCA as X509Certificate).subjectDN.name

        val outChain = arrayOf(
            createCertificate("CN=Client", issuerDn, publicKey, privateKey),
//            certCA
        )

        val keyStore = KeyStore.getInstance("PKCS12", PRIVIDER_NAME_SPONGY_CASTLE)
        keyStore.load(null)
        keyStore.setKeyEntry(KEY_ALIAS, privateKey, KEYSTORE_PASSWORD.toCharArray(), outChain)

        for (alias in keyStore.aliases()) {
            Log.w("App", alias)
        }

        savePkcsKeyStore(keyStore, "cert.p12", KEYSTORE_PASSWORD)
        return keyPair
    }

    private fun createCertificate(
        dn: String,
        issuer: String,
        publicKey: PublicKey,
        privateKey: PrivateKey
    ): X509Certificate {
        val certGenerator = X509V3CertificateGenerator()
        certGenerator.setSerialNumber(BigInteger.valueOf(Math.abs(Random().nextLong())))
        certGenerator.setSubjectDN(X509Name(dn))
        certGenerator.setIssuerDN(X509Name(issuer)) // Set issuer!
        certGenerator.setNotBefore(Calendar.getInstance().time)
        val end: Calendar = Calendar.getInstance()
        end.add(Calendar.YEAR, 10)
        certGenerator.setNotAfter(end.time)
        certGenerator.setPublicKey(publicKey)
        certGenerator.setSignatureAlgorithm("SHA256withRSA")
        return certGenerator.generate(privateKey, PRIVIDER_NAME_SPONGY_CASTLE) as X509Certificate
    }

    //Create the certificate signing request (CSR) from private and public keys
    fun generateCSR(keyPair: KeyPair, cn: String?): PKCS10CertificationRequest {
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
        return csrBuilder.build(signer)
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

        private const val KEY_ALIAS = "host_ssl"
        private const val RSA_KEY_SIZE = 2048
        private const val RSA_CERT_SUBJECT_PREFIX = "CN="
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEYSTORE_PASSWORD = "pass"
        private const val ALGORITHM_RSA = "RSA"
        private const val PRIVIDER_NAME_SPONGY_CASTLE = "SC"
    }
}