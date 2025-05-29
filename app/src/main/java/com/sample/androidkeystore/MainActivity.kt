package com.sample.androidkeystore

import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.security.KeyChain
import android.security.KeyChainAliasCallback
import android.text.method.ScrollingMovementMethod
import android.util.Base64
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.sample.androidkeystore.ssl.SSLConnector
import com.sample.androidkeystore.utils.BouncyCastleSecurityUtils
import com.sample.androidkeystore.utils.SpongyCastleSecurityUtils
import kotlinx.coroutines.*
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FileWriter
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory


@Suppress("DEPRECATION")
class MainActivity : AppCompatActivity() {
    private val useBouncyCastleProvider = true
    private lateinit var subjectName: String

    private val securityUtils = when (useBouncyCastleProvider) {
        true -> BouncyCastleSecurityUtils()
        else -> SpongyCastleSecurityUtils()
    }

    private var keyPair: KeyPair? = null
    private var usePkcsKeyStore = false


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

        subjectName = "Client"
        val provider = Security.getProvider(securityUtils.securityProvider.name)
        if (provider != null) {
            log(provider.info)
        } else {
            log("No provider")
        }

        log("is replaced by")
        Security.removeProvider(securityUtils.securityProvider.name)
        Security.addProvider(securityUtils.securityProvider)
        log(Security.getProvider(securityUtils.securityProvider.name).info)

        log("\nList of providers:")
        Security.getProviders().forEach { log(it.name) }


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
                    this.keyPair = generateKeyPairToPkcs()
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
            R.id.action_transfer_from_pkcs12_to_keystore -> {
                transferFromPkcsToKeystore()
                showKeys()
            }

            R.id.action_transfer_from_keystore_to_pkcs12 -> {
                transferFromKeystoreToPkcs()
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
            R.id.action_ssl_connect1 -> {
                sslConnect()
            }
            R.id.action_encrypt_sample_data -> {
                encryptSampleData()
            }
            R.id.action_decrypt_data -> {
                decryptData()
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

        val keyPairCsr = securityUtils.generateCsr(this.keyPair!!, subjectName)
        logClear()
        log("CSR:")
        log(bytes2HexString(keyPairCsr))

        var csr: String? = "-----BEGIN CERTIFICATE REQUEST-----\n"
        csr += Base64.encodeToString(keyPairCsr, Base64.DEFAULT)
        csr += "-----END CERTIFICATE REQUEST-----"


        runOnUiThread {
            val fw = FileWriter(File(applicationInfo.dataDir + "/${CSR_BASE64_FILE}"))
            fw.write(csr)
            fw.close()

            val fos = FileOutputStream(File(applicationInfo.dataDir + "/${CSR_FILE}"))
            fos.write(keyPairCsr)
            fos.close()
        }
    }

    private fun importSignedCertToKeystore() {
        /*
            Works only if private key available
            https://stackoverflow.com/questions/70897815/why-is-androidkeystore-transforming-privatekeyentry-into-a-trustedcertifiateentr
         */
        if (keyPair == null) {
            val toast = Toast.makeText(
                    applicationContext,
                    "No KeyPair available",
                    Toast.LENGTH_LONG
            )
            toast.show()
            return
        }

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val cert: Certificate = certificateFactory.generateCertificate(
            FileInputStream(File(applicationInfo.dataDir + "/${CERT_SIGNED_FILE}"))
        )

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val newEntry = KeyStore.PrivateKeyEntry(
            keyPair!!.private,
            arrayOf(cert)
        )

        keyStore.setEntry(KEY_ALIAS, newEntry, null)
    }

    private fun importSignedCertToPkcs() {
        val certificateFactory = CertificateFactory.getInstance("X.509")
        val cert: Certificate = certificateFactory.generateCertificate(
            FileInputStream(File(applicationInfo.dataDir + "/${CERT_SIGNED_FILE}"))
        )

        val keyStore = loadPkcsKeyStore(PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)
        val key = keyStore.getKey(KEY_ALIAS, null)
        if (key == null) {
            val toast = Toast.makeText(
                    applicationContext,
                    "No Private Key found",
                    Toast.LENGTH_LONG
            )
            toast.show()
            return
        }

        val privateKey = key as PrivateKey
        val newEntry = KeyStore.PrivateKeyEntry(
            privateKey,
            arrayOf(cert)
        )
        keyStore.setEntry(KEY_ALIAS, newEntry, null)
        savePkcsKeyStore(keyStore, PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)
    }

    private fun importCa() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certCA: Certificate = certificateFactory.generateCertificate(
            FileInputStream(File(applicationInfo.dataDir + "/${CA_FILE}"))
        )

        val caName = (certCA as X509Certificate).subjectDN.name
        keyStore.setCertificateEntry(caName, certCA)
    }

    private fun importCaToPkcs() {
        val keyStore = loadPkcsKeyStore(PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certCA: Certificate = certificateFactory.generateCertificate(
            FileInputStream(File(applicationInfo.dataDir + "/${CA_FILE}"))
        )

        val caName = (certCA as X509Certificate).subjectDN.name
        keyStore.setCertificateEntry(caName, certCA)
        savePkcsKeyStore(keyStore, PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)
    }

    private fun showPkcsCertificate() {
        if (File(applicationInfo.dataDir + "/${PKCS_KEYSTORE_FILE}").exists().not()) {
            logClear()
            log("$PKCS_KEYSTORE_FILE not found")
            return
        }

        val keyStore = loadPkcsKeyStore(PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)

        logClear()
        for (alias in keyStore.aliases()) {
            val cert = keyStore.getEntry(alias, null)
            log(cert.toString())
        }
    }

    private fun transferFromPkcsToKeystore() {
        val keyStoreFrom = loadPkcsKeyStore(PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)
        val keyStoreTo = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        for (alias in keyStoreFrom.aliases()) {
            val entry = keyStoreFrom.getEntry(alias, null)
            keyStoreTo.setEntry(alias, entry, null)
        }
    }

    private fun transferFromKeystoreToPkcs() {
        try {
            val keyStoreFrom = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val keyStoreTo = loadPkcsKeyStore(PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)

            for (alias in keyStoreFrom.aliases()) {
                keyStoreTo.setEntry(alias, keyStoreFrom.getEntry(alias, null), null)
            }

            savePkcsKeyStore(keyStoreTo, PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)
        } catch (e: Exception) {
            val toast = Toast.makeText(
                applicationContext,
                e.message,
                Toast.LENGTH_LONG
            )
            toast.show()
        }

    }

    private fun loadPkcsKeyStore(fileName: String, password: String): KeyStore {
        val keyStore = KeyStore.getInstance(PKCS_KEYSTORE, securityUtils.securityProvider.name)
        val fis = FileInputStream(File(applicationInfo.dataDir + "/" + fileName))
        fis.use {keyStore.load(it, password.toCharArray()) }
        return keyStore
    }

    private fun savePkcsKeyStore(keyStore: KeyStore, fileName: String, password: String) {
        val fos = FileOutputStream(File(applicationInfo.dataDir + "/" + fileName))
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
        val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        for (alias in keyStore.aliases()) {
            val entry = keyStore.getEntry(alias, null)
            keyEntries.add(entry)
        }
        return keyEntries
    }

    private fun deleteKeys(all: Boolean = false) {
        val ks: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

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
        val ks = loadPkcsKeyStore(PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)
        for (alias in ks.aliases()) {
            if (all) {
                ks.deleteEntry(alias)
            } else {
                if (alias != KEY_ALIAS)
                    ks.deleteEntry(alias)
            }
        }
        savePkcsKeyStore(ks, PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)
    }

    private fun sslConnect() {
        val sslConnector = SSLConnector()

        GlobalScope.launch {
            try {
                val alias = selectKeyAlias(this@MainActivity)
                val (privateKey, certChain) = loadKeyChainEntry(this@MainActivity, alias)

                val keyStore: KeyStore = KeyStore.getInstance("PKCS12")
                keyStore.load(null, null) // пустой кейстор
                keyStore.setKeyEntry("client", privateKey, null, certChain)
                sslConnector.init(keyStore)
                
                // connect from Virtual Device to local PC
                sslConnector.connect(HOST_IP, HOST_PORT)
                sslConnector.sendMessage("SSLConnector Hello\n")
                sslConnector.close()

            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    // suspend-функция для выбора alias
    suspend fun selectKeyAlias(context: Activity): String = suspendCancellableCoroutine { cont ->
        KeyChain.choosePrivateKeyAlias(
            context, { alias ->
                if (alias != null) {
                    cont.resume(alias) {}
                } else {
                    cont.cancel(CancellationException("User cancelled key selection"))
                }
            },
            null, null, null, -1, null
        )
    }

    // suspend-функция получения ключа и цепочки
    suspend fun loadKeyChainEntry(context: Context, alias: String): Pair<PrivateKey?, Array<X509Certificate>?> =
        withContext(Dispatchers.IO) {
            val privateKey = KeyChain.getPrivateKey(context, alias)
            val certChain = KeyChain.getCertificateChain(context, alias)
            Pair(privateKey, certChain)
        }

    private fun generateKeyPairToKeystore(): KeyPair {
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(
                ALGORITHM_RSA, securityUtils.securityProvider.name
        )

        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = keyPair.public
        val privateKey = keyPair.private

        val outChain = arrayOf(
                securityUtils.createCertificate("CN=SubjectName", "CN=IssuerName", publicKey, privateKey),
        )

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        keyStore.setKeyEntry(KEY_ALIAS, privateKey, "".toCharArray(), outChain)
        return keyPair
    }

    private fun generateKeyPair(): KeyPair {
        return securityUtils.generateKeyPair()
    }

    private fun generateKeyPairToPkcs(): KeyPair {
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(
            ALGORITHM_RSA, securityUtils.securityProvider.name
        )

        keyPairGenerator.initialize(2048)
        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = keyPair.public
        val privateKey = keyPair.private

        val outChain = arrayOf(
            securityUtils.createCertificate("CN=SubjectName", "CN=IssuerName", publicKey, privateKey),
        )

        val keyStore = KeyStore.getInstance(PKCS_KEYSTORE, securityUtils.securityProvider.name)
        keyStore.load(null)
        keyStore.setKeyEntry(KEY_ALIAS, privateKey, KEYSTORE_PASSWORD.toCharArray(), outChain)

        savePkcsKeyStore(keyStore, PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)
        return keyPair
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

    private fun encryptSampleData() {
        val keyStore: KeyStore
        if (usePkcsKeyStore) {
            keyStore = loadPkcsKeyStore(PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)
        } else {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        }
        val publicKey = keyStore.getCertificate(KEY_ALIAS)?.publicKey
        val sampleData = "Sample Data to Encrypt"

        if (publicKey == null) {
            val toast = Toast.makeText(
                applicationContext,
                "No Encryption Certificate found",
                Toast.LENGTH_LONG
            )
            toast.show()
            return
        }

        logClear()
        log("RSA Encryption\n\nData to encrypt:")
        log(sampleData)
        val encyptedData = securityUtils.encrypt(publicKey, sampleData.toByteArray())
        log("\nEncrypted data:")
        log(bytes2HexString(encyptedData))

        runOnUiThread {
            val fos = FileOutputStream(File(applicationInfo.dataDir + "/${ENCRYPTED_DATA_FILE}"))
            fos.write(encyptedData)
            fos.close()
        }
    }

    private fun decryptData() {
        val keyStore: KeyStore
        if (usePkcsKeyStore) {
            keyStore = loadPkcsKeyStore(PKCS_KEYSTORE_FILE, KEYSTORE_PASSWORD)
        } else {
            keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        }

        val key = keyStore.getKey(KEY_ALIAS, null)
        if (key == null) {
            val toast = Toast.makeText(
                applicationContext,
                "No Decryption Key found",
                Toast.LENGTH_LONG
            )
            toast.show()
            return
        }

        val privateKey = key as PrivateKey
        val fis = FileInputStream(File(applicationInfo.dataDir + "/${ENCRYPTED_DATA_FILE}"))
        val encryptedData = fis.readBytes()
        fis.close()

        logClear()
        log("RSA Decryption\n\nData to decrypt:")
        log(bytes2HexString(encryptedData))

        val decryptedData = securityUtils.decrypt(privateKey, encryptedData)
        log("\nDecrypted data:")
        log(String(decryptedData))
    }

    companion object {
        private const val EMPTY_STRING = ""

        private const val KEY_ALIAS = "test_key"
        private const val RSA_KEY_SIZE = 2048
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val PKCS_KEYSTORE = "PKCS12"
        private const val PKCS_KEYSTORE_FILE = "cert.p12"
        private const val KEYSTORE_PASSWORD = "pass"
        
        private const val ALGORITHM_RSA = "RSA"
        private const val CSR_BASE64_FILE = "client_base64.csr"
        private const val CSR_FILE = "client.csr"
        private const val CERT_SIGNED_FILE = "client_signed.crt"
        private const val CA_FILE = "CAcert.pem"
        private const val ENCRYPTED_DATA_FILE = "encrypted_data.bin"

        private const val HOST_IP = "192.168.1.110"
        private const val HOST_PORT = 1443
    }
}