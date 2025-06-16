package com.sample.androidkeystore.ssl

import android.util.Log
import java.io.BufferedWriter
import java.io.OutputStreamWriter
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import javax.net.ssl.*


class SSLConnector {
    private var sslContext: SSLContext? = null
    private var sslSocket: SSLSocket? = null

    fun init(clientKeyStore: KeyStore, password: String?) {
        val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(clientKeyStore, password?.toCharArray())
        val keyManagers = keyManagerFactory.keyManagers

        val certChain = clientKeyStore.aliases().toList().mapNotNull { alias ->
            clientKeyStore.getCertificateChain(alias)
            ?.filterIsInstance<X509Certificate>()
        }.flatten().toTypedArray()

        val trustStore = createTrustStoreFromChain(certChain)
        val trustManagerFactory =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(trustStore)
        val trustManagers = trustManagerFactory.trustManagers

        sslContext = SSLContext.getInstance("TLS")
        sslContext?.init(keyManagers, trustManagers, SecureRandom())
        val sslEngine = sslContext?.createSSLEngine()
        sslEngine?.useClientMode = true
        sslEngine?.needClientAuth = true
    }

    private fun createTrustStoreFromChain(certChain: Array<X509Certificate>): KeyStore {
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
        trustStore.load(null, null)

        certChain.forEachIndexed { index, certificate ->
            val alias = "cert-$index"
            trustStore.setCertificateEntry(alias, certificate)
        }

        return trustStore
    }

    fun connect(hostName: String, port: Int) {
        try {
            sslSocket = sslContext?.socketFactory?.createSocket(hostName, port) as SSLSocket
            sslSocket?.startHandshake()
        } catch (e: Exception) {
            e.message?.let { Log.w("App", it) }
            close()
        }
    }

    fun sendMessage(message: String) {
        if (sslSocket == null)
            return
        try {
            val out = BufferedWriter(OutputStreamWriter(sslSocket?.outputStream))
            out.write(message)
            out.flush()
        } catch (e: Exception) {
            e.message?.let { Log.w("App", it) }
            close()
        }

    }

    fun close() {
        sslSocket?.close()
        sslSocket = null
    }
}