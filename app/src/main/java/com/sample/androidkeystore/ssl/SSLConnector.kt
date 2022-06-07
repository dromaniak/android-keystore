package com.sample.androidkeystore.ssl

import android.util.Log
import java.io.BufferedWriter
import java.io.OutputStreamWriter
import java.security.KeyStore
import java.security.SecureRandom
import javax.net.ssl.*


class SSLConnector {

    private var sslContext: SSLContext? = null
    private var sslSocket: SSLSocket? = null

    fun init(keyStore: KeyStore, password: String?) {
        val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keyStore, password?.toCharArray())
        val keyManagers = keyManagerFactory.keyManagers

        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(keyStore)
        val trustManagers = trustManagerFactory.trustManagers

        sslContext = SSLContext.getInstance("TLS")
        sslContext?.init(keyManagers, trustManagers, SecureRandom())
        val sslEngine = sslContext?.createSSLEngine()
        sslEngine?.useClientMode = true
        sslEngine?.needClientAuth = false
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