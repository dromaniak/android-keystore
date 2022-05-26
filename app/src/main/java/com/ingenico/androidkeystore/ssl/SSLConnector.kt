package com.ingenico.androidkeystore.ssl

import android.os.StrictMode
import android.util.Log
import java.io.BufferedWriter
import java.io.OutputStreamWriter
import java.net.Socket
import java.security.KeyStore
import java.security.SecureRandom
import javax.net.ssl.*


class SSLConnector {

    private var sslContext: SSLContext? = null

    fun init(keyStore: KeyStore) {
        val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keyStore, "pass".toCharArray())
        val keyManagers = keyManagerFactory.keyManagers

        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(keyStore)
        val trustManagers = trustManagerFactory.trustManagers

        sslContext = SSLContext.getInstance("TLS")
        sslContext?.init(keyManagers, trustManagers, null)
        val sslEngine = sslContext?.createSSLEngine()
        sslEngine?.useClientMode = true
    }

    fun connect(hostName: String, port: Int) {

        val policy = StrictMode.ThreadPolicy.Builder().permitAll().build()
        StrictMode.setThreadPolicy(policy)

        var sslSocket: SSLSocket? = null

        try {
            sslSocket = sslContext?.socketFactory?.createSocket(hostName, port) as SSLSocket
            sslSocket.startHandshake()
            val out = BufferedWriter(OutputStreamWriter(sslSocket.getOutputStream()))
            out.write("Hello")
        } catch (e: Exception) {
            e.message?.let { Log.w("App", it) };
        } finally {
            sslSocket?.close()
        }
    }
}