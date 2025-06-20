package com.sample.androidkeystore.ssl

import android.util.Log
import io.netty.bootstrap.Bootstrap
import io.netty.channel.*
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.handler.codec.bytes.ByteArrayDecoder
import io.netty.handler.codec.bytes.ByteArrayEncoder
import io.netty.handler.ssl.SslHandler
import java.io.IOException
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory

class NettySocketClient(private val remoteHost: String, private val remotePort: Int) {
    private var eventloopGroop: EventLoopGroup? = null
    private val openned = AtomicBoolean(false)
    private var channelFuture: ChannelFuture? = null
    private var clientHandler: BlockingByteArrayClientHandler? = null

    private var sslContext: SSLContext? = null

    fun init(keyStore: KeyStore, password: String?) {
        val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keyStore, password?.toCharArray())
        val keyManagers = keyManagerFactory.keyManagers

        val certChain = keyStore.aliases().toList().mapNotNull { alias ->
            keyStore.getCertificateChain(alias)
                ?.filterIsInstance<X509Certificate>()
        }.flatten().toTypedArray()

        val trustStore = createTrustStoreFromChain(certChain)
        val trustManagerFactory =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(trustStore)
        val trustManagers = trustManagerFactory.trustManagers

        sslContext = SSLContext.getInstance("TLS")
        sslContext?.init(keyManagers, trustManagers, SecureRandom())
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

    @JvmOverloads
    @Throws(Exception::class)
    fun open(eventLoopGroup: EventLoopGroup? = null) {
        try {
            if (openned.compareAndSet(false, true)) {
                eventloopGroop = eventLoopGroup ?: NioEventLoopGroup()
                val bootstrap = Bootstrap()
                val handler = BlockingByteArrayClientHandler(
                        this
                )
                clientHandler = handler
                bootstrap.group(eventloopGroop).channel(NioSocketChannel::class.java)
                        .handler(object : ChannelInitializer<SocketChannel>() {
                            @Throws(Exception::class)
                            override fun initChannel(ch: SocketChannel) {
                                val pipeline = ch.pipeline()
                                val engine: SSLEngine = sslContext!!.createSSLEngine()

                                engine.useClientMode = true
                                engine.needClientAuth = false
                                pipeline.addLast("ssl", SslHandler(engine))
                                pipeline.addLast(
                                        "bytearray-decoder",
                                        ByteArrayDecoder()
                                )
                                pipeline.addLast(
                                        "bytearray-encoder",
                                        ByteArrayEncoder()
                                )
                                pipeline.addLast("handler", handler)
                            }
                        })
                channelFuture = bootstrap.connect(remoteHost, remotePort)
                        .sync()
            }
        } catch (e: Exception) {
            e.message?.let { Log.w("App", it) }
            close()
        }

    }

    fun close() {
        if (eventloopGroop != null && openned.compareAndSet(true, false)) {
            eventloopGroop!!.shutdownGracefully()
        }
    }

    @Throws(Exception::class)
    fun exceptionCaught(cause: Throwable?) {
        close()
        throw IOException("Disconnected unpextectly.", cause)
    }

    fun sendMessage(message: String): ByteArray? {
        val latch = CountDownLatch(1)
        try {
            clientHandler!!.latch = latch
//        channelFuture!!.channel().writeAndFlush(message)
            channelFuture!!.channel().writeAndFlush(message.toByteArray()).sync()
        } catch (e: Exception) {
            e.message?.let { Log.w("App", it) }
            close()
        }
        return ByteArray(0)

        try {
            latch.await()
        } catch (e: InterruptedException) {
        }
        return clientHandler!!.response
    }

    protected class BlockingByteArrayClientHandler(
        var nettySocketClient: NettySocketClient
    ) : SimpleChannelInboundHandler<ByteArray?>() {
        var latch: CountDownLatch? = null
        var response: ByteArray? = null

        @Throws(Exception::class)
        override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
            ctx.close()
            nettySocketClient.exceptionCaught(cause)
        }

        @Throws(Exception::class)
        override fun channelRead0(ctx: ChannelHandlerContext, msg: ByteArray?) {
            response = msg
            if (latch != null) latch!!.countDown()
        }

    }

//    companion object {
//        @Throws(Exception::class)
//        @JvmStatic
//        fun main(args: Array<String>) {
//            val host = if (args.size > 0) args[0] else "localhost"
//            val port = if (args.size > 1) args[1].toInt() else 8443
//            val socketClient = NettySocketClient(host, port)
//            socketClient.open()
//            val response = socketClient.sendMessage("NettySocketClient Hello".toByteArray())
//            socketClient.close()
//        }
//    }
}