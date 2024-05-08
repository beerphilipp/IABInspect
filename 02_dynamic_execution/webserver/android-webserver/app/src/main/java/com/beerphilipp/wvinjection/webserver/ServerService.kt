package com.beerphilipp.wvinjection.webserver

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.call
import io.ktor.server.engine.ApplicationEngineEnvironment
import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore

class ServerService : Service() {

    private val TAG: String = "33WV_WEBSITE44"

    private lateinit var notificationManager: NotificationManager

    var isRunning = false

    lateinit var keyStoreFile: File
    lateinit var keyStore: KeyStore

    lateinit var environment: ApplicationEngineEnvironment

    lateinit var server: NettyApplicationEngine


    override fun onCreate() {
        super.onCreate()

        // Copy the keystore.bks as a file into memory
        val inputStream: InputStream = assets.open("keystore.bks")
        val outputFile: File = File(this.filesDir, "keystore.bks")
        val outputStream: OutputStream = FileOutputStream(outputFile)
        val buffer = ByteArray(1024)
        var length: Int
        while (inputStream.read(buffer).also { length = it } > 0) {
            outputStream.write(buffer, 0, length)
        }
        outputStream.flush()
        outputStream.close()
        inputStream.close()


        keyStoreFile = File(this.filesDir, "keystore.bks")
        //val keyStoreFile: FileInputStream = assets.open("keystore.bks") as FileInputStream
        keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            keyStoreFile.inputStream().use {
                load(it, "password".toCharArray())
            }
        }

        environment = applicationEngineEnvironment {
            connector {
                host = "127.0.0.1"
                port = 13276
            }
            sslConnector(
                keyStore = keyStore,
                keyAlias = "alias",
                keyStorePassword = { "password".toCharArray() },
                privateKeyPassword = { "pass".toCharArray() }
            ) {
                port = 8443
                keyStorePath = keyStoreFile
            }
            module {
                routing {
                    get {
                        call.respondText(
                            assets.open("index.html").bufferedReader().use { it.readText() },
                            ContentType.Text.Html
                        )
                        call.response.status(HttpStatusCode(200, "OK"))
                    }

                    post("/report") {
                        // get the content
                        val content = call.receiveText()
                        // Log the content
                        Log.i(TAG, content)
                        call.respondText("OK", ContentType.Text.Plain)
                    }
                }
            }
        }

        server = embeddedServer(Netty, environment) {}


    }

    override fun onBind(intent: Intent): IBinder? {
        return null;
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {

        getNotificationManager()
        createChannel()

        if (!isRunning) {
            startServer()
        }

        return START_STICKY
    }

    override fun stopService(name: Intent?): Boolean {
        stopServer()
        return super.stopService(name)
    }

    private fun createChannel() {
        val notificationChannel = NotificationChannel(
            "CHANNEL_ID2",
            "Channel 2",
            NotificationManager.IMPORTANCE_LOW
        )
        notificationManager.createNotificationChannel(notificationChannel)
    }

    private fun getNotificationManager() {
        notificationManager = ContextCompat.getSystemService(
            this,
            NotificationManager::class.java
        ) as NotificationManager
    }

    private fun buildNotification(): Notification {
        val title = "Running"

        return NotificationCompat.Builder(this, "CHANNEL_ID2")
            .setContentTitle("Web server")
            .setOngoing(true)
            .setContentText(title)
            .setOngoing(true)
            .build()
    }

    private fun startServer() {
        if (!isRunning) {
            isRunning = true
            startForeground(1, buildNotification())
            server.start()
        }
    }

    private fun stopServer() {
        if (isRunning) {
            isRunning = false
            server.stop()
            stopForeground(true)
        }
    }
}