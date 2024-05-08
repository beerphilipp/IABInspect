package com.beerphilipp.wvinjection.webserver

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViewById<Button>(R.id.startServer).setOnClickListener {
            startServer()
        }

        findViewById<Button>(R.id.stopServer).setOnClickListener {
            stopServer()
        }

        findViewById<TextView>(R.id.ipAddressText).text = getString(R.string.localIpAddressMessage, "127.0.0.1")
    }

    private fun startServer() {
        val serverService = Intent(this, ServerService::class.java)
        startService(serverService)
    }

    private fun stopServer() {
        val serverService = Intent(this, ServerService::class.java)
        stopService(serverService)
    }
}