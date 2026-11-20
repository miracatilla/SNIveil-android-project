package com.sniveil.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var logText: TextView
    private lateinit var fakeSniInput: EditText
    private lateinit var fragmentSizeInput: EditText
    private lateinit var toggleButton: Button

    private val vpnPrepareLauncher =
        registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                startVpn()
            } else {
                statusText.text = "Durum: VPN izni reddedildi"
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        logText = findViewById(R.id.logText)
        fakeSniInput = findViewById(R.id.fakeSniInput)
        fragmentSizeInput = findViewById(R.id.fragmentSizeInput)
        toggleButton = findViewById(R.id.toggleButton)

        val prefs = getSharedPreferences(Prefs.NAME, MODE_PRIVATE)
        fakeSniInput.setText(prefs.getString(Prefs.FAKE_SNI, "www.sabit-izinli-site.com"))
        fragmentSizeInput.setText(prefs.getInt(Prefs.FRAGMENT_SIZE, 2).toString())

        toggleButton.setOnClickListener {
            if (SniFragVpnService.isRunning) {
                stopService(Intent(this, SniFragVpnService::class.java))
                statusText.text = "Durum: Bağlı değil"
                toggleButton.text = "Bağlan"
            } else {
                saveSettings()
                val intent = VpnService.prepare(this)
                if (intent != null) {
                    vpnPrepareLauncher.launch(intent)
                } else {
                    startVpn()
                }
            }
        }

        LogBus.listener = { line ->
            runOnUiThread {
                logText.append(line + "\n")
            }
        }
    }

    private fun saveSettings() {
        val prefs = getSharedPreferences(Prefs.NAME, MODE_PRIVATE)
        prefs.edit()
            .putString(Prefs.FAKE_SNI, fakeSniInput.text.toString().ifBlank { "www.sabit-izinli-site.com" })
            .putInt(Prefs.FRAGMENT_SIZE, fragmentSizeInput.text.toString().toIntOrNull() ?: 2)
            .apply()
    }

    private fun startVpn() {
        startForegroundService(Intent(this, SniFragVpnService::class.java))
        statusText.text = "Durum: Bağlı"
        toggleButton.text = "Kes"
    }

    override fun onResume() {
        super.onResume()
        toggleButton.text = if (SniFragVpnService.isRunning) "Kes" else "Bağlan"
        statusText.text = if (SniFragVpnService.isRunning) "Durum: Bağlı" else "Durum: Bağlı değil"
    }
}

object Prefs {
    const val NAME = "sniveil_prefs"
    const val FAKE_SNI = "fake_sni"
    const val FRAGMENT_SIZE = "fragment_size"
}

/** Tiny pub/sub so the service can push log lines to the UI without a bound-service dance. */
object LogBus {
    var listener: ((String) -> Unit)? = null
    fun log(line: String) {
        listener?.invoke(line)
    }
}
