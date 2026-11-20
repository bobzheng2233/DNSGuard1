package com.dnsguard.android

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class MainActivity : Activity() {

    private lateinit var dohInput: EditText
    private lateinit var httpsHostInput: EditText
    private lateinit var httpsPortInput: EditText
    private lateinit var socksHostInput: EditText
    private lateinit var socksPortInput: EditText
    private lateinit var forceUdpCheck: CheckBox
    private lateinit var quicCheck: CheckBox
    private lateinit var bypassLanCheck: CheckBox
    private lateinit var toggleBtn: Button
    private lateinit var logView: TextView

    private val logListener: (String) -> Unit = { line ->
        runOnUiThread {
            logView.append("$line\n")
            updateButtonState()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val cfg = ProxyConfig.load(this)

        val scroll = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#0B1020"))
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(42, 48, 42, 64)
        }

        val title = TextView(this).apply {
            text = "DNSGuard 加密与代理工具"
            textSize = 21f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#38BDF8"))
        }
        val subtitle = TextView(this).apply {
            text = "DoH 加密解析 · HTTPS/SOCKS5 代理 · 强制 UDP · 网页无损"
            textSize = 13f
            setTextColor(Color.parseColor("#93A4C7"))
            setPadding(0, 8, 0, 28)
        }
        root.addView(title)
        root.addView(subtitle)

        dohInput = addField(root, "DoH 加密 DNS 地址", cfg.dohUrl)
        httpsHostInput = addField(root, "HTTPS 代理服务器（选填）", cfg.httpsHost)
        httpsPortInput = addField(root, "HTTPS 代理端口", cfg.httpsPort.toString(), true)
        socksHostInput = addField(root, "SOCKS5 代理服务器（选填）", cfg.socksHost)
        socksPortInput = addField(root, "SOCKS5 代理端口", cfg.socksPort.toString(), true)

        forceUdpCheck = addCheck(root, "强制 UDP 流量走 SOCKS5 代理", cfg.forceUdpProxy)
        quicCheck = addCheck(root, "QUIC (UDP/443) 智能回退 TCP（保障网页无影响）", cfg.quicFallback)
        bypassLanCheck = addCheck(root, "绕过局域网地址（192.168.x.x / 10.x.x.x）", cfg.bypassLan)

        toggleBtn = Button(this).apply {
            setTextColor(Color.parseColor("#041322"))
            setBackgroundColor(Color.parseColor("#38BDF8"))
            typeface = Typeface.DEFAULT_BOLD
            setOnClickListener { onToggleVpn() }
        }
        val testBtn = Button(this).apply {
            text = "测试 DoH 加密连通性"
            setTextColor(Color.WHITE)
            setBackgroundColor(Color.parseColor("#1E293B"))
            setOnClickListener { testDohConnectivity() }
        }

        val lp = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = 22 }
        root.addView(toggleBtn, lp)
        root.addView(testBtn, lp)

        val logLabel = TextView(this).apply {
            text = "运行日志"
            textSize = 14f
            setTextColor(Color.parseColor("#93A4C7"))
            setPadding(0, 28, 0, 10)
        }
        logView = TextView(this).apply {
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.parseColor("#CBD5E1"))
            setBackgroundColor(Color.parseColor("#070B16"))
            setPadding(24, 24, 24, 24)
            minLines = 7
            gravity = Gravity.TOP
            text = LogBus.snapshot().ifBlank { "就绪。填写配置后点击上方按钮启动。\n" }
        }
        root.addView(logLabel)
        root.addView(logView)

        scroll.addView(root)
        setContentView(scroll)
        LogBus.addListener(logListener)
        updateButtonState()
    }

    override fun onDestroy() {
        LogBus.removeListener(logListener)
        super.onDestroy()
    }

    private fun addField(parent: LinearLayout, label: String, value: String, numeric: Boolean = false): EditText {
        val tv = TextView(this).apply {
            text = label
            textSize = 13f
            setTextColor(Color.parseColor("#93A4C7"))
            setPadding(0, 14, 0, 6)
        }
        val et = EditText(this).apply {
            setText(value)
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#64748B"))
            setBackgroundColor(Color.parseColor("#1A2442"))
            setPadding(24, 20, 24, 20)
            if (numeric) inputType = InputType.TYPE_CLASS_NUMBER
        }
        parent.addView(tv)
        parent.addView(et)
        return et
    }

    private fun addCheck(parent: LinearLayout, label: String, checked: Boolean): CheckBox {
        val cb = CheckBox(this).apply {
            text = label
            isChecked = checked
            setTextColor(Color.parseColor("#E6EDF7"))
            setPadding(8, 12, 8, 12)
        }
        parent.addView(cb)
        return cb
    }

    private fun saveCurrentConfig(): ProxyConfig {
        val cfg = ProxyConfig(
            dohUrl = dohInput.text.toString().trim().ifBlank { "https://1.1.1.1/dns-query" },
            httpsHost = httpsHostInput.text.toString().trim(),
            httpsPort = httpsPortInput.text.toString().toIntOrNull() ?: 443,
            socksHost = socksHostInput.text.toString().trim(),
            socksPort = socksPortInput.text.toString().toIntOrNull() ?: 1080,
            forceUdpProxy = forceUdpCheck.isChecked,
            quicFallback = quicCheck.isChecked,
            bypassLan = bypassLanCheck.isChecked
        )
        cfg.save(this)
        return cfg
    }

    private fun onToggleVpn() {
        if (LogBus.isRunning) {
            val stopIntent = Intent(this, DnsGuardVpnService::class.java).apply {
                action = DnsGuardVpnService.ACTION_STOP
            }
            startService(stopIntent)
            updateButtonState()
            return
        }
        saveCurrentConfig()
        val intent = VpnService.prepare(this)
        if (intent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(intent, REQ_VPN)
        } else {
            startVpnService()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            startVpnService()
        } else if (requestCode == REQ_VPN) {
            LogBus.log("用户取消了 VPN 授权")
        }
    }

    private fun startVpnService() {
        val svc = Intent(this, DnsGuardVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(svc)
        } else {
            startService(svc)
        }
        updateButtonState()
    }

    private fun updateButtonState() {
        if (LogBus.isRunning) {
            toggleBtn.text = "停止 DNSGuard 保护"
            toggleBtn.setBackgroundColor(Color.parseColor("#F87171"))
        } else {
            toggleBtn.text = "启动 DNSGuard 加密与代理"
            toggleBtn.setBackgroundColor(Color.parseColor("#38BDF8"))
        }
    }

    private fun testDohConnectivity() {
        val cfg = saveCurrentConfig()
        LogBus.log("正在测试 DoH 节点: ${cfg.dohUrl}")
        thread {
            val t0 = System.currentTimeMillis()
            try {
                val conn = (URL("${cfg.dohUrl}?name=example.com&type=A").openConnection() as HttpURLConnection).apply {
                    connectTimeout = 5000
                    readTimeout = 5000
                    setRequestProperty("Accept", "application/dns-json")
                }
                val code = conn.responseCode
                val ms = System.currentTimeMillis() - t0
                LogBus.log("DoH 测试完成: HTTP $code (${ms}ms)")
            } catch (e: Exception) {
                LogBus.log("DoH 测试失败: ${e.message}")
            }
        }
    }

    companion object {
        private const val REQ_VPN = 9001
    }
}
