package com.dnsguard.android

import android.content.Context

data class ProxyConfig(
    val dohUrl: String = "https://1.1.1.1/dns-query",
    val httpsHost: String = "",
    val httpsPort: Int = 443,
    val socksHost: String = "",
    val socksPort: Int = 1080,
    val forceUdpProxy: Boolean = true,
    val quicFallback: Boolean = true,
    val bypassLan: Boolean = true
) {
    fun save(context: Context) {
        val sp = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        sp.edit()
            .putString("dohUrl", dohUrl)
            .putString("httpsHost", httpsHost)
            .putInt("httpsPort", httpsPort)
            .putString("socksHost", socksHost)
            .putInt("socksPort", socksPort)
            .putBoolean("forceUdpProxy", forceUdpProxy)
            .putBoolean("quicFallback", quicFallback)
            .putBoolean("bypassLan", bypassLan)
            .apply()
    }

    companion object {
        private const val PREFS = "dnsguard_prefs"

        fun load(context: Context): ProxyConfig {
            val sp = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            return ProxyConfig(
                dohUrl = sp.getString("dohUrl", "https://1.1.1.1/dns-query") ?: "https://1.1.1.1/dns-query",
                httpsHost = sp.getString("httpsHost", "") ?: "",
                httpsPort = sp.getInt("httpsPort", 443),
                socksHost = sp.getString("socksHost", "") ?: "",
                socksPort = sp.getInt("socksPort", 1080),
                forceUdpProxy = sp.getBoolean("forceUdpProxy", true),
                quicFallback = sp.getBoolean("quicFallback", true),
                bypassLan = sp.getBoolean("bypassLan", true)
            )
        }
    }
}
