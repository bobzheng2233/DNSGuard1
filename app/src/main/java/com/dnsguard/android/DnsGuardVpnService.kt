package com.dnsguard.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class DnsGuardVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private val executor = Executors.newCachedThreadPool()
    private val writeLock = Any()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        startForegroundNotification()
        startVpn()
        return START_STICKY
    }

    private fun startForegroundNotification() {
        val channelId = "dnsguard_vpn_channel"
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(channelId, "DNSGuard 加密隧道", NotificationManager.IMPORTANCE_LOW)
            nm.createNotificationChannel(ch)
        }
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val notif = builder
            .setContentTitle("DNSGuard 正在运行")
            .setContentText("DoH 加密解析与代理保护已开启")
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    private fun startVpn() {
        if (running.getAndSet(true)) return
        val cfg = ProxyConfig.load(this)
        LogBus.isRunning = true

        try {
            val builder = Builder()
                .setSession("DNSGuard")
                .setMtu(1400)
                .addAddress("10.233.233.1", 30)
                .addDnsServer("10.233.233.2")
                .addRoute("10.233.233.2", 32)

            // 防止自身流量回环
            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: Exception) {
            }

            // Android 10+ 支持系统级 HTTP/HTTPS 代理，不解密 TLS，网页功能零影响
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && cfg.httpsHost.isNotBlank()) {
                val bypassList = if (cfg.bypassLan) {
                    listOf("localhost", "127.0.0.1", "10.*", "192.168.*", "172.16.*")
                } else {
                    emptyList()
                }
                builder.setHttpProxy(ProxyInfo.buildDirectProxy(cfg.httpsHost, cfg.httpsPort, bypassList))
                LogBus.log("已启用系统 HTTPS/HTTP 代理: ${cfg.httpsHost}:${cfg.httpsPort}")
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                LogBus.log("建立 VPN 接口失败：未获得系统授权")
                stopVpn()
                return
            }

            LogBus.log("DNSGuard 隧道已启动 | DoH: ${cfg.dohUrl}")
            if (cfg.forceUdpProxy && cfg.socksHost.isNotBlank()) {
                LogBus.log("已启用强制 UDP 走 SOCKS5: ${cfg.socksHost}:${cfg.socksPort}")
            }

            val fd = vpnInterface!!.fileDescriptor
            val input = FileInputStream(fd)
            val output = FileOutputStream(fd)

            executor.execute {
                val buf = ByteArray(4096)
                while (running.get()) {
                    try {
                        val len = input.read(buf)
                        if (len <= 0) continue
                        val packet = buf.copyOf(len)
                        handlePacket(packet, cfg, output)
                    } catch (e: Exception) {
                        if (running.get()) LogBus.log("读取隧道异常: ${e.message}")
                        break
                    }
                }
            }
        } catch (e: Exception) {
            LogBus.log("启动失败: ${e.message}")
            stopVpn()
        }
    }

    private fun handlePacket(packet: ByteArray, cfg: ProxyConfig, output: FileOutputStream) {
        if (packet.size < 28) return
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return
        val ihl = (packet[0].toInt() and 0x0F) * 4
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17 || packet.size < ihl + 8) return // UDP

        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)
        val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
        val payload = packet.copyOfRange(ihl + 8, packet.size)

        if (dstPort == 53) {
            executor.execute {
                val dnsResp = queryDoh(cfg, payload)
                if (dnsResp != null) {
                    val reply = PacketUtils.buildIpv4UdpResponse(dstIp, srcIp, dstPort, srcPort, dnsResp)
                    synchronized(writeLock) {
                        try {
                            output.write(reply)
                        } catch (_: Exception) {
                        }
                    }
                }
            }
        } else if (dstPort == 443 && cfg.quicFallback) {
            // QUIC 平滑回退：丢弃 UDP/443，浏览器自动无感回退标准 HTTPS/TCP
            return
        } else if (cfg.forceUdpProxy && cfg.socksHost.isNotBlank()) {
            executor.execute {
                val udpResp = relayViaSocks5Udp(cfg, dstIp, dstPort, payload)
                if (udpResp != null) {
                    val reply = PacketUtils.buildIpv4UdpResponse(dstIp, srcIp, dstPort, srcPort, udpResp)
                    synchronized(writeLock) {
                        try {
                            output.write(reply)
                        } catch (_: Exception) {
                        }
                    }
                }
            }
        }
    }

    private fun queryDoh(cfg: ProxyConfig, dnsQuery: ByteArray): ByteArray? {
        return try {
            val url = URL(cfg.dohUrl)
            val proxy = when {
                cfg.socksHost.isNotBlank() -> Proxy(Proxy.Type.SOCKS, InetSocketAddress(cfg.socksHost, cfg.socksPort))
                cfg.httpsHost.isNotBlank() -> Proxy(Proxy.Type.HTTP, InetSocketAddress(cfg.httpsHost, cfg.httpsPort))
                else -> Proxy.NO_PROXY
            }
            val conn = (url.openConnection(proxy) as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 5000
                readTimeout = 5000
                doOutput = true
                setRequestProperty("Content-Type", "application/dns-message")
                setRequestProperty("Accept", "application/dns-message")
            }
            conn.outputStream.use { it.write(dnsQuery) }
            if (conn.responseCode == 200) {
                conn.inputStream.use { it.readBytes() }
            } else {
                LogBus.log("DoH 返回异常状态码: ${conn.responseCode}")
                null
            }
        } catch (e: Exception) {
            LogBus.log("DoH 请求失败: ${e.message}")
            null
        }
    }

    private fun relayViaSocks5Udp(
        cfg: ProxyConfig,
        dstIp: ByteArray,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray? {
        var ctrlSocket: Socket? = null
        var udpSocket: DatagramSocket? = null
        return try {
            ctrlSocket = Socket()
            protect(ctrlSocket)
            ctrlSocket.connect(InetSocketAddress(cfg.socksHost, cfg.socksPort), 4000)
            ctrlSocket.soTimeout = 4000

            val out = ctrlSocket.getOutputStream()
            val inp = ctrlSocket.getInputStream()

            // SOCKS5 greeting (No Auth)
            out.write(byteArrayOf(0x05, 0x01, 0x00))
            val greetResp = ByteArray(2)
            if (inp.read(greetResp) != 2 || greetResp[1].toInt() != 0x00) return null

            // UDP ASSOCIATE request
            out.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            val assocResp = ByteArray(10)
            if (inp.read(assocResp) < 10 || assocResp[1].toInt() != 0x00) return null

            val relayIp = InetAddress.getByAddress(assocResp.copyOfRange(4, 8))
            val relayPort = ((assocResp[8].toInt() and 0xFF) shl 8) or (assocResp[9].toInt() and 0xFF)
            val targetRelay = if (relayIp.isAnyLocalAddress) InetAddress.getByName(cfg.socksHost) else relayIp

            udpSocket = DatagramSocket()
            protect(udpSocket)
            udpSocket.soTimeout = 4000

            val header = ByteArray(10 + payload.size)
            header[3] = 0x01 // IPv4
            System.arraycopy(dstIp, 0, header, 4, 4)
            header[8] = ((dstPort ushr 8) and 0xFF).toByte()
            header[9] = (dstPort and 0xFF).toByte()
            System.arraycopy(payload, 0, header, 10, payload.size)

            udpSocket.send(DatagramPacket(header, header.size, targetRelay, relayPort))
            val recvBuf = ByteArray(4096)
            val recvPkt = DatagramPacket(recvBuf, recvBuf.size)
            udpSocket.receive(recvPkt)
            if (recvPkt.length > 10) recvBuf.copyOfRange(10, recvPkt.length) else null
        } catch (_: Exception) {
            null
        } finally {
            try { udpSocket?.close() } catch (_: Exception) {}
            try { ctrlSocket?.close() } catch (_: Exception) {}
        }
    }

    private fun stopVpn() {
        running.set(false)
        LogBus.isRunning = false
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
        LogBus.log("DNSGuard 隧道已停止")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "com.dnsguard.android.STOP"
        private const val NOTIF_ID = 1001
    }
}
