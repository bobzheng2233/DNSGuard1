package com.dnsguard.android

import java.net.InetAddress

object PacketUtils {
    fun buildIpv4UdpResponse(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val ipHeaderLen = 20
        val udpHeaderLen = 8
        val totalLen = ipHeaderLen + udpHeaderLen + payload.size
        val pkt = ByteArray(totalLen)

        // IPv4 Header
        pkt[0] = 0x45.toByte()
        pkt[1] = 0x00
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[4] = 0x00
        pkt[5] = 0x00
        pkt[6] = 0x40
        pkt[7] = 0x00
        pkt[8] = 64.toByte()
        pkt[9] = 17.toByte() // UDP
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)

        val ipChecksum = calcChecksum(pkt, 0, ipHeaderLen)
        pkt[10] = ((ipChecksum ushr 8) and 0xFF).toByte()
        pkt[11] = (ipChecksum and 0xFF).toByte()

        // UDP Header
        val udpLen = udpHeaderLen + payload.size
        pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        pkt[24] = ((udpLen ushr 8) and 0xFF).toByte()
        pkt[25] = (udpLen and 0xFF).toByte()
        pkt[26] = 0
        pkt[27] = 0
        System.arraycopy(payload, 0, pkt, 28, payload.size)

        val udpChecksum = calcUdpChecksum(srcIp, dstIp, pkt, ipHeaderLen, udpLen)
        pkt[26] = ((udpChecksum ushr 8) and 0xFF).toByte()
        pkt[27] = (udpChecksum and 0xFF).toByte()
        return pkt
    }

    private fun calcChecksum(buf: ByteArray, offset: Int, len: Int): Int {
        var sum = 0L
        var i = offset
        while (i < offset + len - 1) {
            val word = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (len % 2 == 1) {
            sum += (buf[offset + len - 1].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun calcUdpChecksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        pkt: ByteArray,
        udpOffset: Int,
        udpLen: Int
    ): Int {
        var sum = 0L
        for (i in 0 until 4 step 2) {
            sum += ((srcIp[i].toInt() and 0xFF) shl 8) or (srcIp[i + 1].toInt() and 0xFF)
            sum += ((dstIp[i].toInt() and 0xFF) shl 8) or (dstIp[i + 1].toInt() and 0xFF)
        }
        sum += 17L
        sum += udpLen.toLong()

        var i = udpOffset
        while (i < udpOffset + udpLen - 1) {
            sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (udpLen % 2 == 1) {
            sum += (pkt[udpOffset + udpLen - 1].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val res = (sum.inv() and 0xFFFF).toInt()
        return if (res == 0) 0xFFFF else res
    }

    fun ipBytesToString(bytes: ByteArray): String =
        InetAddress.getByAddress(bytes).hostAddress ?: "0.0.0.0"
}
