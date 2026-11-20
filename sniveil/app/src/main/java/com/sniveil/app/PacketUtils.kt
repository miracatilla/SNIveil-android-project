package com.sniveil.app

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal IPv4 + TCP header parsing/building. This is NOT a full TCP/IP
 * stack: no retransmission, no congestion control, no options beyond MSS.
 * It is enough to terminate simple TCP connections locally (NAT-style,
 * the same trick tun2socks-style apps use) so that we can see and split
 * the TLS ClientHello before it leaves the device.
 */
object PacketUtils {

    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    data class IpHeader(
        val version: Int,
        val headerLength: Int,
        val protocol: Int,
        val srcIp: InetAddress,
        val dstIp: InetAddress,
        val totalLength: Int
    )

    data class TcpHeader(
        val srcPort: Int,
        val dstPort: Int,
        val seq: Long,
        val ack: Long,
        val headerLength: Int,
        val flags: Int,
        val window: Int
    ) {
        val isSyn get() = flags and 0x02 != 0
        val isAck get() = flags and 0x10 != 0
        val isFin get() = flags and 0x01 != 0
        val isRst get() = flags and 0x04 != 0
        val isPsh get() = flags and 0x08 != 0
    }

    fun parseIpHeader(buf: ByteArray, len: Int): IpHeader? {
        if (len < 20) return null
        val versionAndIhl = buf[0].toInt() and 0xFF
        val version = versionAndIhl shr 4
        if (version != 4) return null // IPv6 is not routed through the tunnel, see Builder config
        val ihl = (versionAndIhl and 0x0F) * 4
        val totalLength = ((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF)
        val protocol = buf[9].toInt() and 0xFF
        val srcIp = InetAddress.getByAddress(buf.copyOfRange(12, 16))
        val dstIp = InetAddress.getByAddress(buf.copyOfRange(16, 20))
        return IpHeader(version, ihl, protocol, srcIp, dstIp, totalLength)
    }

    fun parseTcpHeader(buf: ByteArray, offset: Int): TcpHeader {
        val bb = ByteBuffer.wrap(buf, offset, buf.size - offset).order(ByteOrder.BIG_ENDIAN)
        val srcPort = bb.short.toInt() and 0xFFFF
        val dstPort = bb.short.toInt() and 0xFFFF
        val seq = bb.int.toLong() and 0xFFFFFFFFL
        val ack = bb.int.toLong() and 0xFFFFFFFFL
        val offsetAndReserved = buf[offset + 12].toInt() and 0xFF
        val headerLength = (offsetAndReserved shr 4) * 4
        val flags = buf[offset + 13].toInt() and 0x3F
        val window = ((buf[offset + 14].toInt() and 0xFF) shl 8) or (buf[offset + 15].toInt() and 0xFF)
        return TcpHeader(srcPort, dstPort, seq, ack, headerLength, flags, window)
    }

    private fun checksum(data: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i < data.size - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (data.size % 2 == 1) {
            sum += (data[data.size - 1].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    /** Builds a full IPv4 packet containing a TCP segment, with correct checksums. */
    fun buildTcpPacket(
        srcIp: InetAddress,
        dstIp: InetAddress,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int,
        payload: ByteArray
    ): ByteArray {
        val tcpHeaderLen = 20
        val ipHeaderLen = 20
        val totalLen = ipHeaderLen + tcpHeaderLen + payload.size
        val packet = ByteArray(totalLen)

        // IPv4 header
        packet[0] = 0x45 // version 4, IHL 5
        packet[1] = 0
        packet[2] = (totalLen shr 8).toByte()
        packet[3] = totalLen.toByte()
        packet[4] = 0; packet[5] = 0 // identification
        packet[6] = 0x40.toByte(); packet[7] = 0 // flags: don't fragment
        packet[8] = 64 // TTL
        packet[9] = PROTO_TCP.toByte()
        packet[10] = 0; packet[11] = 0 // checksum placeholder
        System.arraycopy(srcIp.address, 0, packet, 12, 4)
        System.arraycopy(dstIp.address, 0, packet, 16, 4)
        val ipChecksum = checksum(packet.copyOfRange(0, ipHeaderLen))
        packet[10] = (ipChecksum shr 8).toByte()
        packet[11] = ipChecksum.toByte()

        // TCP header
        val tcpOffset = ipHeaderLen
        packet[tcpOffset] = (srcPort shr 8).toByte(); packet[tcpOffset + 1] = srcPort.toByte()
        packet[tcpOffset + 2] = (dstPort shr 8).toByte(); packet[tcpOffset + 3] = dstPort.toByte()
        packet[tcpOffset + 4] = (seq shr 24).toByte(); packet[tcpOffset + 5] = (seq shr 16).toByte()
        packet[tcpOffset + 6] = (seq shr 8).toByte(); packet[tcpOffset + 7] = seq.toByte()
        packet[tcpOffset + 8] = (ack shr 24).toByte(); packet[tcpOffset + 9] = (ack shr 16).toByte()
        packet[tcpOffset + 10] = (ack shr 8).toByte(); packet[tcpOffset + 11] = ack.toByte()
        packet[tcpOffset + 12] = (5 shl 4).toByte() // data offset, no options
        packet[tcpOffset + 13] = flags.toByte()
        packet[tcpOffset + 14] = (window shr 8).toByte(); packet[tcpOffset + 15] = window.toByte()
        packet[tcpOffset + 16] = 0; packet[tcpOffset + 17] = 0 // checksum placeholder
        packet[tcpOffset + 18] = 0; packet[tcpOffset + 19] = 0 // urgent pointer
        System.arraycopy(payload, 0, packet, tcpOffset + tcpHeaderLen, payload.size)

        // TCP checksum over pseudo-header + tcp segment
        val pseudo = ByteArray(12 + tcpHeaderLen + payload.size)
        System.arraycopy(srcIp.address, 0, pseudo, 0, 4)
        System.arraycopy(dstIp.address, 0, pseudo, 4, 4)
        pseudo[9] = PROTO_TCP.toByte()
        val tcpSegLen = tcpHeaderLen + payload.size
        pseudo[10] = (tcpSegLen shr 8).toByte(); pseudo[11] = tcpSegLen.toByte()
        System.arraycopy(packet, tcpOffset, pseudo, 12, tcpSegLen)
        val tcpChecksum = checksum(pseudo)
        packet[tcpOffset + 16] = (tcpChecksum shr 8).toByte()
        packet[tcpOffset + 17] = tcpChecksum.toByte()

        return packet
    }

    /** True if `data` looks like the start of a TLS ClientHello (handshake record, SNI inside). */
    fun looksLikeTlsClientHello(data: ByteArray): Boolean {
        return data.size > 5 &&
            data[0] == 0x16.toByte() && // Content type: Handshake
            data[1] == 0x03.toByte()    // Legacy record version: TLS 1.x
    }
}
