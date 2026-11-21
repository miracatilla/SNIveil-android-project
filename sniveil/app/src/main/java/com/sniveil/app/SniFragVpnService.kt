package com.sniveil.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.content.Intent
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * Captures all device traffic via a TUN interface and relays it to the
 * real internet through normal (protected) sockets, exactly like a
 * tun2socks-style app. For destination port 443 it additionally:
 *
 *  1. Splits the outgoing TLS ClientHello into two TCP writes so a
 *     passive DPI box on the ISP's side sees the SNI split across two
 *     segments instead of one readable record (SNI fragmentation).
 *  2. Optionally fires a short-lived "decoy" connection to the same
 *     destination first, carrying a fake ClientHello whose SNI is the
 *     address you configured, with a low IP TTL so it dies a few hops
 *     out and never reaches the real server. A DPI/logging box that
 *     only inspects ClientHellos in transit sees that domain; it never
 *     completes a handshake with it.
 *
 * This is a minimal, single-purpose TCP relay, not a production TCP/IP
 * stack: no retransmission or congestion control. It is meant for your
 * own personal testing on a single device.
 */
class SniFragVpnService : VpnService() {

    companion object {
        var isRunning = false
        private const val CHANNEL_ID = "sniveil_vpn"
        private const val NOTIF_ID = 1
    }

    private var tunFd: ParcelFileDescriptor? = null
    private val connections = ConcurrentHashMap<String, Connection>()
    private val pool = Executors.newCachedThreadPool()
    private var running = false

    private var fakeSni = "www.example.com"
    private var fragmentSize = 2
    private var decoyEnabled = true
    private var decoyTtl = 4

    private class Connection(
        val key: String,
        val clientPort: Int,
        val dstIp: InetAddress,
        val dstPort: Int,
        var clientSeq: Long,   // next byte we expect FROM the client
        var ourSeq: Long,      // next byte we send TO the client
        val socket: Socket
    ) {
        var sawFirstPayload = false
        var closing = false
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (running) return START_STICKY
        val prefs = getSharedPreferences(Prefs.NAME, MODE_PRIVATE)
        fakeSni = prefs.getString(Prefs.FAKE_SNI, fakeSni) ?: fakeSni
        fragmentSize = prefs.getInt(Prefs.FRAGMENT_SIZE, fragmentSize)

        startForeground(NOTIF_ID, buildNotification())
        val builder = Builder()
            .setSession("SNIveil")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0) // IPv4 only: no addRoute for IPv6, so IPv6 traffic bypasses the tunnel
            .addDnsServer("1.1.1.1")
            .setMtu(1500)
        tunFd = builder.establish()
        running = true
        isRunning = true
        pool.execute { readLoop() }
        LogBus.log("VPN başladı, sahte SNI=$fakeSni, parça=$fragmentSize byte")
        return START_STICKY
    }

    private fun readLoop() {
        val fd = tunFd ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        while (running) {
            val len = try { input.read(buf) } catch (e: Exception) { break }
            if (len <= 0) continue
            try {
                handlePacket(buf.copyOf(len))
            } catch (e: Exception) {
                LogBus.log("paket hatası: ${e.message}")
            }
        }
    }

    private fun handlePacket(packet: ByteArray) {
        val ip = PacketUtils.parseIpHeader(packet, packet.size) ?: return
        if (ip.protocol != PacketUtils.PROTO_TCP) return // UDP/ICMP: dropped for simplicity (DNS goes via 1.1.1.1 UDP and will simply time out — see README)
        val tcp = PacketUtils.parseTcpHeader(packet, ip.headerLength)
        val payloadOffset = ip.headerLength + tcp.headerLength
        val payload = if (payloadOffset < packet.size) packet.copyOfRange(payloadOffset, packet.size) else ByteArray(0)
        val key = "${tcp.srcPort}-${ip.dstIp.hostAddress}-${tcp.dstPort}"

        if (tcp.isSyn && !tcp.isAck) {
            openConnection(key, tcp.srcPort, ip.dstIp, ip.srcIp, tcp.dstPort, tcp.seq)
            return
        }

        val conn = connections[key] ?: run {
            if (!tcp.isRst) sendRst(ip.srcIp, ip.dstIp, tcp)
            return
        }

        if (tcp.isRst) {
            closeConnection(conn)
            return
        }

        if (tcp.isFin) {
            conn.clientSeq = tcp.seq + 1
            sendAck(conn, ip.srcIp)
            try { conn.socket.shutdownOutput() } catch (_: Exception) {}
            return
        }

        if (payload.isNotEmpty()) {
            conn.clientSeq = tcp.seq + payload.size
            sendAck(conn, ip.srcIp) // ack immediately, we don't do real flow control
            forwardToRemote(conn, payload)
        }
    }

    private fun openConnection(
        key: String,
        clientPort: Int,
        dstIp: InetAddress,
        localTunnelIp: InetAddress,
        dstPort: Int,
        clientIsn: Long
    ) {
        pool.execute {
            try {
                if (dstPort == 443 && decoyEnabled) {
                    fireDecoyClientHello(dstIp, dstPort)
                }
                val socket = Socket()
                protect(socket)
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(dstIp, dstPort), 8000)

                val conn = Connection(
                    key, clientPort, dstIp, dstPort,
                    clientSeq = clientIsn + 1,
                    ourSeq = (0..Int.MAX_VALUE).random().toLong(),
                    socket = socket
                )
                connections[key] = conn
                sendSynAck(conn, localTunnelIp)
                conn.ourSeq += 1

                // relay thread: remote -> client (via synthetic TCP packets into the TUN)
                pool.execute { remoteToClientLoop(conn, localTunnelIp) }
            } catch (e: Exception) {
                LogBus.log("bağlantı kurulamadı $dstIp:$dstPort -> ${e.message}")
            }
        }
    }

    /**
     * Experimental: opens a disposable connection to the same destination
     * with a deliberately low TTL and sends a fake ClientHello carrying
     * the SNI you configured. It is expected to die a few hops out and
     * never reach the real server — the point is only for a passive
     * logger on the way to record that hostname. Tune decoyTtl for your
     * network: too high and it reaches (and confuses) the real server;
     * too low and it dies before clearing your ISP's own equipment.
     */
    private fun fireDecoyClientHello(dstIp: InetAddress, dstPort: Int) {
        try {
            val decoy = Socket()
            protect(decoy)
            val pfd = ParcelFileDescriptor.fromSocket(decoy)
            Os.setsockoptInt(pfd.fileDescriptor, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, decoyTtl)
            decoy.connect(InetSocketAddress(dstIp, dstPort), 1500)
            decoy.getOutputStream().write(TlsHello.buildFakeClientHello(fakeSni))
            decoy.getOutputStream().flush()
            try { decoy.close() } catch (_: Exception) {}
            pfd.close()
        } catch (e: Exception) {
            // Expected to frequently fail/timeout since the TTL is intentionally too low to connect — that's fine.
            LogBus.log("decoy gönderildi/düştü (beklenen): ${e.message}")
        }
    }

    private fun forwardToRemote(conn: Connection, payload: ByteArray) {
        try {
            val out = conn.socket.getOutputStream()
            if (!conn.sawFirstPayload && conn.dstPort == 443 && PacketUtils.looksLikeTlsClientHello(payload)) {
                conn.sawFirstPayload = true
                val splitAt = fragmentSize.coerceIn(1, payload.size - 1)
                out.write(payload, 0, splitAt)
                out.flush()
                Thread.sleep(5) // tiny gap to encourage two separate TCP segments on the wire
                out.write(payload, splitAt, payload.size - splitAt)
                out.flush()
                LogBus.log("ClientHello parçalandı (${splitAt}/${payload.size} byte) -> ${conn.dstIp.hostAddress}:443")
            } else {
                conn.sawFirstPayload = true
                out.write(payload)
                out.flush()
            }
        } catch (e: Exception) {
            closeConnection(conn)
        }
    }

    private fun remoteToClientLoop(conn: Connection, localTunnelIp: InetAddress) {
        val buf = ByteArray(16384)
        try {
            val input = conn.socket.getInputStream()
            while (running) {
                val n = input.read(buf)
                if (n < 0) break
                sendData(conn, localTunnelIp, buf.copyOf(n))
            }
        } catch (_: Exception) {
        } finally {
            sendFin(conn, localTunnelIp)
            closeConnection(conn)
        }
    }

    private fun writeToTun(packet: ByteArray) {
        val fd = tunFd ?: return
        try {
            FileOutputStream(fd.fileDescriptor).write(packet)
        } catch (_: Exception) {
        }
    }

    private fun sendSynAck(conn: Connection, localTunnelIp: InetAddress) {
        val pkt = PacketUtils.buildTcpPacket(
            srcIp = conn.dstIp, dstIp = localTunnelIp,
            srcPort = conn.dstPort, dstPort = conn.clientPort,
            seq = conn.ourSeq, ack = conn.clientSeq,
            flags = 0x12, window = 65535, payload = ByteArray(0)
        )
        writeToTun(pkt)
    }

    private fun sendAck(conn: Connection, localTunnelIp: InetAddress) {
        val pkt = PacketUtils.buildTcpPacket(
            srcIp = conn.dstIp, dstIp = localTunnelIp,
            srcPort = conn.dstPort, dstPort = conn.clientPort,
            seq = conn.ourSeq, ack = conn.clientSeq,
            flags = 0x10, window = 65535, payload = ByteArray(0)
        )
        writeToTun(pkt)
    }

    private fun sendData(conn: Connection, localTunnelIp: InetAddress, data: ByteArray) {
        val pkt = PacketUtils.buildTcpPacket(
            srcIp = conn.dstIp, dstIp = localTunnelIp,
            srcPort = conn.dstPort, dstPort = conn.clientPort,
            seq = conn.ourSeq, ack = conn.clientSeq,
            flags = 0x18, window = 65535, payload = data
        )
        conn.ourSeq += data.size
        writeToTun(pkt)
    }

    private fun sendFin(conn: Connection, localTunnelIp: InetAddress) {
        val pkt = PacketUtils.buildTcpPacket(
            srcIp = conn.dstIp, dstIp = localTunnelIp,
            srcPort = conn.dstPort, dstPort = conn.clientPort,
            seq = conn.ourSeq, ack = conn.clientSeq,
            flags = 0x11, window = 65535, payload = ByteArray(0)
        )
        conn.ourSeq += 1
        writeToTun(pkt)
    }

    private fun sendRst(localTunnelIp: InetAddress, dstIp: InetAddress, tcp: PacketUtils.TcpHeader) {
        val pkt = PacketUtils.buildTcpPacket(
            srcIp = dstIp, dstIp = localTunnelIp,
            srcPort = tcp.dstPort, dstPort = tcp.srcPort,
            seq = tcp.ack, ack = tcp.seq + 1,
            flags = 0x14, window = 0, payload = ByteArray(0)
        )
        writeToTun(pkt)
    }

    private fun closeConnection(conn: Connection) {
        connections.remove(conn.key)
        try { conn.socket.close() } catch (_: Exception) {}
    }

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java)
            mgr.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "SNIveil VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("SNIveil çalışıyor")
            .setContentText("Trafik yerel olarak işleniyor")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openApp)
            .build()
    }

    override fun onDestroy() {
        running = false
        isRunning = false
        connections.values.forEach { try { it.socket.close() } catch (_: Exception) {} }
        connections.clear()
        try { tunFd?.close() } catch (_: Exception) {}
        super.onDestroy()
    }
}
