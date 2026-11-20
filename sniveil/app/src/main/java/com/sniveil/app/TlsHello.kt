package com.sniveil.app

import java.io.ByteArrayOutputStream
import kotlin.random.Random

/** Builds a minimal but well-formed TLS 1.2 ClientHello containing only an SNI extension. */
object TlsHello {

    fun buildFakeClientHello(hostname: String): ByteArray {
        val hostBytes = hostname.toByteArray(Charsets.US_ASCII)

        // server_name extension
        val serverNameEntry = ByteArrayOutputStream().apply {
            write(0x00) // name type: host_name
            write((hostBytes.size shr 8) and 0xFF); write(hostBytes.size and 0xFF)
            write(hostBytes)
        }.toByteArray()
        val serverNameList = ByteArrayOutputStream().apply {
            write((serverNameEntry.size shr 8) and 0xFF); write(serverNameEntry.size and 0xFF)
            write(serverNameEntry)
        }.toByteArray()
        val sniExtension = ByteArrayOutputStream().apply {
            write(0x00); write(0x00) // extension type: server_name
            write((serverNameList.size shr 8) and 0xFF); write(serverNameList.size and 0xFF)
            write(serverNameList)
        }.toByteArray()

        val extensions = sniExtension // just the one extension is enough for SNI sniffers

        val body = ByteArrayOutputStream().apply {
            write(0x03); write(0x03) // client_version: TLS 1.2
            write(Random.nextBytes(32)) // random
            write(0x00) // session_id length
            // two harmless cipher suites
            write(0x00); write(0x04)
            write(0xC0); write(0x2F)
            write(0x00); write(0x35)
            write(0x01); write(0x00) // compression methods: length 1, null
            write((extensions.size shr 8) and 0xFF); write(extensions.size and 0xFF)
            write(extensions)
        }.toByteArray()

        val handshake = ByteArrayOutputStream().apply {
            write(0x01) // handshake type: ClientHello
            write((body.size shr 16) and 0xFF); write((body.size shr 8) and 0xFF); write(body.size and 0xFF)
            write(body)
        }.toByteArray()

        return ByteArrayOutputStream().apply {
            write(0x16); write(0x03); write(0x01) // record: Handshake, TLS 1.0
            write((handshake.size shr 8) and 0xFF); write(handshake.size and 0xFF)
            write(handshake)
        }.toByteArray()
    }
}
