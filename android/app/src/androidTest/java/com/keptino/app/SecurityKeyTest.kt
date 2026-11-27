package com.keptino.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SecurityKeyTest {
    private val file get() = InstrumentationRegistry.getInstrumentation().context.assets
        .open("linux-debug-fido.keptino").use { it.readBytes() }

    private fun open(device: SecurityKeyIo) {
        val vault = file
        // Cancellation must not start another ceremony on the other copy.
        Core.open("vaultfido", "fixture".toByteArray(), ByteArray(32), vault, vault, 4096, device)
    }

    // The host peer drives the shared fixture authenticator. Only HID packets
    // and NFC APDUs cross this socket. The release app has no simulator.
    private class Peer(port: Int) : SecurityKeyIo, java.io.Closeable {
        private val socket = java.net.Socket("127.0.0.1", port).apply { soTimeout = 10000; tcpNoDelay = true }
        private val source = socket.getInputStream().bufferedReader()
        private val sink = socket.getOutputStream().bufferedWriter()
        private val keys = ArrayDeque<Pair<String, Int>>()
        val pins = mutableListOf<ByteArray>()
        var enteredPin = "1234"
        fun useKey(link: String, index: Int) { keys.addLast(link to index) }
        private fun command(line: String): String {
            sink.write(line); sink.newLine(); sink.flush()
            return checkNotNull(source.readLine()) { "Fixture peer disconnected" }
        }
        override fun begin(): Int {
            val (link, index) = keys.removeFirstOrNull() ?: error("Unexpected key request")
            command("$link $index")
            return if (link == "usb") 1 else 2
        }
        override fun write(packet: ByteArray) { command("write " + packet.toHexString()) }
        override fun read() = command("read").hexToByteArray()
        override fun apdu(request: ByteArray) = command("apdu " + request.toHexString()).hexToByteArray()
        override fun pin() = enteredPin.toByteArray().also(pins::add)
        override fun close() = socket.close()
    }

    @Test fun fixtureAndKeyChangesThroughJni() {
        val port = InstrumentationRegistry.getArguments().getString("port")
        org.junit.Assume.assumeNotNull(port)
        val password = "correct horse battery staple".toByteArray()
        val pepper = "3cd9546c0999a233094b17ca466b70e94cb3dc10cdf9a718d35ad025c4da2ae1".hexToByteArray()
        Peer(port!!.toInt()).use { peer ->
            fun openFile(bytes: ByteArray, name: String) = Core.open(name, password, pepper, bytes, null, 4096, peer)
            for ((link, index) in listOf("usb" to 1, "nfc" to 2)) {
                peer.useKey(link, index)
                val h = openFile(file, "vaultfido")
                try { assertEquals(2, Core.keySlots(h).size) } finally { Core.close(h) }
            }
            peer.useKey("nfc", 3)
            assertThrows(RuntimeException::class.java) { openFile(file, "vaultfido") }
            peer.useKey("usb", 1)
            peer.enteredPin = "4321"
            val prompts = peer.pins.size
            assertThrows(RuntimeException::class.java) { openFile(file, "vaultfido") }
            assertEquals(prompts + 1, peer.pins.size)
            peer.enteredPin = "1234"

            val name = "jni-keys"
            var handle = Core.open(name, password, pepper, null, null, 4096)
            try {
                var bytes = Core.save(handle)
                fun change(remove: Int) {
                    val next = Core.prepareKeys(handle, bytes, password, pepper, remove, false, peer)
                    val updated = try { Core.save(next) } catch (e: Throwable) { Core.close(next); throw e }
                    Core.close(handle)
                    handle = next
                    bytes = updated
                }
                peer.useKey("usb", 1)
                change(0)
                assertEquals(1, Core.keySlots(handle).size)
                peer.useKey("usb", 1); peer.useKey("nfc", 1)
                assertThrows(RuntimeException::class.java) { change(0) }
                for (newKey in 2..4) {
                    peer.useKey("usb", 1); peer.useKey("nfc", newKey)
                    change(0)
                }
                assertEquals(4, Core.keySlots(handle).size)
                assertThrows(RuntimeException::class.java) { change(0) }
                val before = bytes
                // Keep only the spare. The old and new salts must differ.
                peer.useKey("nfc", 2)
                change(13)
                assertEquals(1, Core.keySlots(handle).size)
                assertFalse(Core.fileStamp(before).copyOf(32).contentEquals(Core.fileStamp(bytes).copyOf(32)))
                peer.useKey("usb", 1)
                assertThrows(RuntimeException::class.java) { openFile(bytes, name) }
                peer.useKey("usb", 2)
                Core.close(openFile(bytes, name))
                assertThrows(RuntimeException::class.java) {
                    Core.prepareKeys(handle, bytes, byteArrayOf(0), pepper, 1, false, peer)
                }
                change(1)
                assertEquals(0, Core.keySlots(handle).size)
                Core.close(openFile(bytes, name))
                assertTrue(peer.pins.isNotEmpty() && peer.pins.all { pin -> pin.all { it == 0.toByte() } })
            } finally { Core.close(handle) }
        }
    }

    @Test fun cancelDuringUsbReadSendsCancelAndEndsUnlock() {
        val sent = mutableListOf<ByteArray>()
        var opens = 0
        var reads = 0
        val device = object : SecurityKeyIo {
            override fun begin() = 1.also { opens++ }
            override fun write(packet: ByteArray) { sent.add(packet.copyOf()) }
            override fun read(): ByteArray? {
                if (++reads > 1) return null
                // Broadcast INIT response echoes the reader's nonce and allocates channel 1.
                return sent.single().copyOf().apply {
                    this[6] = 17
                    this[18] = 1
                    this[19] = 2
                    this[23] = 4
                }
            }
            override fun apdu(request: ByteArray): ByteArray = error("Unexpected NFC")
            override fun pin(): ByteArray = error("Unexpected PIN request")
        }
        val error = assertThrows(RuntimeException::class.java) { open(device) }
        assertTrue(error.message.orEmpty().contains("cancel", ignoreCase = true))
        assertEquals(1, opens)
        assertEquals(listOf(0x86, 0x90, 0x91), sent.map { it[4].toInt() and 255 })
    }

    @Test fun disconnectDuringNfcSelectPreservesDeviceError() {
        var opens = 0
        val device = object : SecurityKeyIo {
            override fun begin() = 2.also { opens++ }
            override fun apdu(request: ByteArray): ByteArray {
                assertEquals(0xa4, request[1].toInt() and 255)
                error("NFC key removed")
            }
            override fun write(packet: ByteArray) = error("Unexpected USB")
            override fun read(): ByteArray = error("Unexpected USB")
            override fun pin(): ByteArray = error("Unexpected PIN request")
        }
        val error = assertThrows(IllegalStateException::class.java) { open(device) }
        assertEquals("NFC key removed", error.message)
        assertEquals(1, opens)
    }

    @Test fun offlineRekeyAndRestartRecheckTheBucket() = kotlinx.coroutines.runBlocking {
        val url = InstrumentationRegistry.getArguments().getString("mockBaseUrl")
        org.junit.Assume.assumeNotNull(url)
        val client = Backblaze(Settings(ByteArray(0), "test-key-id", "test-app-key", url!!))
        val name = "rekey-" + java.util.UUID.randomUUID()
        val original = byteArrayOf(1)
        val successor = byteArrayOf(2)
        val offline = BackblazeSession(client, name, original, offline = true, initiallyPaused = false)
        assertEquals("?", offline.predecessor)
        offline.rekeyCommitted()
        assertFalse(offline.upload(successor) { true })
        assertNull(client.download(name))
        offline.allowEmpty()
        client.upload(name, original)
        assertFalse(offline.upload(successor) { true })
        assertArrayEquals(original, client.download(name))

        fun restart() = BackblazeSession(client, name, successor, offline = true, initiallyPaused = false,
            pendingPredecessor = fingerprint(original))
        assertFalse(restart().upload(successor) { false })
        assertArrayEquals(original, client.download(name))
        assertTrue(restart().upload(successor) { true })
        val stale = restart()
        assertFalse(stale.upload(original) { true })
        assertTrue(stale.paused)
        assertArrayEquals(successor, client.download(name))
    }

    @Test fun interruptedMarkerAndAdoptionPreserveBothGenerations() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val storage = VaultStorage(ctx)
        val name = "key-test-" + java.util.UUID.randomUUID()
        val first = file
        val second = InstrumentationRegistry.getInstrumentation().context.assets
            .open("linux-debug-unmarked.keptino").use { it.readBytes() }
        val third = InstrumentationRegistry.getInstrumentation().context.assets
            .open("linux-debug.keptino").use { it.readBytes() }
        val path = storage.file(name)
        try {
            storage.write(name, first)
            storage.writeRekey(name, first, second, fingerprint(first))
            storage.writeRekey(name, second, third, "?")
            // Simulate process death between publishing the marker and replacing the vault.
            storage.write(name, second)
            val reopened = VaultStorage(ctx)
            val rows = reopened.markers(name)
            assertEquals(fingerprint(first), rows.single { it.covers(Core.fileStamp(second)) }.predecessor)
            assertEquals("?", rows.single { it.covers(Core.fileStamp(third)) }.predecessor)
            assertThrows(IllegalStateException::class.java) { reopened.adopt(name, first, third) }
            assertArrayEquals(second, reopened.read(name))
            reopened.adopt(name, second, third)
            reopened.adopt(name, second, third)
            assertArrayEquals(second, java.io.File(path.path + ".1").readBytes())
            assertArrayEquals(third, reopened.read(name))
            assertTrue(reopened.markers(name).isEmpty())
        } finally {
            path.parentFile!!.listFiles().orEmpty().filter { it.name.startsWith(name + ".") }.forEach { it.delete() }
        }
    }

    @Test fun busyFidoDescriptorIsVerifiedUnderClaim() {
        val calls = mutableListOf<String>()
        fun probe(known: Boolean, vararg reports: Boolean?): Boolean {
            calls.clear()
            val results = reports.iterator()
            return claimFidoInterface(known, { calls.add("inspect"); results.next() },
                { calls.add("claim"); true }, { calls.add("release") })
        }
        assertTrue(probe(true, null, true))
        assertEquals(listOf("inspect", "claim", "inspect"), calls)
        assertFalse(probe(false, null))
        assertEquals(listOf("inspect"), calls)
        assertFalse(probe(true, false))
        assertEquals(listOf("inspect"), calls)
        assertThrows(IllegalStateException::class.java) { probe(true, null, false) }
        assertEquals(listOf("inspect", "claim", "inspect", "release"), calls)
    }

    @Test fun onlyClaimAnInterfaceWithAFidoApplicationCollection() {
        val fido = "06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0".hexToByteArray()
        val keyboard = byteArrayOf(0x05, 1, 0x09, 6, 0xa1.toByte(), 1, 0xc0.toByte())
        assertTrue(isFidoInterface(fido, fido.size))
        val short = fido.copyOf().also { it[17] = 32 }
        assertFalse(isFidoInterface(short, short.size))
        assertFalse(isFidoInterface(keyboard, keyboard.size))
        assertFalse(isFidoInterface(fido + keyboard, fido.size + keyboard.size))
        assertFalse(isFidoInterface(fido, fido.size - 1))
    }
}
