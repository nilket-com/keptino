package com.digisafe.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class VaultIntegrationTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val args = InstrumentationRegistry.getArguments()
    private fun pepper(): ByteArray {
        val hex = args.getString("pepperHex") ?: "42".repeat(32)
        return ByteArray(32) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
    private fun text(h: Long, id: Int): String { val bytes = Core.getField(h, id); return try { bytes.toString(Charsets.UTF_8) } finally { bytes.fill(0) } }
    private fun set(h: Long, id: Int, value: String) { val bytes = value.toByteArray(); try { Core.setField(h, id, bytes) } finally { bytes.fill(0) } }

    @Test fun nativeErrorsDoNotAbortAndSavedVaultReopens() {
        val pepper = pepper()
        val password = "synthetic-test-password".toByteArray()
        val h = Core.open("android-test", password, pepper, null, null, 4096)
        val encoded: ByteArray
        try {
            Core.clear(h); set(h, 1, "emulator-entry"); set(h, 2, "alice"); set(h, 3, "password 🔑"); set(h, 4, "1234"); set(h, 5, "private note\nsecond line")
            assertEquals(2, Core.commit(h)); encoded = Core.save(h)
            assertFalse(String(encoded, Charsets.ISO_8859_1).contains("private note"))
        } finally { Core.close(h) }
        try { Core.getField(h, 1); fail("Stale handle accepted") } catch (_: RuntimeException) {}
        try { Core.open("android-test", "wrong".toByteArray(), pepper, encoded, null, 4096); fail("Wrong password accepted") } catch (_: RuntimeException) {}
        val reopened = Core.open("android-test", password, pepper, encoded, null, 4096)
        try { assertTrue(Core.query(reopened, "emulator-entry")); assertEquals("password 🔑", text(reopened, 3)); assertEquals("private note\nsecond line", text(reopened, 5)) }
        finally { Core.close(reopened); password.fill(0); pepper.fill(0) }
    }

    @Test fun keystoreSettingsAndAtomicVaultStorage() {
        val storage = VaultStorage(context)
        val pepper = pepper()
        storage.writeSettings(Settings(pepper, "fake-id", "fake-key", "http://10.0.2.2:8765"))
        val read = storage.settings()
        assertArrayEquals(pepper, read.pepper)
        assertEquals("fake-id", read.keyId)
        val ciphertext = File(context.filesDir, "settings.enc").readBytes()
        assertFalse(String(ciphertext, Charsets.ISO_8859_1).contains("fake-key"))
        try { storage.file("../outside"); fail("Unsafe file name accepted") } catch (_: IllegalArgumentException) {}
        storage.write("atomic-test", byteArrayOf(1, 2, 3)); storage.write("atomic-test", byteArrayOf(4, 5))
        assertArrayEquals(byteArrayOf(4, 5), storage.read("atomic-test"))
        storage.file("atomic-test").delete()
        // Leave a local-only setup so a following UI test never contacts a real account.
        storage.writeSettings(Settings(pepper)); pepper.fill(0); read.pepper.fill(0)
    }

    @Test fun linuxFixtureEditAndExport() {
        org.junit.Assume.assumeTrue("Pass fixture arguments to exercise Linux interoperability", args.containsKey("fixture"))
        val fixtureName = args.getString("fixture")!!
        val encoded = instrumentation.context.assets.open(fixtureName).use { it.readBytes() }
        val password = (args.getString("password") ?: error("Fixture password is required")).toByteArray()
        val mem = args.getString("memoryKib")?.toInt() ?: 4096
        val name = args.getString("dbName") ?: "interop"
        val entry = args.getString("entry") ?: "example"
        val pepper = pepper()
        val h = Core.open(name, password, pepper, encoded, null, mem)
        try {
            assertTrue("Linux entry not found", Core.query(h, entry))
            val oldUsername = text(h, 2)
            set(h, 3, "android-edited-password 🔑"); assertEquals(1, Core.commit(h))
            val saved = Core.save(h)
            VaultStorage(context).write("android-roundtrip", saved)
            val reopened = Core.open(name, password, pepper, saved, null, mem)
            try { assertTrue(Core.query(reopened, entry)); assertEquals("android-edited-password 🔑", text(reopened, 3)); assertEquals(oldUsername, text(reopened, 2)) }
            finally { Core.close(reopened) }
        } finally { Core.close(h); password.fill(0); pepper.fill(0) }
    }

    @Test fun backblazeMockRoundTrip() {
        org.junit.Assume.assumeTrue("Pass mockBaseUrl to exercise B2 sync", args.containsKey("mockBaseUrl"))
        val base = args.getString("mockBaseUrl")!!
        val settings = Settings(pepper(), args.getString("mockKeyId") ?: "test-key-id", args.getString("mockAppKey") ?: "test-app-key", base)
        val b2 = Backblaze(settings)
        val bytes = ByteArray(50000) { (it % 251).toByte() }
        b2.upload("android-mock-test", bytes)
        assertArrayEquals(bytes, b2.download("android-mock-test"))
        assertNull(b2.download("missing-android-mock-test"))
        settings.pepper.fill(0)
    }
}
