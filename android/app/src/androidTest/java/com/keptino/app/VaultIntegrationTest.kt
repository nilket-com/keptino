package com.keptino.app

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.Closeable
import java.io.File
import javax.crypto.Cipher

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
    private fun settingsFiles(): List<File> = context.filesDir.listFiles { f -> f.name.startsWith("settings") }!!.sortedBy { it.name }
    private fun assertCancelled(e: Exception) = assertTrue("Expected a cancellation, got: ${e.message}", (e.message ?: "").contains("cancel", ignoreCase = true))

    /** The real activity and its BiometricPrompt as the authenticator for storage calls. */
    private class Prompter(private val scenario: ActivityScenario<MainActivity>) : Closeable {
        private lateinit var activity: MainActivity
        init { scenario.onActivity { activity = it } }
        val authenticate: suspend (Cipher) -> Cipher = { cipher -> withContext(Dispatchers.Main) { activity.authenticate(cipher) } }
        fun <T> run(credential: DeviceCredential, answer: DeviceCredential.() -> Unit, block: suspend (suspend (Cipher) -> Cipher) -> T): T =
            credential.answering(answer) { runBlocking { withTimeout(60_000) { block(authenticate) } } }
        override fun close() = scenario.close()
    }
    private fun prompter() = Prompter(ActivityScenario.launch(MainActivity::class.java))

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

    @Test fun nativePreflightPassesAndIsRepeatable() {
        val warnings = Core.preflight()
        warnings.forEach { assertTrue("Warnings are sentences for the user: $it", it.endsWith(".")) }
        // Hardening is already applied by then; a second run reports the same state.
        assertArrayEquals(warnings, Core.preflight())
    }

    @Test fun rememberedRevisionRejectsOlderAndLegacyVaultsAfterReopen() {
        val name = "revision-" + java.util.UUID.randomUUID()
        val storage = VaultStorage(context)
        storage.acceptRevision(name, 0uL)
        storage.acceptRevision(name, 1uL)
        val reopened = VaultStorage(context)
        reopened.acceptRevision(name, ULong.MAX_VALUE)
        reopened.acceptRevision(name, ULong.MAX_VALUE)
        assertThrows(IllegalStateException::class.java) {
            reopened.acceptRevision(name, ULong.MAX_VALUE, previous = 1uL) { fail("Replaced a concurrent save") }
        }
        for (older in listOf(0uL, 1uL, ULong.MAX_VALUE - 1uL)) {
            assertThrows(IllegalStateException::class.java) {
                reopened.acceptRevision(name, older) { fail("Replaced a vault below the remembered revision") }
            }
        }
    }

    @Test fun atomicVaultStorageAndSafeFileNames() {
        val storage = VaultStorage(context)
        try { storage.file("../outside"); fail("Unsafe file name accepted") } catch (_: IllegalArgumentException) {}
        storage.write("atomic-test", byteArrayOf(1, 2, 3)); storage.write("atomic-test", byteArrayOf(4, 5))
        assertArrayEquals(byteArrayOf(4, 5), storage.read("atomic-test"))
        try {
            storage.write("atomic-test", ByteArray(MAX_VAULT_BYTES + 1))
            fail("Saved a vault larger than the reader accepts")
        } catch (_: IllegalArgumentException) {}
        assertArrayEquals(byteArrayOf(4, 5), storage.read("atomic-test"))
        storage.file("atomic-test").delete()
    }

    @Test fun migratesLegacyVaultAndPreservesBothFilesOnCollision() {
        val dir = context.filesDir
        val old = File(dir, "migration-test.digisafe")
        val backup = File(dir, "migration-test.digisafe.bak")
        val current = File(dir, "migration-test.keptino")
        val original = byteArrayOf(1, 2, 3)
        val other = byteArrayOf(4, 5)
        try {
            current.delete()
            old.writeBytes(other)
            backup.writeBytes(original)
            val storage = VaultStorage(context)
            assertTrue(current.isFile)
            assertFalse(old.exists())
            assertFalse(backup.exists())
            assertArrayEquals(original, storage.read("migration-test"))

            old.writeBytes(other)
            assertArrayEquals(original, VaultStorage(context).read("migration-test"))
            assertArrayEquals(other, old.readBytes())
        } finally {
            listOf(old, backup, current).forEach { it.delete() }
        }
    }

    @Test fun settingsNeedTheDeviceCredentialForEveryOperation() {
        val credential = DeviceCredential.fromArguments()
        val storage = VaultStorage(context)
        LegacySettings.clear(context)
        val pepper = pepper()
        val written = Settings(pepper, "fake-id", "fake-key", "http://10.0.2.2:8765")
        prompter().use { prompt ->
            prompt.run(credential, { enterPinOnce() }) { auth -> storage.writeSettings(written, auth) }
            assertTrue(storage.configured())
            assertFalse("New settings must not use the legacy format", LegacySettings.stillLegacy(context))
            val files = settingsFiles()
            assertTrue(files.isNotEmpty())
            for (file in files) assertFalse(file.name, String(file.readBytes(), Charsets.ISO_8859_1).contains("fake-key"))

            // Reading is its own operation: a dismissed prompt releases nothing.
            try { prompt.run(credential, { cancel() }) { auth -> storage.settings(auth) }; fail("Cancelled prompt released settings") }
            catch (e: Exception) { assertCancelled(e) }
            val read = prompt.run(credential, { enterPinOnce() }) { auth -> storage.settings(auth) }
            assertArrayEquals(pepper, read.pepper); assertEquals("fake-id", read.keyId); assertEquals("fake-key", read.appKey); assertEquals("http://10.0.2.2:8765", read.authUrl)

            // A cancelled write changes nothing on disk.
            val before = files.associate { it.name to it.readBytes() }
            try { prompt.run(credential, { cancel() }) { auth -> storage.writeSettings(Settings(pepper, "other-id", "other-key"), auth) }; fail("Cancelled prompt wrote settings") }
            catch (e: Exception) { assertCancelled(e) }
            val after = settingsFiles().associate { it.name to it.readBytes() }
            assertEquals(before.keys, after.keys)
            before.forEach { (name, bytes) -> assertArrayEquals(name, bytes, after[name]) }
            val reread = prompt.run(credential, { enterPinOnce() }) { auth -> storage.settings(auth) }
            assertEquals("fake-id", reread.keyId)
            read.pepper.fill(0); reread.pepper.fill(0)
        }
        pepper.fill(0)
        LegacySettings.clear(context)
    }

    @Test fun legacySettingsMigrateOnFirstReadWithOnePrompt() {
        val credential = DeviceCredential.fromArguments()
        val storage = VaultStorage(context)
        LegacySettings.clear(context)
        val pepper = pepper()
        val legacy = Settings(pepper, "legacy-id", "legacy-key", "http://10.0.2.2:8765")
        val legacyBytes = LegacySettings.write(context, legacy)
        assertTrue(LegacySettings.stillLegacy(context)); assertTrue(storage.configured())
        prompter().use { prompt ->
            val migrated = prompt.run(credential, { enterPinOnce() }) { auth -> storage.settings(auth) }
            assertArrayEquals(pepper, migrated.pepper); assertEquals("legacy-id", migrated.keyId); assertEquals("legacy-key", migrated.appKey); assertEquals("http://10.0.2.2:8765", migrated.authUrl)
            assertFalse("The legacy file must not stay readable after migration", LegacySettings.stillLegacy(context))
            assertTrue(storage.configured())
            for (file in settingsFiles()) assertFalse(file.name, file.readBytes().contentEquals(legacyBytes))
            // The migrated setup opens again with one prompt and the same values.
            val again = prompt.run(credential, { enterPinOnce() }) { auth -> storage.settings(auth) }
            assertArrayEquals(pepper, again.pepper); assertEquals("legacy-id", again.keyId); assertEquals("legacy-key", again.appKey)
            migrated.pepper.fill(0); again.pepper.fill(0)

            // Cancelling the migration prompt leaves the legacy setup intact and usable.
            LegacySettings.clear(context); LegacySettings.write(context, legacy)
            try { prompt.run(credential, { cancel() }) { auth -> storage.settings(auth) }; fail("Cancelled migration released settings") }
            catch (e: Exception) { assertCancelled(e) }
            assertTrue("A cancelled migration must keep the legacy settings", LegacySettings.stillLegacy(context))
            assertTrue(storage.configured())
        }
        pepper.fill(0)
        LegacySettings.clear(context)
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

    @Test fun cloudSessionPreservesRemoteChangesAcrossRetries() = runBlocking {
        org.junit.Assume.assumeTrue("Pass mockBaseUrl to exercise B2 sync", args.containsKey("mockBaseUrl"))
        val client = Backblaze(Settings(ByteArray(0), "test-key-id", "test-app-key", args.getString("mockBaseUrl")!!))
        val name = "conflict-" + java.util.UUID.randomUUID()
        val original = byteArrayOf(1)
        val edit = byteArrayOf(2)
        val concurrent = byteArrayOf(3)
        val session = BackblazeSession(client, name, original, offline = true, initiallyPaused = false)
        assertTrue(session.upload(original) { true }) // First upload from an offline vault to an empty bucket.
        assertFalse(session.upload(edit) { false }) // Lock during the remote check.
        assertArrayEquals(original, client.download(name))
        assertTrue(session.upload(edit) { true })
        client.upload(name, concurrent)
        repeat(2) {
            assertFalse(session.upload(edit) { true })
            assertTrue(session.paused)
            assertArrayEquals(concurrent, client.download(name))
        }
        val fallback = BackblazeSession(client, name, concurrent, offline = false, initiallyPaused = true)
        assertFalse(fallback.upload(edit) { true })
        assertArrayEquals(concurrent, client.download(name))
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
