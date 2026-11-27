package com.keptino.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class R2Test {
    private val account = "0123456789abcdef0123456789abcdef"
    private val settings = Settings(ByteArray(32), "fixture-id", "fixture-secret", provider = "r2", account = account, bucket = "keptino-test")

    private class Reply(url: URL, val code: Int, val data: ByteArray, val tag: String? = null) : HttpURLConnection(url) {
        val sent = ByteArrayOutputStream()
        override fun getOutputStream() = sent
        override fun getInputStream() = data.inputStream()
        override fun getErrorStream() = data.inputStream()
        override fun getResponseCode() = code
        override fun getHeaderField(name: String) = if (name == "ETag") tag else null
        override fun connect() {}
        override fun disconnect() {}
        override fun usingProxy() = false
    }

    @Test fun signedReadAndConditionalWriteUseLinuxObjectBytes() {
        val vault = InstrumentationRegistry.getInstrumentation().context.assets.open("linux-debug.keptino").use { it.readBytes() }
        val body = java.util.Base64.getEncoder().encode(vault)
        var code = 200
        lateinit var last: Reply
        val r2 = R2(settings) { url -> Reply(url, code, body, "\"old\"").also { last = it } }
        val objectRead = r2.fetch("vaultdebug")
        assertArrayEquals(vault, objectRead.bytes)
        assertEquals("https://$account.r2.cloudflarestorage.com/keptino-test/vaultdebug.keptino", last.url.toString())
        assertTrue(last.getRequestProperty("Authorization").contains("/auto/s3/aws4_request"))
        assertFalse(last.instanceFollowRedirects)
        assertTrue(r2.put("vaultdebug", vault, objectRead))
        assertEquals("\"old\"", last.getRequestProperty("If-Match"))
        assertArrayEquals(body, last.sent.toByteArray())
        assertEquals(java.security.MessageDigest.getInstance("SHA-256").digest(body).toHexString(),
            last.getRequestProperty("x-amz-content-sha256"))
        code = 412
        assertFalse(r2.put("vaultdebug", vault, RemoteObject(null)))
        assertEquals("*", last.getRequestProperty("If-None-Match"))
        for (invalid in listOf(null, "W/\"old\"", "\"\"", "\"*\"")) {
            assertThrows(IllegalArgumentException::class.java) { r2.put("vaultdebug", vault, RemoteObject(vault, invalid)) }
        }
    }

    @Test fun missingDeniedAndOversizeAreDistinct() {
        fun remote(code: Int, xml: String) = R2(settings) { Reply(it, code, xml.toByteArray()) }
        assertNull(remote(404, "<Error><Code>NoSuchKey</Code></Error>").fetch("main").bytes)
        for ((code, body) in listOf(404 to "<Error><Code>NoSuchBucket</Code></Error>", 403 to "", 302 to "")) {
            assertThrows(IllegalStateException::class.java) { remote(code, body).fetch("main") }
        }
        val oversize = R2(settings) { object : HttpURLConnection(it) {
            override fun getResponseCode() = 200
            override fun getContentLengthLong() = MAX_VAULT_BODY_BYTES.toLong() + 1
            override fun getInputStream() = error("body was read")
            override fun connect() {}
            override fun disconnect() {}
            override fun usingProxy() = false
        } }
        assertEquals("R2 vault is too large", assertThrows(IllegalStateException::class.java) { oversize.fetch("main") }.message)
    }

    @Test fun settingsRemainSafeAcrossUpgradesAndDowngrades() {
        val legacy = JSONObject(Settings(ByteArray(32), "old-id", "old-secret").encode().decodeToString())
        legacy.remove("provider")
        assertTrue(Settings.parse(legacy.toString().toByteArray()).remote() is Backblaze)
        val encoded = settings.encode()
        val previousReader = JSONObject(encoded.decodeToString())
        assertEquals("", previousReader.getString("keyId"))
        assertEquals("", previousReader.getString("appKey"))
        val restored = Settings.parse(encoded)
        assertEquals("fixture-secret", restored.appKey)
        assertTrue(restored.remote() is R2)
    }

    @Test fun streamFromAppPrivateFifo() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val dir = java.nio.file.Files.createTempDirectory(context.cacheDir.toPath(), "fixture").toFile()
        val pipe = File(dir, "r2-setup.pipe")
        val token = "1".repeat(32)
        try {
            val receiver = async(Dispatchers.IO) { UsbSetup.receive(dir) }
            kotlinx.coroutines.withTimeout(5000) { while (!pipe.exists()) delay(10) }
            val message = listOf("KPR2", "03".repeat(32), "keptino-test", account, "fixture-id", "fixture-secret", token, "")
                .joinToString("\u0000").toByteArray()
            val frame = ByteBuffer.allocate(message.size + 4).putInt(message.size).put(message).array()
            pipe.outputStream().use { it.write(frame) }
            val result = receiver.await()
            assertEquals(token, result.token)
            assertArrayEquals(ByteArray(32) { 3 }, result.settings.pepper)
            assertEquals(settings.account, result.settings.account)
            assertFalse(pipe.exists())
        } finally { dir.deleteRecursively() }
        Unit
    }
}
