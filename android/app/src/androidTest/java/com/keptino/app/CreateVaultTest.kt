package com.keptino.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CreateVaultTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val storage = VaultStorage(context)
    private val password = "correct horse battery staple".toByteArray()
    private val pepper = "3cd9546c0999a233094b17ca466b70e94cb3dc10cdf9a718d35ad025c4da2ae1".hexToByteArray()
    private fun name() = "phone-" + UUID.randomUUID()
    private fun create(name: String, remote: R2? = null, cost: Int = 4096) =
        createVault(storage, name, password, pepper, remote, cost, null) {}

    private class Reply(url: URL, val status: Int, val data: ByteArray) : HttpURLConnection(url) {
        val written = ByteArrayOutputStream()
        override fun getOutputStream() = written
        override fun getInputStream() = data.inputStream()
        override fun getErrorStream() = data.inputStream()
        override fun getResponseCode() = status
        override fun connect() {}
        override fun disconnect() {}
        override fun usingProxy() = false
    }

    private val missing = "<Error><Code>NoSuchKey</Code></Error>".toByteArray()
    private fun remote(responses: List<Pair<Int, ByteArray>>, requests: MutableList<Reply> = mutableListOf()): R2 {
        val settings = Settings(pepper, "fixture-id", "fixture-key", provider = "r2", account = "a".repeat(32), bucket = "fixture")
        val replies = responses.iterator()
        return R2(settings) {
            val (code, body) = replies.next()
            Reply(it, code, body).also(requests::add)
        }
    }

    @Test fun localCreationIsDurableAndLinuxCanOpenTheExport() {
        val name = name() + " café"
        val production = InstrumentationRegistry.getArguments().getString("productionCreation") == "true"
        val cost = if (production) PRODUCTION_MEMORY_KIB else 4096
        val result = create(name, cost = cost)
        try {
            assertEquals(1L, Core.revision(result.handle))
            assertArrayEquals(result.file, storage.read(name))
            assertThrows(IllegalStateException::class.java) { storage.acceptRevision(name, 0uL) }
            assertThrows(IllegalStateException::class.java) { create(name, remote(emptyList())) }
            Core.setField(result.handle, 1, "from-phone".toByteArray())
            Core.setField(result.handle, 2, "android".toByteArray())
            Core.commit(result.handle)
            val second = Core.save(result.handle)
            storage.acceptRevision(name, 2uL, 1uL) { storage.write(name, second) }
            val reopened = Core.open(name, password, pepper, storage.read(name), null, 4096)
            try { assertTrue(Core.query(reopened, "from-phone")) } finally { Core.close(reopened) }
            File(context.cacheDir, "phone-created.keptino").writeBytes(second)
        } finally { Core.close(result.handle) }
    }

    @Test fun insufficientMemoryLeavesNameFree() {
        val unused = name()
        val error = assertThrows(RuntimeException::class.java) { create(unused, cost = Int.MAX_VALUE) }
        assertTrue(error.message.orEmpty().contains("available memory"))
        storage.requireUnusedName(unused)
    }

    @Test fun r2PublishesBeforeLocalCommitAndRejectsRemoteErrors() {
        val name = name()
        val requests = mutableListOf<Reply>()
        val created = create(name, remote(listOf(404 to missing, 200 to byteArrayOf()), requests))
        try {
            assertEquals(listOf("GET", "PUT"), requests.map { it.requestMethod })
            assertEquals("*", requests.last().getRequestProperty("If-None-Match"))
            assertArrayEquals(java.util.Base64.getEncoder().encode(created.file), requests.last().written.toByteArray())
            assertArrayEquals(created.file, storage.read(name))
        } finally { Core.close(created.handle) }
        for (replies in listOf(listOf(403 to missing), listOf(404 to "<Error/>".toByteArray()),
                listOf(404 to "<Error><!--<Code>NoSuchKey</Code>--><Code>NoSuchBucket</Code></Error>".toByteArray()),
                listOf(200 to "AAAA".toByteArray()), listOf(404 to missing, 503 to missing),
                listOf(404 to missing, 412 to missing, 404 to missing))) {
            val unused = name()
            assertThrows(Exception::class.java) { create(unused, remote(replies)) }
            storage.requireUnusedName(unused)
        }
    }

    @Test fun collisionDiscardsCandidateAndAuthenticatesWinner() {
        for (canOpen in listOf(true, false)) {
            val name = name()
            val other = Core.open(name, if (canOpen) password else "other".toByteArray(), pepper, null, null, 4096)
            val winner = try { Core.save(other) } finally { Core.close(other) }
            val r2 = remote(listOf(404 to missing, 412 to missing, 200 to java.util.Base64.getEncoder().encode(winner)))
            if (canOpen) {
                val opened = create(name, r2)
                try {
                    assertEquals(2, Core.source(opened.handle))
                    assertArrayEquals(winner, opened.file)
                    assertNull(storage.read(name))
                } finally { Core.close(opened.handle) }
            } else {
                assertThrows(RuntimeException::class.java) { create(name, r2) }
                storage.requireUnusedName(name)
            }
        }
    }
}
