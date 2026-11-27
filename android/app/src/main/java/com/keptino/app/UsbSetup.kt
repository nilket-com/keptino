package com.keptino.app

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.File
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout

/** The Linux helper writes a length-prefixed frame to this app's private FIFO. */
internal object UsbSetup {
    private const val LIMIT = 4096

    data class Transfer(val token: String, val settings: Settings)
    fun receipt(cache: File, token: String, state: String) {
        File(cache, "r2-setup.result").writeText("$token $state")
    }

    suspend fun receive(cache: File): Transfer {
        check(BuildConfig.DEBUG) { "USB setup requires the ADB installation" }
        File(cache, "r2-setup.result").delete()
        val pipe = File(cache, "r2-setup.pipe")
        // A process death can leave an empty FIFO behind.
        if (pipe.exists()) check(pipe.delete()) { "Could not clear the old setup pipe" }
        Os.mkfifo(pipe.path, 384) // 0600
        val buffer = ByteArray(LIMIT + 4)
        try {
            val fd = Os.open(pipe.path, OsConstants.O_RDWR or OsConstants.O_NONBLOCK or OsConstants.O_NOFOLLOW, 0)
            try {
                return withTimeout(180_000) {
                    var used = 0
                    var wanted = 4
                    while (used < wanted) {
                        val n = try { Os.read(fd, buffer, used, wanted - used) } catch (e: ErrnoException) {
                            if (e.errno != OsConstants.EAGAIN && e.errno != OsConstants.EINTR) throw e
                            0
                        }
                        if (n == 0) delay(50) else used += n
                        if (used == 4 && wanted == 4) {
                            val length = java.nio.ByteBuffer.wrap(buffer, 0, 4).int
                            require(length in 1..LIMIT) { "Invalid Linux setup length" }
                            wanted += length
                        }
                    }
                    decode(buffer, wanted)
                }
            } finally { Os.close(fd) }
        } finally { buffer.fill(0); pipe.delete() }
    }

    private fun decode(buffer: ByteArray, end: Int): Transfer {
        val fields = mutableListOf<String>()
        var start = 4
        for (i in 4 until end) if (buffer[i] == 0.toByte()) {
            fields.add(String(buffer, start, i - start, Charsets.UTF_8))
            start = i + 1
        }
        require(start == end && fields.size == 7 && fields[0] == "KPR2" && fields[6].matches(Regex("[a-f0-9]{32}")) &&
            fields[1].matches(Regex("[0-9a-fA-F]{64}"))) { "Invalid Linux setup" }
        return Transfer(fields[6], Settings(fields[1].hexToByteArray(), fields[4], fields[5], provider = "r2", bucket = fields[2], account = fields[3]))
    }
}
