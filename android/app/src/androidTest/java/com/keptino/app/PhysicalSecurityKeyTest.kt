package com.keptino.app

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Operator-driven smoke test. Install with an isolated application ID and supply a phase explicitly. */
@RunWith(AndroidJUnit4::class)
class PhysicalSecurityKeyTest {
    @Test fun disposableVault() {
        val phase = InstrumentationRegistry.getArguments().getString("keyPhase")
        assumeTrue(phase in listOf("enroll", "unlock", "cancel", "disconnect", "add", "revoke", "revoked"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        check(context.packageName.endsWith(".keycheck")) { "Use the separate keycheck installation" }
        val name = "vaultdebug"
        val pepper = "3cd9546c0999a233094b17ca466b70e94cb3dc10cdf9a718d35ad025c4da2ae1".hexToByteArray()
        val password = "correct horse battery staple".toByteArray()
        val file = File(context.filesDir, "hardware.keptino")
        val before = if (file.exists()) file.readBytes() else
            InstrumentationRegistry.getInstrumentation().context.assets.open("linux-debug.keptino").use { it.readBytes() }
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            lateinit var device: AndroidSecurityKey
            scenario.onActivity {
                it.window.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                device = AndroidSecurityKey(it)
            }
            device.purpose(when (phase) {
                "unlock" -> "Unlock the test vault. Select the USB key and touch it when it flashes."
                "cancel" -> "Cancellation check. Tap Cancel below."
                "disconnect" -> "Disconnection check. Select USB, then unplug the key when it flashes."
                else -> "Test vault: $phase"
            })
            device.use fixture@{
                fun open() = Core.open(name, password, pepper, before, null, 4096, device)
                if (phase in listOf("cancel", "disconnect", "revoked")) {
                    val failure = assertThrows(Exception::class.java) { open() }
                    when (phase) {
                        "cancel" -> check(failure is java.util.concurrent.CancellationException ||
                            failure.message.orEmpty().contains("cancel", true))
                        "disconnect" -> check(failure is java.io.IOException ||
                            listOf("disconnect", "transfer", "cancel").any { failure.message.orEmpty().contains(it, true) })
                        "revoked" -> check(failure.message.orEmpty().contains("enrolled", true) ||
                            failure.message.orEmpty().contains("unavailable", true))
                    }
                    check(before.contentEquals(file.readBytes()))
                    return@fixture
                }
                val vault = open()
                try {
                    val count = Core.keySlots(vault).size
                    if (phase == "unlock") { check(count > 0); return@fixture }
                    when (phase) {
                        "enroll" -> assertEquals(0, count)
                        "add" -> assertEquals(1, count)
                        "revoke" -> assertEquals(2, count)
                    }
                    val next = Core.prepareKeys(vault, before, password, pepper,
                        if (phase == "revoke") 1 else 0, true, device)
                    try {
                        val bytes = Core.save(next)
                        val atomic = android.util.AtomicFile(file)
                        val output = atomic.startWrite()
                        try { output.write(bytes); atomic.finishWrite(output) }
                        catch (e: Exception) { atomic.failWrite(output); throw e }
                        check(bytes.contentEquals(atomic.readFully()))
                    } finally { Core.close(next) }
                } finally { Core.close(vault) }
            }
            scenario.onActivity { android.widget.Toast.makeText(it, "Passed: $phase", android.widget.Toast.LENGTH_LONG).show() }
        }
    }
}
