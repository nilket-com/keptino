package com.keptino.app

import android.os.SystemClock
import android.widget.EditText
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.Configurator
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import org.junit.Assume.assumeTrue

/**
 * Drives the system prompt BiometricPrompt shows for the device credential when no
 * biometric is enrolled. It is a SystemUI window, out of reach of Compose testing, so
 * UiAutomator types the lock screen PIN that `test-emulator.py` set on the dedicated
 * emulator and passed as the `devicePin` instrumentation argument. Without that
 * argument every test calling [fromArguments] is skipped. There is no bypass: the Keystore
 * key refuses to work until the real prompt succeeds.
 */
class DeviceCredential private constructor(private val pin: String) {
    private val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())

    /**
     * Packages whose window hosts the prompt: SystemUI's BiometricPrompt credential view, or
     * Settings' ConfirmDeviceCredential on devices that delegate to it. An OEM build can
     * name others through the `credentialPackages` argument, comma separated.
     */
    private val promptPackages: Set<String> = (InstrumentationRegistry.getArguments().getString("credentialPackages")
        ?: "com.android.systemui,com.android.settings").split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()

    companion object {
        const val APP = "com.keptino.app"
        fun fromArguments(): DeviceCredential {
            val pin = InstrumentationRegistry.getArguments().getString("devicePin")
            assumeTrue("Pass devicePin (the emulator lock screen PIN) to exercise device credential prompts", pin != null)
            require(pin!!.isNotEmpty() && pin.all { it.isDigit() }) { "devicePin must be numeric" }
            Configurator.getInstance().waitForIdleTimeout = 400
            return DeviceCredential(pin)
        }
    }

    fun promptShowing(): Boolean {
        // Android 17's credential keypad exposes no EditText to UI automation.
        // Match both the focused window and its owner before sending the synthetic PIN.
        val windows = device.executeShellCommand("dumpsys window")
        val focused = windows.lineSequence().map { it.trim() }.firstOrNull {
            it.startsWith("mCurrentFocus=Window{") && it.endsWith(" BiometricPrompt}")
        }?.substringAfter('=')
        if (focused != null) {
            val owner = windows.lineSequence().dropWhile {
                !it.trimStart().startsWith("Window #") || !it.endsWith("$focused:")
            }.take(4)
                .firstOrNull { it.contains("mOwnerUid=") } ?: return false
            return promptPackages.any { owner.contains("package=$it ") }
        }
        // Some devices delegate credential confirmation to a Settings activity.
        val pkg = device.currentPackageName ?: return false
        return pkg != APP && pkg in promptPackages && device.hasObject(By.pkg(pkg).clazz(EditText::class.java))
    }

    private fun waitFor(what: String, timeoutMs: Long, condition: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + timeoutMs
        while (!condition()) {
            if (SystemClock.uptimeMillis() > deadline) throw AssertionError("Device credential prompt $what")
            SystemClock.sleep(100)
        }
    }

    fun awaitPrompt(timeoutMs: Long = 30_000) = waitFor("did not appear", timeoutMs) { promptShowing() }
    fun awaitDismissed(timeoutMs: Long = 30_000) = waitFor("did not close", timeoutMs) { !promptShowing() }

    /** Waits for the prompt, types the PIN and confirms it. */
    fun enterPin() {
        awaitPrompt()
        // SystemUI focuses the window before the PIN keypad accepts input.
        // On API 37 a single input-text command can lose its first digit here.
        device.waitForIdle(3_000)
        SystemClock.sleep(1_500)
        for (digit in pin) {
            check(promptShowing()) { "Credential prompt lost focus" }
            device.pressKeyCode(android.view.KeyEvent.KEYCODE_0 + digit.digitToInt())
        }
        check(promptShowing()) { "Credential prompt lost focus" }
        device.pressEnter()
        awaitDismissed()
    }

    /**
     * Enters the PIN once, then fails if a second prompt follows within [windowMs].
     * The stray prompt is dismissed so the operation under test fails instead of hanging.
     */
    fun enterPinOnce(windowMs: Long = 3_000) {
        enterPin()
        val deadline = SystemClock.uptimeMillis() + windowMs
        while (SystemClock.uptimeMillis() < deadline) {
            if (promptShowing()) {
                device.pressBack()
                throw AssertionError("A second device credential prompt appeared")
            }
            SystemClock.sleep(100)
        }
    }

    /** Waits for the prompt and dismisses it without a credential. */
    fun cancel() {
        awaitPrompt()
        device.pressBack()
        // The first Back may only hide the on-screen keyboard.
        SystemClock.sleep(500)
        if (promptShowing()) device.pressBack()
        awaitDismissed()
    }

    /**
     * Runs [block] on this thread while a helper thread answers the prompt it raises.
     * A helper failure takes precedence over the block's, and is never left to crash
     * the instrumentation process.
     */
    fun <T> answering(answer: DeviceCredential.() -> Unit, block: () -> T): T {
        var helperError: Throwable? = null
        val helper = Thread { try { answer() } catch (e: Throwable) { helperError = e } }
        helper.start()
        val result = runCatching(block)
        helper.join(40_000)
        helperError?.let { failure -> result.exceptionOrNull()?.let(failure::addSuppressed); throw failure }
        return result.getOrThrow()
    }
}
