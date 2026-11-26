package com.digisafe.app

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class VaultUiTest {
    @JvmField @Rule val compose = createEmptyComposeRule()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val args = InstrumentationRegistry.getArguments()
    private fun pepper(): ByteArray {
        val hex = args.getString("pepperHex") ?: "42".repeat(32)
        return ByteArray(32) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
    private fun shown(text: String) = compose.onAllNodesWithText(text, substring = false).fetchSemanticsNodes().isNotEmpty()

    @Test fun cancelledCredentialPromptKeepsVaultLocked() {
        val credential = DeviceCredential.fromArguments()
        LegacySettings.clear(context)
        val pepper = pepper()
        LegacySettings.write(context, Settings(pepper)); pepper.fill(0)
        ActivityScenario.launch(MainActivity::class.java).use {
            compose.onNodeWithText("Database name").performTextReplacement("cancel-test")
            compose.onNodeWithText("Master password").performTextReplacement("synthetic-test-password")
            androidx.test.espresso.Espresso.closeSoftKeyboard()
            compose.onNodeWithText("Unlock", substring = false).performScrollTo().assertIsDisplayed().performClick()
            compose.waitForIdle()
            credential.cancel()
            compose.waitUntil(30_000) { compose.onAllNodes(hasText("cancel", substring = true, ignoreCase = true)).fetchSemanticsNodes().isNotEmpty() }
            compose.onNodeWithText("Master password").assertExists()
            compose.onAllNodesWithText("Find by name or tag").assertCountEquals(0)
        }
        assertTrue("A cancelled prompt must leave the saved setup untouched", LegacySettings.stillLegacy(context))
        LegacySettings.clear(context)
    }

    @Test fun productionLinuxVaultCanBeEditedAndSavedThroughUi() {
        val credential = DeviceCredential.fromArguments()
        assumeTrue("Pass uiFixture and production fixture credentials", args.containsKey("uiFixture"))
        val fixture = instrumentation.context.assets.open(args.getString("uiFixture")!!).use { it.readBytes() }
        val pepper = pepper()
        val name = args.getString("dbName") ?: "interop"
        val storage = VaultStorage(context)
        val mock = args.getString("mockBaseUrl")
        val savedText = if (mock == null) "Saved locally" else "Saved locally and to Backblaze"
        // An installation upgraded from the previous release: the first unlock migrates its setup.
        LegacySettings.clear(context)
        LegacySettings.write(context, if (mock == null) Settings(pepper) else Settings(pepper, "test-key-id", "test-app-key", mock)); pepper.fill(0)
        if (mock == null) storage.write(name, fixture) else {
            storage.file(name).delete()
            java.io.File(storage.file(name).path + ".bak").delete()
            java.io.File(storage.file(name).path + ".new").delete()
        }
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            fun unlock() {
                compose.onNodeWithText("Database name").performTextReplacement(name)
                compose.onNodeWithText("Master password").performTextReplacement(args.getString("password")!!)
                androidx.test.espresso.Espresso.closeSoftKeyboard()
                compose.onNodeWithText("Unlock", substring = false).performScrollTo().assertIsDisplayed().performClick()
                compose.waitForIdle()
                credential.enterPin()
                compose.waitUntil(180_000) { credential.promptShowing() || shown("Find by name or tag") }
                assertFalse("Unlock must authenticate exactly once", credential.promptShowing())
                compose.onNodeWithText("Find by name or tag").assertExists()
            }
            unlock()
            assertFalse("The first unlock must migrate the legacy setup", LegacySettings.stillLegacy(context))
            if (mock != null) compose.onNodeWithText("Opened remote database").assertExists()
            compose.onNodeWithText("Find by name or tag").performTextReplacement(args.getString("entry") ?: "example")
            compose.onNodeWithText("Find", substring = false).performClick()
            compose.onNodeWithText("Copy Password").performScrollTo().performClick()
            scenario.moveToState(androidx.lifecycle.Lifecycle.State.CREATED)
            scenario.moveToState(androidx.lifecycle.Lifecycle.State.RESUMED)
            compose.waitForIdle()
            compose.onNodeWithText("Find by name or tag").assertExists()
            scenario.onActivity { activity ->
                val clip = activity.getSystemService(android.content.ClipboardManager::class.java).primaryClip
                org.junit.Assert.assertEquals("hunter2 ünïcödé 🔑", clip?.getItemAt(0)?.text?.toString())
            }
            compose.onAllNodesWithText("Reveal")[0].performScrollTo().performClick()
            compose.onNodeWithText("Password", substring = false).performTextReplacement("accidental edit")
            compose.onNodeWithText("Revert entry edits").performScrollTo().performClick()
            compose.onAllNodesWithText("Reveal")[0].performScrollTo().performClick()
            compose.onNodeWithText("Password", substring = false).assertTextContains("hunter2 ünïcödé 🔑")
            compose.onNodeWithText("Password", substring = false).performTextReplacement("android-edited-password 🔑")
            compose.onNodeWithText("Set entry", substring = false).performScrollTo().performClick()
            compose.onNodeWithText("Save", substring = false).performScrollTo().performClick()
            // Save reuses the session's sync configuration: no prompt may appear.
            compose.waitUntil(30_000) { credential.promptShowing() || shown(savedText) }
            assertFalse("Save must not ask for the device credential again", credential.promptShowing())
            compose.onNodeWithText(savedText, substring = false).assertExists()
            // A fixed output name lets the host reopen the exact UI-saved bytes with Linux.
            storage.write("android-ui-roundtrip", storage.read(name)!!)
            compose.onNodeWithText("Lock", substring = false).performScrollTo().performClick()
            compose.onNodeWithText("Master password").assertExists()
            // The migrated setup unlocks again with one prompt and the same pepper and sync settings.
            unlock()
            compose.onNodeWithText("Lock", substring = false).performScrollTo().performClick()
            compose.onNodeWithText("Master password").assertExists()
        }
    }
}
