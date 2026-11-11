package com.digisafe.app

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class VaultUiTest {
    @JvmField @Rule val compose = createEmptyComposeRule()

    @Test fun productionLinuxVaultCanBeEditedAndSavedThroughUi() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("Pass uiFixture and production fixture credentials", args.containsKey("uiFixture"))
        val fixture = instrumentation.context.assets.open(args.getString("uiFixture")!!).use { it.readBytes() }
        val hex = args.getString("pepperHex")!!
        val pepper = ByteArray(32) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        val name = args.getString("dbName") ?: "interop"
        val storage = VaultStorage(instrumentation.targetContext)
        val mock = args.getString("mockBaseUrl")
        storage.writeSettings(if (mock == null) Settings(pepper) else Settings(pepper, "test-key-id", "test-app-key", mock)); pepper.fill(0)
        if (mock == null) storage.write(name, fixture) else {
            storage.file(name).delete()
            java.io.File(storage.file(name).path + ".bak").delete()
            java.io.File(storage.file(name).path + ".new").delete()
        }
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            compose.onNodeWithText("Database name").performTextReplacement(name)
            compose.onNodeWithText("Master password").performTextReplacement(args.getString("password")!!)
            compose.onNodeWithText("Unlock", substring = false).performClick()
            compose.waitUntil(180_000) { compose.onAllNodesWithText("Find by name or tag").fetchSemanticsNodes().isNotEmpty() }
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
            compose.waitUntil(30_000) { compose.onAllNodesWithText(if (mock == null) "Saved locally" else "Saved locally and to Backblaze", substring = false).fetchSemanticsNodes().isNotEmpty() }
            // A fixed output name lets the host reopen the exact UI-saved bytes with Linux.
            storage.write("android-ui-roundtrip", storage.read(name)!!)
            compose.onNodeWithText("Lock", substring = false).performScrollTo().performClick()
            compose.onNodeWithText("Master password").assertExists()
        }
    }
}
