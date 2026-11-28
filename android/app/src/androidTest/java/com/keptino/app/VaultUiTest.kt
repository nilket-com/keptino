package com.keptino.app

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

    @Test fun healthReportUsesSetEntriesAndClosesOnLock() {
        val credential = DeviceCredential.fromArguments()
        val name = "health-" + java.util.UUID.randomUUID()
        val storage = VaultStorage(context)
        val pepper = pepper()
        val master = "synthetic-health-master"
        val handle = Core.open(name, master.toByteArray(), pepper, null, null, 4096)
        try {
            LegacySettings.write(context, Settings(pepper))
            org.junit.Assert.assertArrayEquals(arrayOf("0 entries. No reused, weak, stale or empty passwords."), Core.healthReport(handle))
            for ((entry, password) in listOf("bank, joint" to "123456", "mail" to "123456", "blank" to "")) {
                Core.clear(handle)
                Core.setField(handle, 1, entry.toByteArray())
                Core.setField(handle, 3, password.toByteArray())
                Core.commit(handle)
            }
            val expected = arrayOf("3 entries", "Reused password 1", "bank, joint", "mail",
                "Weak passwords, estimated under 50 bits", "bank, joint: 19 bits", "mail: 19 bits",
                "No password", "blank")
            org.junit.Assert.assertArrayEquals(expected, Core.healthReport(handle))
            storage.write(name, Core.save(handle))
        } finally { Core.close(handle); pepper.fill(0) }
        ActivityScenario.launch(MainActivity::class.java).use {
            fun openReport() {
                compose.onNodeWithContentDescription("Vault actions").performClick()
                compose.onNodeWithText("Health").performClick()
                compose.waitUntil(10_000) { shown("Password health report") }
                compose.onNodeWithText("Find by name or tag").assertDoesNotExist()
                compose.onNodeWithText("bank, joint: 19 bits").assertExists()
            }
            compose.onNodeWithText("Vault name").performTextReplacement(name)
            compose.onNodeWithText("Master password").performTextReplacement(master)
            androidx.test.espresso.Espresso.closeSoftKeyboard()
            compose.onNodeWithText("Unlock").performScrollTo().performClick()
            credential.enterPin()
            compose.waitUntil(30_000) { shown("2 weak") }
            compose.onNodeWithText("2 weak").performClick()
            compose.onNodeWithText("blank").assertDoesNotExist()
            compose.onNodeWithText("mail").performClick()
            compose.onNodeWithText("Username").performTextReplacement("set-user")
            compose.onNodeWithText("Set entry").performClick()
            compose.waitUntil(10_000) { shown("1 set, not saved") && shown("bank, joint") }
            compose.onNodeWithText("bank, joint").performClick()
            compose.onNodeWithText("Username").performTextReplacement("unset-user")
            compose.onNodeWithContentDescription("Back to vault").performClick()
            compose.onNodeWithText("Unset edits were discarded.").assertExists()
            compose.onNodeWithText("Save").performClick()
            compose.waitUntil(10_000) { shown("Saved locally") }
            compose.onNodeWithText("set-user").assertExists()
            compose.onNodeWithText("unset-user").assertDoesNotExist()
            openReport()
            compose.onNodeWithText("Back to vault").performClick()
            openReport()
            androidx.test.espresso.Espresso.pressBack()
            compose.onNodeWithText("Find by name or tag").assertExists()
            openReport()
            compose.onNodeWithText("Lock").performClick()
            compose.onNodeWithText("Master password").assertExists()
            compose.onNodeWithText("Password health report").assertDoesNotExist()
        }
    }

    @Test fun cancelledCredentialPromptKeepsVaultLocked() {
        val credential = DeviceCredential.fromArguments()
        LegacySettings.clear(context)
        val pepper = pepper()
        LegacySettings.write(context, Settings(pepper)); pepper.fill(0)
        ActivityScenario.launch(MainActivity::class.java).use {
            compose.onNodeWithText("Vault name").performTextReplacement("cancel-test")
            compose.onNodeWithText("Master password").performTextReplacement("synthetic-test-password")
            androidx.test.espresso.Espresso.closeSoftKeyboard()
            compose.onNodeWithText("Unlock", substring = false).performScrollTo().assertIsDisplayed().performClick()
            compose.waitForIdle()
            credential.cancel()
            compose.waitUntil(30_000) { compose.onAllNodes(hasText("cancel", substring = true, ignoreCase = true)).fetchSemanticsNodes().isNotEmpty() }
            compose.onNodeWithText("Master password").assertExists()
            compose.onAllNodesWithText("Find by name or tag").assertCountEquals(0)
        }
        assertTrue("A canceled prompt must leave the saved setup untouched", LegacySettings.stillLegacy(context))
        LegacySettings.clear(context)
    }

    @Test fun generateRevertAndConfirmDelete() {
        val credential = DeviceCredential.fromArguments()
        assumeTrue(args.containsKey("password") && args.containsKey("pepperHex"))
        val name = "generator-delete-" + java.util.UUID.randomUUID()
        val storage = VaultStorage(context)
        val pepper = pepper()
        try { LegacySettings.write(context, Settings(pepper)) } finally { pepper.fill(0) }
        storage.write(name, instrumentation.context.assets.open("linux-debug-unmarked.keptino").use { it.readBytes() })
        ActivityScenario.launch(MainActivity::class.java).use {
            fun click(text: String) = compose.onNodeWithText(text).performClick()
            fun icon(text: String) = compose.onNodeWithContentDescription(text).performClick()
            fun unlock() {
                compose.onNodeWithText("Vault name").performTextReplacement(name)
                compose.onNodeWithText("Master password").performTextReplacement(args.getString("password")!!)
                androidx.test.espresso.Espresso.closeSoftKeyboard()
                compose.onNodeWithText("Unlock").performScrollTo().performClick()
                credential.enterPin()
                compose.waitUntil(120_000) { shown("mail") }
            }
            fun find(entry: String) {
                compose.onNodeWithText("Find by name or tag").performTextReplacement(entry)
                androidx.test.espresso.Espresso.closeSoftKeyboard()
                compose.waitUntil(10_000) { compose.onAllNodes(hasText(entry, ignoreCase = true) and hasClickAction() and !hasSetTextAction()).fetchSemanticsNodes().isNotEmpty() || shown("No matching entry") }
            }
            fun openBank() = compose.onNode(hasText("bank") and hasClickAction() and !hasSetTextAction()).performClick()
            unlock()
            find("BANK")
            openBank()
            icon("Generate password")
            compose.onNodeWithText("152 bits").assertExists()
            icon("Reveal preview")
            androidx.test.espresso.Espresso.pressBack()
            icon("Reveal Password")
            val password = compose.onNodeWithText("Password")
            password.assertTextContains("hunter2 ünïcödé 🔑")
            icon("Generate password")
            click("Words")
            compose.waitUntil(5_000) { shown("77 bits") }
            click("Use this password")
            val generated = password.fetchSemanticsNode().config[androidx.compose.ui.semantics.SemanticsProperties.EditableText].text
            assertTrue(generated.count { it == '-' } >= 5 && generated.all { it in 'a'..'z' || it == '-' })
            click("Revert")
            icon("Reveal Password")
            password.assertTextContains("hunter2 ünïcödé 🔑")
            icon("Generate password")
            click("Characters")
            for (label in listOf("A–Z", "a–z", "#%&", "0–9")) click(label)
            compose.onNodeWithText("Use this password").assertIsNotEnabled()
            click("0–9")
            click("Use this password")
            val digits = password.fetchSemanticsNode().config[androidx.compose.ui.semantics.SemanticsProperties.EditableText].text
            assertTrue(digits.length == 24 && digits.all { it in '0'..'9' })
            click("Set entry")
            click("Save")
            compose.waitUntil(30_000) { shown("Saved locally") }
            openBank()
            icon("Delete entry")
            click("Cancel")
            icon("Delete entry")
            click("Delete")
            compose.waitUntil(10_000) { shown("No matching entry") }
            icon("Lock")
            click("Discard and lock")
            unlock()
            openBank()
            icon("Delete entry")
            click("Delete")
            click("Save")
            compose.waitUntil(30_000) { shown("Saved locally") }
            icon("Lock")
            unlock()
            find("bank")
            compose.waitUntil(10_000) { shown("No matching entry") }
            find("mail")
            compose.onNode(hasText("mail") and hasClickAction() and !hasSetTextAction()).performClick()
            compose.onNodeWithContentDescription("Delete entry").assertExists()

        }
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
                compose.onNodeWithText("Vault name").performTextReplacement(name)
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
            androidx.test.espresso.Espresso.closeSoftKeyboard()
            val entry = args.getString("entry") ?: "example"
            val entryRow = hasText(entry) and hasClickAction() and !hasSetTextAction()
            compose.waitUntil(10_000) { compose.onAllNodes(entryRow).fetchSemanticsNodes().isNotEmpty() }
            compose.onNode(entryRow).performClick()
            compose.onNodeWithContentDescription("Copy Password").performScrollTo().performClick()
            scenario.moveToState(androidx.lifecycle.Lifecycle.State.CREATED)
            scenario.moveToState(androidx.lifecycle.Lifecycle.State.RESUMED)
            compose.waitForIdle()
            compose.onNodeWithText("Password").assertExists()
            scenario.onActivity { activity ->
                val clip = activity.getSystemService(android.content.ClipboardManager::class.java).primaryClip
                org.junit.Assert.assertEquals("hunter2 ünïcödé 🔑", clip?.getItemAt(0)?.text?.toString())
            }
            compose.onNodeWithContentDescription("Reveal Password").performScrollTo().performClick()
            compose.onNodeWithText("Password", substring = false).performTextReplacement("accidental edit")
            compose.onNodeWithText("Revert").performClick()
            compose.onNodeWithContentDescription("Reveal Password").performScrollTo().performClick()
            compose.onNodeWithText("Password", substring = false).assertTextContains("hunter2 ünïcödé 🔑")
            compose.onNodeWithText("Password", substring = false).performTextReplacement("android-edited-password 🔑")
            compose.onNodeWithText("Set entry", substring = false).performClick()
            compose.onNodeWithText("Save", substring = false).performClick()
            // Save reuses the session's sync configuration: no prompt may appear.
            compose.waitUntil(30_000) { credential.promptShowing() || shown(savedText) }
            assertFalse("Save must not ask for the device credential again", credential.promptShowing())
            compose.onNodeWithText(savedText, substring = false).assertExists()
            // A fixed output name lets the host reopen the exact UI-saved bytes with Linux.
            storage.write("android-ui-roundtrip", storage.read(name)!!)
            compose.onNode(entryRow).performClick()
            compose.onNodeWithContentDescription("Copy Password").performScrollTo().performClick()
            compose.onNodeWithContentDescription("Back to vault").performClick()
            compose.onNodeWithContentDescription("Lock").performClick()
            compose.onNodeWithText("Master password").assertExists()
            scenario.onActivity { activity ->
                val clipboard = activity.getSystemService(android.content.ClipboardManager::class.java)
                assertFalse("Explicit lock must clear our copied password", clipboard.hasPrimaryClip())
            }
            // The migrated setup unlocks again with one prompt and the same pepper and sync settings.
            unlock()
            // Both calls run on the main thread before the save can publish its result.
            lateinit var vm: VaultViewModel
            scenario.onActivity { activity ->
                vm = androidx.lifecycle.ViewModelProvider(activity)[VaultViewModel::class.java]
                vm.openEntry(args.getString("entry") ?: "example")
                vm.reveal(3)
                org.junit.Assert.assertEquals("android-edited-password 🔑", vm.fields[2])
                vm.save()
                assertTrue(vm.busy)
                vm.lock()
                assertFalse(vm.unlocked)
                assertTrue(vm.revealed.isEmpty() && vm.fields.all { it.isEmpty() })
            }
            compose.waitUntil(30_000) { !vm.busy }
            assertFalse(vm.unlocked)
            org.junit.Assert.assertEquals("Locked", vm.status)
            compose.onNodeWithText("Master password").assertExists()
        }
    }
}
