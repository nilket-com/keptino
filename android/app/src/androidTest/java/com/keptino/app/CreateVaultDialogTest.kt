package com.keptino.app

import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class CreateVaultDialogTest {
    @JvmField @Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun createRequiresValidNameAndTwoMatchingPasswords() {
        var submitted: String? = null
        val visible = mutableStateOf(true)
        // Only the empty test activity and its synthetic form are shown.
        compose.activityRule.scenario.onActivity { activity ->
            activity.setShowWhenLocked(true)
            activity.setTurnScreenOn(true)
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
        compose.setContent {
            if (visible.value) CreateVaultDialog({ visible.value = false }) { name, password, confirmation ->
                assertEquals(password, confirmation)
                submitted = name
                visible.value = false
            }
        }
        val submit = compose.onNodeWithText("Create")
        submit.assertIsNotEnabled()
        compose.onNodeWithText("New vault name").performTextReplacement("../other")
        compose.onNodeWithText("New master password").performTextReplacement("phone test")
        compose.onNodeWithText("Confirm master password").performTextReplacement("phone test")
        submit.assertIsNotEnabled()
        compose.onNodeWithText("New vault name").performTextReplacement("Café on phone")
        compose.onNodeWithText("Confirm master password").performTextReplacement("different")
        submit.assertIsNotEnabled()
        compose.onNodeWithText("Confirm master password").performTextReplacement("phone test")
        submit.performClick()
        compose.runOnIdle { assertEquals("Café on phone", submitted) }
    }
}
