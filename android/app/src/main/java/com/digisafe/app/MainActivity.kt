package com.digisafe.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.digisafe.app.ui.theme.DigiSafeTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private val vm: VaultViewModel by viewModels()
    private val timer = Handler(Looper.getMainLooper())
    private var idleDeadline = 0L
    private var clipboardDeadline = 0L
    private val idleLock = Runnable { if (SystemClock.elapsedRealtime() >= idleDeadline) vm.lock() }
    private var clipboardToken: String? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent { DigiSafeTheme { VaultScreen(vm, ::copySecret) } }
    }
    override fun onUserInteraction() { super.onUserInteraction(); armIdleLock() }
    override fun onResume() {
        super.onResume()
        val now = SystemClock.elapsedRealtime()
        if (idleDeadline != 0L && now >= idleDeadline) vm.lock()
        if (clipboardToken != null && now >= clipboardDeadline) clearClipboard()
        if (idleDeadline == 0L || now >= idleDeadline) armIdleLock()
    }
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus && clipboardToken != null && SystemClock.elapsedRealtime() >= clipboardDeadline) clearClipboard()
    }
    private fun armIdleLock() {
        idleDeadline = SystemClock.elapsedRealtime() + 120_000
        timer.removeCallbacks(idleLock); timer.postDelayed(idleLock, 120_000)
    }
    private fun copySecret(id: Int) {
        if (vm.busy || !vm.unlocked) { vm.report("Unlock and wait for the current operation to finish before copying"); return }
        val text = vm.secret(id)
        if (text.isEmpty()) { vm.report("This field is empty"); return }
        val token = "DigiSafe " + java.util.UUID.randomUUID().toString()
        val clip = ClipData.newPlainText(token, text)
        clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
        getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
        clipboardToken = token
        clipboardDeadline = SystemClock.elapsedRealtime() + 30_000
        timer.postDelayed({ if (clipboardToken == token) clearClipboard() }, 30_000)
        vm.report("Copied; clipboard clears in 30 seconds")
    }
    private fun clearClipboard() {
        val clipboard = getSystemService(ClipboardManager::class.java)
        val label = clipboard.primaryClipDescription?.label?.toString()
        if (label == clipboardToken && clipboardToken != null) {
            clipboard.clearPrimaryClip(); clipboardToken = null
        } else if (hasWindowFocus() && label != clipboardToken) {
            clipboardToken = null
        }
        // Android can deny clipboard access in the background. Keep the token
        // then, so onResume retries without erasing another application's copy.
    }
}

@Composable
private fun VaultScreen(vm: VaultViewModel, copy: (Int) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var seed by remember { mutableStateOf("") }
    var pepper by remember { mutableStateOf("") }
    var keyId by remember { mutableStateOf("") }
    var appKey by remember { mutableStateOf("") }
    var authUrl by remember { mutableStateOf("https://api.backblazeb2.com") }
    var offline by remember { mutableStateOf(false) }
    var confirmLock by remember { mutableStateOf(false) }
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) { password = ""; seed = ""; pepper = ""; appKey = "" }
        }
        owner.lifecycle.addObserver(observer)
        onDispose { owner.lifecycle.removeObserver(observer) }
    }
    val import = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            try {
                val bytes = withContext(Dispatchers.IO) { context.contentResolver.openInputStream(uri)!!.use { stream ->
                    val output = java.io.ByteArrayOutputStream(); val buffer = ByteArray(8192)
                    while (true) { val n = stream.read(buffer); if (n < 0) break; require(output.size() + n <= MAX_VAULT_BYTES) { "Vault is too large" }; output.write(buffer, 0, n) }
                    output.toByteArray()
                } }
                vm.importVault(bytes)
            } catch (e: Exception) { vm.report(e.message ?: "Import failed") }
        }
    }
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri != null) scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val bytes = vm.storage.read(vm.dbName) ?: error("Save the database first")
                    context.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(bytes) }
                }
                vm.report("Exported the last saved encrypted database")
            } catch (e: Exception) { vm.report(e.message ?: "Export failed") }
        }
    }
    Surface(Modifier.fillMaxSize()) {
        Column(Modifier.safeDrawingPadding().imePadding().padding(20.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("DigiSafe", style = MaterialTheme.typography.headlineLarge)
            Text(if (vm.unlocked) "${vm.dbName} · ${if (vm.dirty) "unsaved changes" else "unlocked"}" else "Your encrypted vault", style = MaterialTheme.typography.titleMedium)
            if (vm.busy) { LinearProgressIndicator(Modifier.fillMaxWidth()); Text("Working… Password derivation uses 4 GiB of memory.") }
            if (vm.status.isNotEmpty()) Text(vm.status)
            if (!vm.configured) {
                Text("Connect to your Linux vault", style = MaterialTheme.typography.titleLarge)
                Text("Use the original pepper seed, or import its 64-character hexadecimal value. Seed derivation requires 4 GiB of available memory. Setup is encrypted with Android Keystore.")
                Input("Original pepper seed", seed, { seed = it }, secret = true, enabled = !vm.busy)
                Input("Or original pepper (hex)", pepper, { pepper = it }, secret = true, enabled = !vm.busy)
                Text("Backblaze sync (optional)")
                Input("Application key ID", keyId, { keyId = it }, enabled = !vm.busy)
                Input("Application key", appKey, { appKey = it }, secret = true, enabled = !vm.busy)
                if (BuildConfig.DEBUG) Input("Backblaze API base URL", authUrl, { authUrl = it }, enabled = !vm.busy)
                Button(enabled = !vm.busy, onClick = { vm.setup(seed, pepper, keyId, appKey, authUrl); seed = ""; pepper = ""; appKey = "" }) { Text("Save setup") }
            } else if (!vm.unlocked) {
                Input("Database name", vm.dbName, { vm.dbName = it }, enabled = !vm.busy)
                Input("Master password", password, { password = it }, secret = true, enabled = !vm.busy)
                Row { Checkbox(offline, { offline = it }, enabled = !vm.busy); Text("Open local copy only", Modifier.padding(top = 12.dp)) }
                Button(enabled = !vm.busy, onClick = { vm.unlock(password, offline); password = "" }) { Text("Unlock") }
                OutlinedButton(enabled = !vm.busy, onClick = { import.launch(arrayOf("*/*")) }) { Text("Import Linux vault") }
                OutlinedButton(enabled = !vm.busy, onClick = vm::changeSetup) { Text("Change setup") }
                Text("Import preserves the source file and refuses to replace an existing local vault. Production Linux vaults require 4 GiB of available memory to unlock.")
            } else {
                Input("Find by name or tag", vm.query, { vm.query = it }, enabled = !vm.busy)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(enabled = !vm.busy, onClick = { vm.navigate(-1) }) { Text("Previous") }
                    Button(enabled = !vm.busy, onClick = { vm.navigate(0) }) { Text("Find") }
                    OutlinedButton(enabled = !vm.busy, onClick = { vm.navigate(1) }) { Text("Next") }
                }
                listOf(1 to "Name", 2 to "Username", 3 to "Password", 4 to "PIN", 6 to "URL", 7 to "Tags", 5 to "Note").forEach { (id, label) ->
                    val secret = id in listOf(3, 4, 5)
                    val visible = !secret || id in vm.revealed
                    OutlinedTextField(value = if (visible) vm.fields[id - 1] else "", onValueChange = { vm.edit(id, it) }, label = { Text(label) },
                        placeholder = { if (!visible) Text("Hidden") }, readOnly = !visible, enabled = !vm.busy,
                        modifier = Modifier.fillMaxWidth(), singleLine = id != 5,
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = if (secret) KeyboardType.Password else KeyboardType.Text),
                        trailingIcon = if (secret) {{ TextButton(enabled = !vm.busy, onClick = { vm.reveal(id) }) { Text(if (visible) "Hide" else "Reveal") } }} else null)
                    if (id == 3 || id == 4) TextButton(enabled = !vm.busy, onClick = { copy(id) }) { Text("Copy $label") }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(enabled = !vm.busy, onClick = vm::newEntry) { Text("New") }
                    Button(enabled = !vm.busy, onClick = vm::commit) { Text("Set entry") }
                    Button(enabled = !vm.busy, onClick = vm::save) { Text("Save") }
                }
                if (vm.editing) OutlinedButton(enabled = !vm.busy, onClick = vm::revert) { Text("Revert entry edits") }
                Text("Set entry applies edits to the open vault. Save writes the encrypted file and syncs when configured. Locking discards unsaved changes.")
                OutlinedButton(enabled = !vm.busy, onClick = { export.launch("${vm.dbName}.digisafe") }) { Text("Export saved vault") }
                OutlinedButton(enabled = !vm.busy, onClick = { if (vm.dirty) confirmLock = true else vm.lock() }) { Text("Lock") }
            }
        }
    }
    if (confirmLock) AlertDialog(onDismissRequest = { confirmLock = false }, title = { Text("Discard unsaved changes?") },
        text = { Text("Save first to keep changes to this vault.") },
        confirmButton = { TextButton(onClick = { confirmLock = false; vm.lock() }) { Text("Discard and lock") } },
        dismissButton = { TextButton(onClick = { confirmLock = false }) { Text("Cancel") } })
}

@Composable
private fun Input(label: String, value: String, change: (String) -> Unit, secret: Boolean = false, enabled: Boolean = true) {
    OutlinedTextField(value, change, label = { Text(label) }, enabled = enabled, singleLine = true, modifier = Modifier.fillMaxWidth(),
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = if (secret) KeyboardType.Password else KeyboardType.Text),
        visualTransformation = if (secret) PasswordVisualTransformation() else VisualTransformation.None)
}
