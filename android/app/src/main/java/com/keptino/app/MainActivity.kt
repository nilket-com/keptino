package com.keptino.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.Image
import androidx.compose.ui.Alignment
import androidx.compose.ui.res.painterResource
import com.keptino.app.ui.theme.Nautilus as N
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.isSensitiveData
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.keptino.app.ui.theme.KeptinoTheme
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private var requestR2 by mutableStateOf(false)
    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        requestR2 = BuildConfig.DEBUG && intent.action == "com.keptino.app.IMPORT_R2"
    }
    private val vm: VaultViewModel by viewModels()
    private val timer = Handler(Looper.getMainLooper())
    private var idleDeadline = 0L
    private var clipboardDeadline = 0L
    private var ready = false
    private var promptSignal: CancellationSignal? = null
    private val idleLock = Runnable {
        if (SystemClock.elapsedRealtime() >= idleDeadline) { lockVault() }
    }
    private var clipboardToken: String? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestR2 = savedInstanceState == null && BuildConfig.DEBUG && intent.action == "com.keptino.app.IMPORT_R2"
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.decorView.apply {
            filterTouchesWhenObscured = true
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            if (Build.VERSION.SDK_INT >= 34) setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
        val nativeWarnings = try { Core.preflight().toList() } catch (e: RuntimeException) {
            viewModelStore.clear()
            setContent { KeptinoTheme { Text(e.message ?: "Device security check failed.", Modifier.safeDrawingPadding().padding(20.dp)) } }
            return
        }
        idleDeadline = savedInstanceState?.getLong("idleDeadline") ?: 0L
        clipboardDeadline = savedInstanceState?.getLong("clipboardDeadline") ?: 0L
        clipboardToken = savedInstanceState?.getString("clipboardToken") ?: clipboardCleanup.getString("pending", null)
        ready = true
        setContent {
            var warnings by remember { mutableStateOf(nativeWarnings) }
            LaunchedEffect(Unit) {
                warnings = nativeWarnings + withContext(Dispatchers.IO) { deviceWarnings(applicationContext) }
                vm.refreshKeyProtection()
            }
            KeptinoTheme { VaultScreen(vm, ::copySecret, ::lockVault, ::authenticate, { AndroidSecurityKey(this) }, warnings, requestR2) { requestR2 = false } }
        }
    }
    internal suspend fun authenticate(cipher: Cipher): Cipher = withContext(Dispatchers.Main.immediate) {
        check(ready && !isFinishing && !isDestroyed && lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
            "Return to Keptino and retry device authentication."
        }
        suspendCancellableCoroutine { continuation ->
            val signal = CancellationSignal()
            check(promptSignal == null) { "Device authentication is already in progress." }
            promptSignal = signal
            continuation.invokeOnCancellation { signal.cancel() }
            val prompt = BiometricPrompt.Builder(this@MainActivity)
                .setTitle("Authenticate for Keptino")
                .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
                .build()
            try {
                prompt.authenticate(BiometricPrompt.CryptoObject(cipher), signal, mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (promptSignal === signal) promptSignal = null
                        if (!continuation.isActive) return
                        val authorized = result.cryptoObject?.cipher
                        if (authorized === cipher && !signal.isCanceled) {
                            armIdleLock()
                            continuation.resume(authorized)
                        } else continuation.resumeWithException(IllegalStateException("Device authentication was interrupted."))
                    }
                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        if (promptSignal === signal) promptSignal = null
                        val detail = when (code) {
                            BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
                            BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED -> "Authentication canceled."
                            else -> message.toString()
                        }
                        if (continuation.isActive) continuation.resumeWithException(IllegalStateException(detail))
                    }
                })
            } catch (e: Exception) {
                promptSignal = null
                throw e
            }
        }
    }
    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if (event.flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED != 0) return false
        return super.dispatchTouchEvent(event)
    }
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putLong("idleDeadline", idleDeadline)
        outState.putLong("clipboardDeadline", clipboardDeadline)
        outState.putString("clipboardToken", clipboardToken)
    }
    private val clipboardCleanup by lazy { getSharedPreferences("clipboard_cleanup", MODE_PRIVATE) }
    private fun lockVault() {
        promptSignal?.cancel()
        vm.lock()
        clipboardDeadline = 0L
        clearClipboard()
    }
    override fun finish() {
        // A finishing window may still have foreground clipboard access here.
        if (ready) clearClipboard()
        super.finish()
    }
    override fun onStop() {
        super.onStop()
        if (ready) vm.cancelKeyOperation(background = true)
    }
    override fun onDestroy() {
        if (ready) vm.cancelKeyOperation()
        if (ready && isFinishing) {
            clearClipboard()
            clipboardCleanup.edit().putString("pending", clipboardToken).apply()
        }
        promptSignal?.cancel()
        timer.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
    override fun onUserInteraction() { super.onUserInteraction(); if (ready) armIdleLock() }
    override fun onResume() {
        super.onResume()
        if (!ready) return
        val now = SystemClock.elapsedRealtime()
        if (idleDeadline != 0L && now >= idleDeadline) idleLock.run()
        if (clipboardToken != null && now >= clipboardDeadline) clearClipboard()
        if (idleDeadline == 0L || now >= idleDeadline) armIdleLock()
        else { timer.removeCallbacks(idleLock); timer.postDelayed(idleLock, idleDeadline - now) }
        val token = clipboardToken
        if (token != null && now < clipboardDeadline) timer.postDelayed({ if (clipboardToken == token) clearClipboard() }, clipboardDeadline - now)
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
        val token = "Keptino " + java.util.UUID.randomUUID().toString()
        val clip = ClipData.newPlainText(token, text)
        clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
        getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
        clipboardToken = token
        clipboardDeadline = SystemClock.elapsedRealtime() + 30_000
        timer.postDelayed({ if (clipboardToken == token) clearClipboard() }, 30_000)
        vm.report("Copied; clipboard clears in 30 seconds")
    }
    private fun clearClipboard() {
        val token = clipboardToken ?: return
        val clipboard = getSystemService(ClipboardManager::class.java)
        try {
            val label = clipboard.primaryClipDescription?.label?.toString()
            if (label == token) {
                clipboard.clearPrimaryClip()
            } else if (!hasWindowFocus() || label == null) {
                return
            }
            clipboardToken = null
            clipboardCleanup.edit().remove("pending").apply()
        } catch (_: SecurityException) {
            // Keep the token to retry after focus returns.
        }
        // Android can deny clipboard access in the background. Keep the token
        // then, so onResume retries without erasing another application's copy.
    }
}

@Composable
private fun VaultScreen(vm: VaultViewModel, copy: (Int) -> Unit, lock: () -> Unit, authenticate: suspend (Cipher) -> Cipher, securityKey: () -> AndroidSecurityKey, warnings: List<String>, requestR2: Boolean, handledR2: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var masterVisible by remember { mutableStateOf(false) }
    var seed by remember { mutableStateOf("") }
    var pepper by remember { mutableStateOf("") }
    var r2 by remember { mutableStateOf(false) }
    var account by remember { mutableStateOf("") }
    var bucket by remember { mutableStateOf("") }
    var creating by remember { mutableStateOf(false) }
    var confirmUsb by remember { mutableStateOf(false) }
    LaunchedEffect(requestR2, vm.unlocked, vm.busy) {
        if (requestR2 && !vm.unlocked && !vm.busy) { confirmUsb = true; handledR2() }
    }
    var keyId by remember { mutableStateOf("") }
    var appKey by remember { mutableStateOf("") }
    var authUrl by remember { mutableStateOf("https://api.backblazeb2.com") }
    var offline by remember { mutableStateOf(false) }
    var settings by remember { mutableStateOf(false) }
    var settingsAfterLock by remember { mutableStateOf(false) }
    var confirmLock by remember(vm.unlocked) { mutableStateOf(false) }
    val requestLock = { settingsAfterLock = false; if (vm.dirty) confirmLock = true else lock() }
    val openSettings = {
        if (vm.dirty) { settingsAfterLock = true; confirmLock = true }
        else { lock(); settings = true }
    }
    LaunchedEffect(vm.unlocked) { if (vm.unlocked) settings = false }
    val deletableName = vm.deletableName
    var confirmDelete by remember(deletableName) { mutableStateOf(false) }
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) { creating = false; password = ""; masterVisible = false; seed = ""; pepper = ""; appKey = "" }
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
        vm.slots?.let { slots ->
            KeysScreen(vm, slots, authenticate, securityKey, requestLock)
            return@Surface
        }
        val rows = vm.healthRows
        if (vm.unlocked && rows != null) {
            BackHandler(enabled = !confirmLock, onBack = vm::closeHealth)
            Column(Modifier.safeDrawingPadding().padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Password health report", style = MaterialTheme.typography.headlineMedium)
                if (vm.editing) Text("Set the current entry to include its edits in the report.")
                LazyColumn(Modifier.weight(1f).fillMaxWidth().semantics { isSensitiveData = true },
                    verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    items(rows.size) { index -> Text(rows[index]) }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = vm::closeHealth) { Text("Back to vault") }
                    OutlinedButton(onClick = requestLock) { Text("Lock") }
                }
            }
            return@Surface
        }
        if (vm.unlocked) {
            if (vm.inEntry) EntryEditor(vm, copy) { confirmDelete = true }
            else VaultList(vm, requestLock, { export.launch("${vm.dbName}.keptino") }, openSettings)
            return@Surface
        }
        BackHandler(enabled = settings && vm.configured && !confirmUsb) { settings = false }
        Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding().verticalScroll(rememberScrollState()).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (vm.configured && !settings) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    ActionIcon(R.drawable.action_settings, "Settings", !vm.busy) { password = ""; masterVisible = false; settings = true }
                }
                Column(Modifier.fillMaxWidth().padding(vertical = 16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Image(painterResource(R.mipmap.ic_launcher_foreground), null, Modifier.size(84.dp))
                    Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium, color = N.green)
                }
            } else if (vm.configured) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    ActionIcon(R.drawable.action_back, "Back to unlock", !vm.busy) { settings = false }
                    Text("Settings", style = MaterialTheme.typography.titleLarge)
                }
                vm.keyProtection?.let { Readout(it) }
            }
            warnings.forEach { Text(it, color = N.rose) }
            if (vm.busy) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                if (vm.opening) {
                    if (vm.keyInstruction.isNotEmpty()) Text(vm.keyInstruction)
                    OutlinedButton(onClick = { vm.cancelKeyOperation() }) { Text("Cancel unlock") }
                } else Text("Working…")
            }
            if (vm.status.isNotEmpty()) Readout(vm.status)
            if (BuildConfig.DEBUG) {
                if (settings || !vm.configured) OutlinedButton(enabled = !vm.busy, onClick = { confirmUsb = true }) { Text("Import R2 setup from Linux") }
                if (confirmUsb) AlertDialog(onDismissRequest = { confirmUsb = false },
                    title = { Text("Use this Linux computer’s R2 setup?") },
                    text = { Text("Keptino will check the bucket, then ask you to unlock the phone to save the Linux pepper and R2 credentials.") },
                    confirmButton = { TextButton(onClick = { confirmUsb = false; vm.importR2(authenticate) }) { Text("Receive setup") } },
                    dismissButton = { TextButton(onClick = { confirmUsb = false }) { Text("Cancel") } })
            }
            if (!vm.configured) {
                Text("Set up Keptino", style = MaterialTheme.typography.titleLarge)
                Text("For your first vault, choose a pepper seed and keep it for setup on other devices. For an existing vault, use its original seed or 64-character hexadecimal pepper. Seed derivation requires 4 GiB of available memory.")
                Input("Pepper seed", seed, { seed = it }, secret = true, enabled = !vm.busy)
                Input("Or original pepper (hex)", pepper, { pepper = it }, secret = true, enabled = !vm.busy)
                Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Checkbox(r2, { r2 = it; keyId = ""; appKey = "" }, enabled = !vm.busy)
                    Text("Use Cloudflare R2")
                }
                if (r2) {
                    Input("R2 account ID", account, { account = it }, enabled = !vm.busy)
                    Input("R2 bucket name", bucket, { bucket = it }, enabled = !vm.busy)
                } else Text("Backblaze sync (optional)")
                Input(if (r2) "R2 access key ID" else "Application key ID", keyId, { keyId = it }, enabled = !vm.busy)
                Input(if (r2) "R2 secret access key" else "Application key", appKey, { appKey = it }, secret = true, enabled = !vm.busy)
                if (BuildConfig.DEBUG && !r2) Input("Backblaze API base URL", authUrl, { authUrl = it }, enabled = !vm.busy)
                Button(enabled = !vm.busy, onClick = { vm.setup(seed, pepper, keyId, appKey, authUrl, authenticate, if (r2) "r2" else "b2", account, bucket); seed = ""; pepper = ""; appKey = "" }) { Text("Save setup") }
            } else if (!settings) {
                var keyHint by remember(vm.dbName) { mutableStateOf(false) }
                LaunchedEffect(vm.dbName) { kotlinx.coroutines.delay(300); keyHint = vm.localKeyHint(vm.dbName) }
                Input("Vault name", vm.dbName, { vm.dbName = it }, enabled = !vm.busy)
                Input("Master password", password, { password = it }, secret = true, enabled = !vm.busy,
                    visible = masterVisible, toggle = { masterVisible = !masterVisible })
                if (keyHint) Readout("Security key enrolled. Connect it before unlocking.")
                Primary("Unlock", Modifier.fillMaxWidth(), !vm.busy) { vm.unlock(password, offline, authenticate, securityKey()); password = ""; masterVisible = false }
                TextButton(enabled = !vm.busy, modifier = Modifier.fillMaxWidth(), onClick = { password = ""; masterVisible = false; creating = true }) { Text("Create a new vault") }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Switch(offline, { offline = it }, enabled = !vm.busy)
                    Text("Open local copy only")
                }
                if (creating) CreateVaultDialog(onDismiss = { creating = false }) { name, master, confirmation ->
                    creating = false
                    vm.create(name, master, confirmation, offline, authenticate, securityKey())
                }
                if (vm.adoptName == vm.dbName && !offline) {
                    var confirm by remember(vm.dbName) { mutableStateOf(false) }
                    OutlinedButton(enabled = !vm.busy, onClick = { confirm = true }) { Text("Adopt bucket copy") }
                    if (confirm) AlertDialog(onDismissRequest = { confirm = false }, title = { Text("Adopt bucket copy?") },
                        text = { Text("Keptino will open the bucket copy with the password and any enrolled key, then keep the current local copy as a generation.") },
                        confirmButton = { TextButton(onClick = {
                            confirm = false
                            vm.unlock(password, false, authenticate, securityKey(), adopt = true)
                            password = ""
                        }) { Text("Adopt") } }, dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } })
                }
            } else {
                Input("Vault name", vm.dbName, { vm.dbName = it }, enabled = !vm.busy)
                OutlinedButton(enabled = !vm.busy, onClick = { import.launch(arrayOf("*/*")) }) { Text("Import encrypted vault") }
                OutlinedButton(enabled = !vm.busy, onClick = { export.launch("${vm.dbName}.keptino") }) { Text("Export saved vault") }
                OutlinedButton(enabled = !vm.busy, onClick = vm::changeSetup) { Text("Change setup") }
            }
        }
    }
    if (deletableName != null && confirmDelete) AlertDialog(onDismissRequest = { confirmDelete = false },
        title = { Text("Delete '$deletableName'?") },
        text = { Text("Save the vault to make this deletion permanent.") },
        confirmButton = { TextButton(onClick = { confirmDelete = false; vm.deleteEntry(deletableName) }) { Text("Delete") } },
        dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } })
    if (vm.unlocked && confirmLock) AlertDialog(onDismissRequest = { confirmLock = false }, title = { Text("Discard unsaved changes?") },
        text = { Text("Save first to keep changes to this vault.") },
        confirmButton = { TextButton(onClick = { confirmLock = false; lock(); settings = settingsAfterLock; settingsAfterLock = false }) { Text("Discard and lock") } },
        dismissButton = { TextButton(onClick = { confirmLock = false }) { Text("Cancel") } })
}

@Composable
internal fun CreateVaultDialog(onDismiss: () -> Unit, onCreate: (String, String, String) -> Unit) {
    var name by remember { mutableStateOf("") }
    var master by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("Create a vault") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Input("New vault name", name, { name = it })
                Input("New master password", master, { master = it }, secret = true)
                Input("Confirm master password", confirmation, { confirmation = it }, secret = true)
                if (confirmation.isNotEmpty() && master != confirmation) Text("The passwords do not match.")
                Text("If you lose the master password, you cannot recover this vault.")
            }
        },
        confirmButton = {
            TextButton(enabled = validVaultName(name) && master.isNotEmpty() && master == confirmation,
                onClick = { onCreate(name, master, confirmation) }) { Text("Create") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}

@Composable
private fun Input(label: String, value: String, change: (String) -> Unit, secret: Boolean = false,
                  enabled: Boolean = true, visible: Boolean = false, toggle: (() -> Unit)? = null) {
    OutlinedTextField(value, change, label = { Text(label) }, enabled = enabled, singleLine = true, modifier = Modifier.fillMaxWidth().semantics { isSensitiveData = secret },
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = if (secret) KeyboardType.Password else KeyboardType.Text),
        shape = MaterialTheme.shapes.small,
        colors = OutlinedTextFieldDefaults.colors(unfocusedContainerColor = N.field, focusedContainerColor = N.field),
        trailingIcon = if (toggle == null) null else {{ ActionIcon(if (visible) R.drawable.action_eye else R.drawable.action_hidden,
            if (visible) "Hide master password" else "Reveal master password", enabled, click = toggle) }},
        visualTransformation = if (secret && !visible) PasswordVisualTransformation() else VisualTransformation.None)
}

@Composable
private fun KeysScreen(vm: VaultViewModel, slots: Array<String>, authenticate: suspend (Cipher) -> Cipher,
                       securityKey: () -> AndroidSecurityKey, lock: () -> Unit) {
    var remove by remember(slots) { mutableIntStateOf(0) }
    var touchOnly by remember(slots) { mutableStateOf(false) }
    var password by remember(slots) { mutableStateOf("") }
    var confirming by remember(slots) { mutableStateOf(false) }
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) { password = ""; confirming = false }
        }
        owner.lifecycle.addObserver(observer)
        onDispose { owner.lifecycle.removeObserver(observer) }
    }
    BackHandler { if (vm.busy) vm.cancelKeyOperation() else vm.closeKeys() }
    Column(Modifier.safeDrawingPadding().imePadding().padding(20.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Security keys", style = MaterialTheme.typography.headlineMedium)
        Text(if (slots.isEmpty()) "If every enrolled key is lost while the vault is locked, the vault cannot be opened."
             else "Select keys to remove, or add a spare. Each remaining key must be present during removal.")
        slots.forEachIndexed { index, label ->
            val bit = 1 shl index
            Row { Checkbox(remove and bit != 0, { remove = remove xor bit }, enabled = !vm.busy)
                Text(label, Modifier.padding(top = 12.dp)) }
        }
        if (remove == 0 && slots.size < 4) Row {
            Checkbox(touchOnly, { touchOnly = it }, enabled = !vm.busy)
            Text("Enroll as touch-only", Modifier.padding(top = 12.dp))
        }
        Input("Master password", password, { password = it }, secret = true, enabled = !vm.busy)
        val action = when {
            remove != 0 -> "Remove selected keys"
            slots.isEmpty() -> "Protect with a security key"
            else -> "Add a key"
        }
        Button(modifier = Modifier.fillMaxWidth(), enabled = !vm.busy && password.isNotEmpty() && (remove != 0 || slots.size < 4),
            onClick = { confirming = true }) { Text(action) }
        if (confirming) AlertDialog(onDismissRequest = { confirming = false }, title = { Text("$action?") },
            text = { Text(when {
                remove == 0 -> "Save this key change to the vault."
                else -> slots.filterIndexed { index, _ -> remove and (1 shl index) != 0 }.joinToString("\n") +
                    if (Integer.bitCount(remove) == slots.size) "\nRemoving all keys turns off security-key protection." else ""
            }) },
            confirmButton = { TextButton(onClick = {
                confirming = false
                vm.changeKeys(password, remove, touchOnly, authenticate, securityKey())
                password = ""
            }) { Text("Save key change") } },
            dismissButton = { TextButton(onClick = { confirming = false }) { Text("Cancel") } })
        if (vm.busy) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            if (vm.keyInstruction.isNotEmpty()) Text(vm.keyInstruction)
            OutlinedButton(onClick = { vm.cancelKeyOperation() }) { Text("Cancel operation") }
        }
        if (vm.status.isNotEmpty()) Readout(vm.status)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(enabled = !vm.busy, onClick = vm::closeKeys) { Text("Back to vault") }
            OutlinedButton(onClick = lock) { Text("Lock") }
        }
    }
}
