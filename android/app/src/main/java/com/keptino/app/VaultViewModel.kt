package com.keptino.app

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import javax.crypto.Cipher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal data class GeneratorOptions(
    val passphrase: Boolean = false,
    val length: String = "24",
    val words: String = "6",
    val classes: Int = 15,
) {
    val count: Int? get() = (if (passphrase) words else length).toIntOrNull()
    val valid: Boolean get() = if (passphrase) (count ?: 0) in 1..32 else (count ?: 0) in 1..256 && classes != 0
}

class VaultViewModel(application: Application) : AndroidViewModel(application) {
    val storage = VaultStorage(application)
    var configured by mutableStateOf(storage.configured()); private set
    var unlocked by mutableStateOf(false); private set
    var busy by mutableStateOf(false); private set
    var status by mutableStateOf(""); private set
    var dbName by mutableStateOf("main")
    var query by mutableStateOf("")
    var fields by mutableStateOf(List(9) { "" }); private set
    var revealed by mutableStateOf(setOf<Int>()); private set
    var dirty by mutableStateOf(false); private set
    var healthRows by mutableStateOf<Array<String>?>(null); private set
    internal var generator by mutableStateOf(GeneratorOptions())
    var keyProtection by mutableStateOf<String?>(null); private set
    private var sessionSync: CloudSession? = null
    private var heldFile: ByteArray? = null
    var slots by mutableStateOf<Array<String>?>(null); private set
    var adoptName by mutableStateOf<String?>(null); private set
    var confirmEmptyBucket by mutableStateOf(false); private set
    private var heldRevision = 0uL
    private var handle = 0L
    var editing by mutableStateOf(false); private set
    private var committedDirty = false
    private var currentEntryName by mutableStateOf("")
    val deletableName: String? get() = currentEntryName.takeIf { unlocked && !busy && !editing && it.isNotEmpty() }
    @Volatile private var generation = 0L
    // A save owns this handle until the local atomic write returns, even if the UI locks.
    private var savingHandle = 0L
    private fun task(block: suspend (Long) -> Unit) {
        if (busy) return
        val started = generation
        busy = true
        viewModelScope.launch {
            try {
                block(started)
            } catch (e: Exception) {
                if (started == generation) status = e.message ?: "Operation failed"
            } finally {
                busy = false
            }
        }
    }
    suspend fun refreshKeyProtection() {
        keyProtection = withContext(Dispatchers.IO) {
            try { storage.keyProtection() } catch (_: Exception) { "Settings key protection unavailable." }
        }
    }
    fun changeSetup() { if (!busy && !unlocked) { configured = false; status = "Leave both pepper fields empty to keep the saved pepper" } }
    fun setup(seed: String, pepperHex: String, keyIdInput: String, appKeyInput: String, authUrl: String, authenticate: suspend (Cipher) -> Cipher,
              provider: String = "b2", account: String = "", bucket: String = "") = task { started ->
        // Backblaze keys never contain whitespace; keyboards and pastes often add some.
        val keyId = keyIdInput.trim(); val appKey = appKeyInput.trim()
        require((keyId.isBlank() && appKey.isBlank()) || (keyId.isNotBlank() && appKey.isNotBlank())) { "Enter both access keys or leave both empty" }
        val pepper = withContext(Dispatchers.IO) {
            if (pepperHex.isNotBlank()) {
                require(pepperHex.matches(Regex("[0-9a-fA-F]{64}"))) { "Pepper must be exactly 64 hexadecimal characters" }
                ByteArray(32) { pepperHex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            } else if (seed.isEmpty() && storage.configured()) {
                storage.settings(authenticate).pepper // Changing Backblaze credentials only; keep the saved pepper.
            } else {
                require(seed.isNotEmpty()) { "Enter the original pepper seed or pepper value" }
                val bytes = seed.toByteArray(); try { Core.derivePepper(bytes, PRODUCTION_MEMORY_KIB) } finally { bytes.fill(0) }
            }
        }
        try {
            withContext(Dispatchers.IO) { storage.writeSettings(Settings(pepper, keyId, appKey, authUrl, provider, account.trim(), bucket.trim()), authenticate) }
            configured = true
            refreshKeyProtection()
            if (started == generation) status = "Setup saved"
        } finally {
            pepper.fill(0)
        }
    }
    fun importR2(authenticate: suspend (Cipher) -> Cipher) = task { started ->
        check(!unlocked)
        val name = dbName
        status = "Waiting for the USB setup helper on Linux…"
        val cache = getApplication<Application>().cacheDir
        val (token, received) = withContext(Dispatchers.IO) { UsbSetup.receive(cache) }
        try {
            val found = withContext(Dispatchers.IO) { R2(received).fetch(name).bytes != null }
            check(started == generation) { "Setup canceled" }
            withContext(Dispatchers.IO) { storage.writeSettings(received, authenticate) }
            withContext(Dispatchers.IO) { UsbSetup.receipt(cache, token, if (found) "found" else "empty") }
            if (started == generation) {
                configured = true
                refreshKeyProtection()
                status = if (found) "R2 setup saved. Found $name.keptino." else "R2 setup saved. No $name.keptino in the bucket."
            }
        } catch (e: Exception) {
            UsbSetup.receipt(cache, token, "failed")
            throw e
        } finally { received.pepper.fill(0) }
    }
    private var activeKey by mutableStateOf<AndroidSecurityKey?>(null)
    val keyInstruction get() = activeKey?.instruction.orEmpty()
    val opening get() = activeKey != null
    internal fun cancelKeyOperation(background: Boolean = false) {
        val key = activeKey ?: return
        if (background && (key.awaitingDeviceCredential || key.awaitingPermission)) return
        if (!key.cancelPending()) return
        generation++
        status = if (unlocked) "Key change canceled" else "Unlock canceled"
    }
    internal fun unlock(password: String, offline: Boolean, authenticate: suspend (Cipher) -> Cipher, key: AndroidSecurityKey, adopt: Boolean = false) = task { started ->
        val name = dbName
        var selected: ByteArray? = null
        var emptyBucket = false
        if (adopt) check(adoptName == name && !offline) { "Reopen both copies before adopting." }
        activeKey = key
        val bytes = password.toByteArray()
        var settings: Settings? = null
        var pendingHandle = 0L
        try {
            val openedSettings = withContext(Dispatchers.IO) { storage.settings { cipher ->
                key.awaitingDeviceCredential = true
                try { authenticate(cipher) } finally { key.awaitingDeviceCredential = false }
            } }
            settings = openedSettings
            if (started != generation) return@task
            refreshKeyProtection()
            val sync = openedSettings.remote()
            val cloudSession = withContext(Dispatchers.IO + NonCancellable) {
                val local = storage.read(name)
                val remote = if (offline) null else sync?.fetch(name)?.bytes
                require(local != null || remote != null) { "No database found. Check the name and sync settings, import a vault, or choose Create vault." }
                val markers = storage.markers(name)
                val marker = if (local == null || markers.isEmpty()) null else {
                    val stamp = runCatching { Core.fileStamp(local) }.getOrNull()
                    markers.lastOrNull { stamp != null && it.covers(stamp) }
                }
                val matches = marker != null && !offline && marker.predecessor == fingerprint(remote)
                val identical = !offline && remote != null && remote.contentEquals(local)
                val unknown = marker?.predecessor == "?" && !identical
                if (adopt) require(local != null && remote != null) { "Adoption needs a local and a bucket copy." }
                pendingHandle = Core.open(name, bytes, openedSettings.pepper,
                    if (adopt) null else local, if (matches && !adopt) null else remote, PRODUCTION_MEMORY_KIB, key)
                selected = if (Core.source(pendingHandle) == 2) remote else local
                check(started == generation) { "Unlock canceled" }
                storage.acceptRevision(name, Core.revision(pendingHandle).toULong()) {
                    check(started == generation) { "Unlock canceled" }
                    if (adopt) {
                        key.beginCommit()
                        storage.adopt(name, checkNotNull(local), checkNotNull(remote))
                    }
                }
                if (identical && marker != null) storage.clearMarker(name, remote)
                emptyBucket = !adopt && unknown && !offline && remote == null && !Core.uploadsPaused(pendingHandle)
                sync?.let {
                    val pending = if (!adopt && !identical && (offline || matches || unknown)) marker?.predecessor else null
                    CloudSession(it, name, if (offline) local else remote, offline,
                        Core.uploadsPaused(pendingHandle) || (!adopt && unknown), pending)
                }
            }
            if (started != generation) return@task
            heldFile = selected
            confirmEmptyBucket = emptyBucket
            adoptName = null
            heldRevision = Core.revision(pendingHandle).toULong()
            sessionSync = cloudSession
            handle = pendingHandle; pendingHandle = 0L; unlocked = true; dirty = false; editing = false; committedDirty = false
            status = if (Core.source(handle) == 2) "Opened remote database" else "Opened local database"
            if (sessionSync?.paused == true) status += ". The local and remote copies need reconciliation. Uploads paused."
            Core.clear(handle); refresh()
        } catch (error: DifferentVault) {
            if (started == generation) adoptName = name
            throw error
        } finally {
            if (pendingHandle != 0L) Core.close(pendingHandle)
            bytes.fill(0); settings?.pepper?.fill(0)
            activeKey = null
            withContext(Dispatchers.IO + NonCancellable) { key.close() }
        }
    }
    internal fun create(name: String, password: String, confirmation: String, offline: Boolean,
                        authenticate: suspend (Cipher) -> Cipher, key: AndroidSecurityKey) = task { started ->
        check(configured && !unlocked)
        require(validVaultName(name)) { "Enter a vault name without a slash or NUL." }
        require(password.isNotEmpty() && password == confirmation) { "Enter the same master password twice." }
        activeKey = key
        val secret = password.toByteArray()
        var settings: Settings? = null
        var pending: CreatedVault? = null
        try {
            val authorized = withContext(Dispatchers.IO) { storage.settings { cipher ->
                key.awaitingDeviceCredential = true
                try { authenticate(cipher) } finally { key.awaitingDeviceCredential = false }
            } }
            settings = authorized
            val remote = authorized.remote()
            check(remote == null || !offline) { "Go online to check the bucket before creating a vault." }
            check(remote == null || remote is R2) { "Backblaze cannot safely reserve a new vault name. Use R2 or local-only settings." }
            withContext(Dispatchers.IO + NonCancellable) {
                val active = { check(started == generation) { "Creation canceled." } }
                active()
                pending = createVault(storage, name, secret, authorized.pepper, remote, PRODUCTION_MEMORY_KIB,
                    key, active)
            }
            if (started != generation) return@task
            val result = checkNotNull(pending)
            dbName = name
            adoptName = null
            heldRevision = Core.revision(result.handle).toULong()
            heldFile = result.file
            sessionSync = remote?.let { CloudSession(it, name, result.file, false, false) }
            handle = result.handle
            pending = null
            unlocked = true
            refresh()
            status = when {
                Core.source(handle) == 2 -> "Another device created this vault. Opened the R2 copy."
                remote != null -> "Vault created locally and in Cloudflare R2."
                else -> "Vault created locally."
            }
        } finally {
            pending?.let { Core.close(it.handle) }
            secret.fill(0)
            settings?.pepper?.fill(0)
            activeKey = null
            withContext(Dispatchers.IO + NonCancellable) { key.close() }
        }
    }
    private fun refresh() {
        currentEntryName = read(1)
        revealed = emptySet()
        fields = (1..9).map { if (it in listOf(3, 4, 5)) "" else read(it) }
    }
    private fun read(id: Int): String { val bytes = Core.getField(handle, id); return try { String(bytes, Charsets.UTF_8) } finally { bytes.fill(0) } }
    private fun action(block: () -> Unit) {
        if (busy || !unlocked) return
        try { block() } catch (e: Exception) { status = e.message ?: "Operation failed" }
    }
    fun navigate(direction: Int) = action {
        check(!editing) { "Set the current entry before navigating" }
        val found = when (direction) { -1 -> Core.previous(handle); 1 -> Core.next(handle); else -> Core.query(handle, query) }
        refresh()
        if (!found) status = "No matching entry"
    }
    fun newEntry() = action { check(!editing) { "Set the current entry before creating another" }; Core.clear(handle); refresh(); status = "New entry" }
    fun showHealth() = task { started ->
        check(unlocked) { "Unlock first" }
        val openHandle = handle
        val rows = withContext(Dispatchers.Default) { Core.healthReport(openHandle) }
        if (started == generation) healthRows = rows
    }
    fun closeHealth() { healthRows = null }
    fun edit(id: Int, text: String) = action {
        val bytes = text.toByteArray(); try { Core.setField(handle, id, bytes) } finally { bytes.fill(0) }
        fields = fields.toMutableList().also { it[id - 1] = text }; editing = true; dirty = true
    }
    fun generatePassword() = action {
        val options = generator
        val count = requireNotNull(options.count) { "Enter a generator count" }
        val bits = Core.generatePassword(handle, if (options.passphrase) 1 else 0, count, options.classes)
        editing = true
        dirty = true
        if (3 in revealed) fields = fields.toMutableList().also { it[2] = read(3) }
        val unit = if (options.passphrase) "word" else "character"
        status = "Generated $count $unit${if (count == 1) "" else "s"}, $bits bits. Set the entry to keep it."
    }
    fun deleteEntry(confirmedName: String) = action {
        if (deletableName != confirmedName || !Core.deleteSelected(handle, confirmedName)) return@action
        committedDirty = true
        dirty = true
        refresh()
        status = "Entry '$confirmedName' deleted. Save to persist changes."
    }
    fun reveal(id: Int) = action {
        if (id in revealed) { revealed = revealed - id; fields = fields.toMutableList().also { it[id - 1] = "" } }
        else { fields = fields.toMutableList().also { it[id - 1] = read(id) }; revealed = revealed + id }
    }
    fun revert() = action {
        if (currentEntryName.isEmpty()) Core.clear(handle) else Core.query(handle, currentEntryName)
        editing = false; dirty = committedDirty; refresh(); status = "Working entry edits discarded"
    }
    fun secret(id: Int): String = if (unlocked && !busy) read(id) else ""
    fun commit() = action {
        when (Core.commit(handle)) { 0 -> status = "Enter an entry name"; else -> { dirty = true; committedDirty = true; editing = false; status = "Entry set. Save to persist changes."; refresh() } }
    }
    fun showKeys() = action {
        check(!dirty && !editing) { "Save or discard entry changes before managing keys." }
        slots = Core.keySlots(handle)
    }

    fun closeKeys() { if (!busy) slots = null }

    internal fun changeKeys(password: String, remove: Int, touchOnly: Boolean, authenticate: suspend (Cipher) -> Cipher,
                            key: AndroidSecurityKey) = task { started ->
        val rows = checkNotNull(slots)
        check(!dirty && !editing && (remove != 0 || rows.size < 4))
        val original = checkNotNull(heldFile)
        val name = dbName
        val old = handle
        val previous = heldRevision
        val sync = sessionSync
        val rekey = rows.isEmpty() || remove != 0
        activeKey = key
        val secret = password.toByteArray()
        var prepared = 0L
        var settings: Settings? = null
        try {
            val authorized = withContext(Dispatchers.IO) { storage.settings { cipher ->
                key.awaitingDeviceCredential = true
                try { authenticate(cipher) } finally { key.awaitingDeviceCredential = false }
            } }
            settings = authorized
            check(started == generation) { "Key change canceled" }
            val encoded = withContext(Dispatchers.IO + NonCancellable) {
                prepared = Core.prepareKeys(old, original, secret, authorized.pepper, remove, touchOnly, key)
                val bytes = Core.save(prepared)
                storage.acceptRevision(name, Core.revision(prepared).toULong(), previous) {
                    check(started == generation) { "Key change canceled" }
                    key.beginCommit()
                    if (rekey && sync != null) storage.writeRekey(name, storage.read(name), bytes,
                        if (sync.paused) "?" else sync.predecessor)
                    else storage.write(name, bytes)
                }
                bytes
            }
            if (started != generation) return@task
            handle = prepared
            prepared = 0
            Core.close(old)
            heldRevision = Core.revision(handle).toULong()
            heldFile = encoded
            slots = Core.keySlots(handle)
            refresh()
            if (rekey) sync?.rekeyCommitted()
            uploadSaved(name, encoded, started)
        } finally {
            if (prepared != 0L) Core.close(prepared)
            secret.fill(0)
            settings?.pepper?.fill(0)
            activeKey = null
            withContext(Dispatchers.IO + NonCancellable) { key.close() }
        }
    }

    fun publishToEmptyBucket() = task { started ->
        check(confirmEmptyBucket && unlocked && !dirty)
        sessionSync?.allowEmpty()
        confirmEmptyBucket = false
        uploadSaved(dbName, checkNotNull(heldFile), started)
    }

    fun save() = task { started ->
        check(unlocked) { "Unlock first" }
        check(!editing) { "Set the current entry before saving" }
        val name = dbName
        val previous = heldRevision
        val saving = handle
        savingHandle = saving
        val encoded = try {
            withContext(Dispatchers.IO) {
                Core.save(saving).also { bytes ->
                    storage.acceptRevision(name, Core.revision(saving).toULong(), previous) { storage.write(name, bytes) }
                }
            }
        } finally {
            savingHandle = 0L
            if (saving != handle) Core.close(saving)
        }
        if (started != generation) return@task
        heldRevision = Core.revision(handle).toULong()
        heldFile = encoded
        dirty = false; committedDirty = false
        uploadSaved(name, encoded, started)
    }

    private suspend fun uploadSaved(name: String, encoded: ByteArray, started: Long) {
        status = "Saved locally"
        if (sessionSync?.paused == true) {
            status = "Saved locally. Uploads paused until the copies are reconciled and reopened."
            return
        }
        sessionSync?.let { sync ->
            val result = try {
                if (sync.upload(encoded) { started == generation }) {
                    withContext(Dispatchers.IO) { storage.clearMarker(name, encoded) }
                    "Saved locally and to ${sync.label}"
                }
                else "Saved locally. The remote copy changed. Uploads paused. Reopen to reconcile."
            } catch (e: Exception) {
                "Saved locally; remote upload failed. Retry Save when connected."
            }
            if (started == generation) status = result
        }
    }
    fun importVault(bytes: ByteArray) = task { started ->
        check(!unlocked) { "Lock before importing" }
        require(bytes.size <= MAX_VAULT_BYTES) { "Vault is too large" }
        val name = dbName
        withContext(Dispatchers.IO) { storage.importNew(name, bytes) }
        if (started == generation) status = "Imported encrypted vault"
    }
    fun report(message: String) { status = message }
    fun lock() {
        activeKey?.cancel()
        generation++
        closeHealth()
        generator = GeneratorOptions()
        if (handle != 0L && handle != savingHandle) Core.close(handle)
        sessionSync = null
        heldFile = null; slots = null; confirmEmptyBucket = false; adoptName = null
        handle = 0; unlocked = false; fields = List(9) { "" }; revealed = emptySet(); query = ""; dirty = false; editing = false; committedDirty = false; currentEntryName = ""
        status = "Locked"
    }
    override fun onCleared() { lock() }
}
