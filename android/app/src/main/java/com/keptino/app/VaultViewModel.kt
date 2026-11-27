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
    private var sessionSync: BackblazeSession? = null
    private var heldRevision = 0uL
    private var handle = 0L
    var editing by mutableStateOf(false); private set
    private var committedDirty = false
    private var currentEntryName by mutableStateOf("")
    val deletableName: String? get() = currentEntryName.takeIf { unlocked && !busy && !editing && it.isNotEmpty() }
    private var generation = 0L
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
    fun setup(seed: String, pepperHex: String, keyIdInput: String, appKeyInput: String, authUrl: String, authenticate: suspend (Cipher) -> Cipher) = task { started ->
        // Backblaze keys never contain whitespace; keyboards and pastes often add some.
        val keyId = keyIdInput.trim(); val appKey = appKeyInput.trim()
        require((keyId.isBlank() && appKey.isBlank()) || (keyId.isNotBlank() && appKey.isNotBlank())) { "Enter both Backblaze credentials or leave both empty" }
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
            withContext(Dispatchers.IO) { storage.writeSettings(Settings(pepper, keyId, appKey, authUrl), authenticate) }
            configured = true
            refreshKeyProtection()
            if (started == generation) status = "Setup saved"
        } finally {
            pepper.fill(0)
        }
    }
    fun unlock(password: String, offline: Boolean, authenticate: suspend (Cipher) -> Cipher) = task { started ->
        val name = dbName
        val settings = withContext(Dispatchers.IO) { storage.settings(authenticate) }
        val bytes = password.toByteArray()
        var pendingHandle = 0L
        try {
            refreshKeyProtection()
            val sync = if (settings.sync) Backblaze(settings.copy(pepper = ByteArray(0))) else null
            val cloudSession = withContext(Dispatchers.IO + NonCancellable) {
                val local = storage.read(name)
                val remote = if (offline) null else sync?.download(name)
                require(local != null || remote != null) { "No database found. Import a Linux .keptino file or enable Backblaze sync." }
                pendingHandle = Core.open(name, bytes, settings.pepper, local, remote, PRODUCTION_MEMORY_KIB)
                storage.acceptRevision(name, Core.revision(pendingHandle).toULong())
                sync?.let {
                    BackblazeSession(it, name, if (offline) local else remote, offline, Core.uploadsPaused(pendingHandle))
                }
            }
            if (started != generation) return@task
            heldRevision = Core.revision(pendingHandle).toULong()
            sessionSync = cloudSession
            handle = pendingHandle; pendingHandle = 0L; unlocked = true; dirty = false; editing = false; committedDirty = false
            status = if (Core.source(handle) == 2) "Opened remote database" else "Opened local database"
            if (sessionSync?.paused == true) status += ". The local and remote copies need reconciliation. Uploads paused."
            Core.clear(handle); refresh()
        } finally {
            if (pendingHandle != 0L) Core.close(pendingHandle)
            bytes.fill(0); settings.pepper.fill(0)
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
        dirty = false; committedDirty = false
        status = "Saved locally"
        if (sessionSync?.paused == true) {
            status = "Saved locally. Uploads paused until the copies are reconciled and reopened."
            return@task
        }
        sessionSync?.let { sync ->
            val result = try {
                if (sync.upload(encoded) { started == generation }) "Saved locally and to Backblaze"
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
        require(storage.read(name) == null) { "A local vault with this name already exists. Choose a different name to import safely." }
        withContext(Dispatchers.IO) { storage.write(name, bytes) }
        if (started == generation) status = "Imported encrypted vault"
    }
    fun report(message: String) { status = message }
    fun lock() {
        generation++
        closeHealth()
        generator = GeneratorOptions()
        if (handle != 0L && handle != savingHandle) Core.close(handle)
        sessionSync = null
        handle = 0; unlocked = false; fields = List(9) { "" }; revealed = emptySet(); query = ""; dirty = false; editing = false; committedDirty = false; currentEntryName = ""
        status = "Locked"
    }
    override fun onCleared() { lock() }
}
