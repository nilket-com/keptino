package com.keptino.app

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import android.util.Base64
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.file.Files
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject

const val PRODUCTION_MEMORY_KIB = 4194304
const val MAX_VAULT_BYTES = 64 * 1024 * 1024
/** A vault body travels base64-encoded: four thirds of the file budget, plus line breaks a server may add. */
const val MAX_VAULT_BODY_BYTES = MAX_VAULT_BYTES / 3 * 4 + 64 * 1024
/** Authorization and upload-URL responses are small JSON objects. */
const val MAX_METADATA_BYTES = 64 * 1024

data class Settings(val pepper: ByteArray, val keyId: String = "", val appKey: String = "", val authUrl: String = "https://api.backblazeb2.com",
                    val provider: String = "b2", val account: String = "", val bucket: String = "") {
    override fun toString() = "Keptino settings ($provider)"
    internal fun encode(): ByteArray {
        // Older Android readers always treat keyId/appKey as B2 credentials.
        val json = JSONObject().put("pepper", Base64.encodeToString(pepper, Base64.NO_WRAP))
            .put("keyId", if (provider == "b2") keyId else "").put("appKey", if (provider == "b2") appKey else "")
            .put("authUrl", authUrl).put("provider", provider)
        if (provider == "r2") json.put("r2Access", keyId).put("r2Secret", appKey).put("account", account).put("bucket", bucket)
        return json.toString().toByteArray()
    }

    companion object {
        internal fun parse(plain: ByteArray): Settings {
            val json = JSONObject(String(plain, Charsets.UTF_8))
            val provider = json.optString("provider", "b2")
            return Settings(Base64.decode(json.getString("pepper"), Base64.DEFAULT),
                json.getString(if (provider == "r2") "r2Access" else "keyId"),
                json.getString(if (provider == "r2") "r2Secret" else "appKey"),
                json.getString("authUrl"), provider, json.optString("account"), json.optString("bucket"))
        }
    }
    init {
        require(provider in setOf("b2", "r2")) { "Unknown sync provider" }
        if (provider == "r2") {
            require(account.matches(Regex("[0-9a-fA-F]{32}"))) { "Enter the 32-character R2 account ID" }
            require(bucket.matches(Regex("[a-z0-9][a-z0-9-]{1,61}[a-z0-9]"))) { "Invalid R2 bucket name" }
            require(keyId.isNotBlank() && appKey.isNotBlank()) { "Enter both R2 access keys" }
        }
    }
    fun remote(): VaultRemote? = if (!sync) null else if (provider == "r2") R2(copy(pepper = byteArrayOf())) else Backblaze(copy(pepper = byteArrayOf()))
    val sync: Boolean get() = keyId.isNotBlank() && appKey.isNotBlank()
}

class VaultStorage(private val context: Context) {
    private companion object {
        val settingsLock = Mutex()
        val namePattern = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
        val migrationLock = Any()
        val revisionLock = Any()
    }

    private val legacy = AtomicFile(File(context.filesDir, "settings.enc"))
    private val secure = AtomicFile(File(context.filesDir, "settings-v2.enc"))
    private val store get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val legacyAlias = "digisafe-settings"
    private val securePrefix = "digisafe-settings-v2-"

    // AtomicFile.openRead also recovers a .bak left by older framework versions.
    private fun AtomicFile.present() = baseFile.exists() || File(baseFile.path + ".bak").exists()

    init {
        for (entry in context.filesDir.list().orEmpty()) {
            val base = entry.removeSuffix(".bak")
            val name = base.removeSuffix(".digisafe")
            if (base != name && name.matches(namePattern)) {
                // Retry on access so a failed move of one vault cannot block other vaults.
                try { file(name) } catch (_: IOException) {}
            }
        }
    }

    fun configured() = secure.present() || legacy.present()

    // The v2 file contains a 16-byte key ID, a 12-byte GCM IV, and ciphertext + tag.
    // A fresh alias per write keeps the previous file/key pair usable until atomic commit.
    private fun alias(bytes: ByteArray): String {
        require(bytes.size >= 16 + 12 + 16) { "Invalid protected settings" }
        val id = ByteBuffer.wrap(bytes)
        return securePrefix + UUID(id.long, id.long)
    }

    private fun generateKey(alias: String): SecretKey {
        check(context.getSystemService(KeyguardManager::class.java).isDeviceSecure) {
            "Set a device PIN, pattern or password to protect Keptino setup."
        }
        fun generate(strongBox: Boolean): SecretKey {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUnlockedDeviceRequired(true)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .setInvalidatedByBiometricEnrollment(true)
                .setIsStrongBoxBacked(strongBox)
                .build()
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
        }
        if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            try { return generate(true) } catch (_: StrongBoxUnavailableException) { /* Try the default Keystore. */ }
        }
        return generate(false)
    }

    suspend fun keyProtection(): String? = settingsLock.withLock {
        if (!secure.present()) return@withLock if (legacy.present()) "Setup protection will be upgraded on authentication." else null
        val key = store.getKey(alias(secure.readFully()), null) as? SecretKey ?: return@withLock "Settings key unavailable."
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= 31) when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "Settings key protected by StrongBox."
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "Settings key protected by the trusted execution environment."
            KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "Settings key is hardware-backed."
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> "Settings key is software-backed."
            else -> "Settings key security level is unknown."
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) "Settings key is hardware-backed." else "Settings key is software-backed."
        }
    }

    private fun decryptCipher(alias: String, bytes: ByteArray, offset: Int): Cipher {
        val key = store.getKey(alias, null) as? SecretKey ?: error("Settings key unavailable. Re-enter setup using the original pepper.")
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            try { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes, offset, 12)) }
            catch (e: KeyPermanentlyInvalidatedException) {
                throw IllegalStateException("Settings key invalidated. Use Change setup with the original pepper.", e)
            }
        }
    }

    private suspend fun replaceSettings(authenticate: suspend (Cipher) -> Cipher, plaintext: () -> ByteArray) {
        val previous = if (secure.present()) runCatching { alias(secure.readFully()) }.getOrNull() else null
        val id = UUID.randomUUID()
        val name = securePrefix + id
        val key = generateKey(name)
        var committed = false
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
            val authorized = authenticate(cipher)
            val plain = plaintext()
            val encrypted = try { authorized.doFinal(plain) } finally { plain.fill(0) }
            val header = ByteBuffer.allocate(16).putLong(id.mostSignificantBits).putLong(id.leastSignificantBits).array()
            val blob = header + authorized.iv + encrypted
            writeAtomic(secure, blob)
            committed = true
            // Some AtomicFile implementations log a failed rename instead of throwing.
            // Keep both keys if the committed file cannot be verified.
            check(secure.readFully().contentEquals(blob)) { "Protected setup was not saved. Retry setup." }
        } finally {
            if (!committed) store.deleteEntry(name)
        }
        if (previous != null) store.deleteEntry(previous)
        retireLegacy()
    }

    private fun retireLegacy() {
        if (legacy.present()) {
            store.deleteEntry(legacyAlias)
            legacy.delete()
        }
    }

    suspend fun writeSettings(settings: Settings, authenticate: suspend (Cipher) -> Cipher) = settingsLock.withLock {
        replaceSettings(authenticate) { settings.encode() }
    }

    suspend fun settings(authenticate: suspend (Cipher) -> Cipher): Settings = settingsLock.withLock {
        if (secure.present()) {
            val bytes = secure.readFully()
            val cipher = authenticate(decryptCipher(alias(bytes), bytes, 16))
            val plain = cipher.doFinal(bytes, 28, bytes.size - 28)
            // Finish retiring the old credential if a prior migration was interrupted after commit.
            return@withLock try { retireLegacy(); Settings.parse(plain) } finally { plain.fill(0) }
        }
        val bytes = legacy.readFully()
        require(bytes.size >= 28) { "Invalid legacy settings" }
        var migrated: Settings? = null
        try {
            replaceSettings(authenticate) {
                val plain = decryptCipher(legacyAlias, bytes, 0).doFinal(bytes, 12, bytes.size - 12)
                try { migrated = Settings.parse(plain); plain } catch (e: Exception) { plain.fill(0); throw e }
            }
            checkNotNull(migrated)
        } catch (e: Exception) {
            migrated?.pepper?.fill(0)
            throw e
        }
    }
    fun file(name: String): File {
        require(name.matches(namePattern)) { "Use a database name containing letters, digits, dots, underscores or hyphens" }
        val current = File(context.filesDir, "$name.keptino")
        synchronized(migrationLock) {
            val old = AtomicFile(File(context.filesDir, "$name.digisafe"))
            if (old.present() && !AtomicFile(current).present()) {
                old.openRead().close() // Recover the committed file if an old atomic save was interrupted.
                Files.move(old.baseFile.toPath(), current.toPath())
            }
        }
        return current
    }
    // A separate keystore alias per vault also distinguishes first use from a missing record.
    // The encrypted counter is independent of pepper rotation and does not require another prompt.
    fun acceptRevision(name: String, revision: ULong, previous: ULong = revision, persist: () -> Unit = {}) = synchronized(revisionLock) {
        require(name.matches(namePattern))
        val record = AtomicFile(File(context.filesDir, "$name.revision"))
        val alias = "keptino-revision-$name"
        val ks = store
        val existingKey = ks.getKey(alias, null) as? SecretKey
        val aad = alias.toByteArray(Charsets.UTF_8)
        val floor = if (existingKey == null && !record.present()) 0uL else {
            check(existingKey != null && record.present()) {
                "Vault revision record unavailable. To recover, import a saved copy under a fresh name."
            }
            val bytes = record.openRead().use { input ->
                check(input.channel.size() == 36L) { "Invalid vault revision record" }
                input.readBytes()
            }
            val decrypt = Cipher.getInstance("AES/GCM/NoPadding")
            decrypt.init(Cipher.DECRYPT_MODE, existingKey, GCMParameterSpec(128, bytes, 0, 12))
            decrypt.updateAAD(aad)
            ByteBuffer.wrap(decrypt.doFinal(bytes, 12, 24)).long.toULong()
        }
        check(revision >= floor) {
            "This copy is revision $revision. This device has seen $floor. To recover it, import under a fresh name and open locally."
        }
        check(previous >= floor) {
            "Another session saved revision $floor. Reopen before replacing the local vault."
        }
        persist()
        if (revision > floor) {
            val key = existingKey ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256).build())
                generateKey()
            }
            val encrypt = Cipher.getInstance("AES/GCM/NoPadding")
            encrypt.init(Cipher.ENCRYPT_MODE, key)
            encrypt.updateAAD(aad)
            val bytes = encrypt.iv + encrypt.doFinal(ByteBuffer.allocate(8).putLong(revision.toLong()).array())
            writeAtomic(record, bytes)
            check(record.readFully().contentEquals(bytes)) { "Could not verify the vault revision record" }
        }
    }
    fun read(name: String): ByteArray? {
        val file = AtomicFile(file(name))
        if (!file.present()) return null
        return file.openRead().use {
            require(it.channel.size() <= MAX_VAULT_BYTES) { "Vault is too large" }
            it.readBytes()
        }
    }
    fun write(name: String, bytes: ByteArray) {
        require(bytes.size <= MAX_VAULT_BYTES) { "Vault is too large to save" }
        val target = AtomicFile(file(name))
        writeAtomic(target, bytes)
        verify(target, bytes)
    }

    private fun verify(target: AtomicFile, bytes: ByteArray) {
        // AtomicFile can log a failed rename without throwing. Verify the committed
        // bytes before the caller marks the vault clean or starts a remote upload.
        target.openRead().use { input ->
            val buffer = ByteArray(8192)
            var offset = 0
            while (offset < bytes.size) {
                val n = input.read(buffer, 0, minOf(buffer.size, bytes.size - offset))
                if (n <= 0 || (0 until n).any { buffer[it] != bytes[offset + it] }) {
                    throw IOException("Could not verify the saved vault")
                }
                offset += n
            }
            if (input.read() != -1) throw IOException("Could not verify the saved vault")
        }
    }
    private fun marker(name: String) = AtomicFile(File(file(name).path + ".rekey"))

    internal fun markers(name: String): List<RekeyMarker> = synchronized(revisionLock) {
        val file = marker(name)
        if (!file.present()) return@synchronized emptyList()
        val bytes = file.openRead().use {
            check(it.channel.size() in 1..512) { "Invalid rekey marker" }
            it.readBytes()
        }
        bytes.toString(Charsets.US_ASCII).lines().map(RekeyMarker::parse).also { require(it.size in 1..2) }
    }

    // Keep the previous marker until the successor file has committed. After
    // a crash either file can still identify its own predecessor.
    internal fun writeRekey(name: String, before: ByteArray?, successor: ByteArray, predecessor: String) {
        val stamp = Core.fileStamp(successor)
        val previous = before?.let { Core.fileStamp(it) }?.let { stamp -> markers(name).lastOrNull { it.covers(stamp) } }
        val rows = listOfNotNull(previous, RekeyMarker.from(stamp, predecessor))
        val data = rows.joinToString("\n") { it.encode() }.toByteArray(Charsets.US_ASCII)
        val target = marker(name)
        writeAtomic(target, data)
        verify(target, data)
        write(name, successor)
    }

    internal fun clearMarker(name: String, committed: ByteArray) = synchronized(revisionLock) {
        if (marker(name).present() && read(name).contentEquals(committed)) marker(name).delete()
    }

    internal fun adopt(name: String, expected: ByteArray, downloaded: ByteArray) {
        val current = read(name)
        if (current.contentEquals(downloaded)) { clearMarker(name, downloaded); return }
        check(current.contentEquals(expected)) { "Local vault changed. Reopen before adopting." }
        val generation = AtomicFile(File(file(name).path + ".1"))
        writeAtomic(generation, expected)
        verify(generation, expected)
        write(name, downloaded)
        marker(name).delete()
    }

    private fun writeAtomic(file: AtomicFile, bytes: ByteArray) {
        val stream = file.startWrite()
        try { stream.write(bytes); file.finishWrite(stream) }
        catch (e: Exception) { file.failWrite(stream); throw e }
    }
}

internal fun java.io.InputStream.readBounded(limit: Int, label: String): ByteArray {
    val output = java.io.ByteArrayOutputStream()
    val buffer = ByteArray(8192)
    while (true) {
        val count = read(buffer, 0, minOf(buffer.size, limit - output.size() + 1))
        if (count < 0) return output.toByteArray()
        check(count <= limit - output.size()) { "$label is too large" }
        output.write(buffer, 0, count)
    }
}

/** B2 carries base64 of the Linux .keptino file, not the raw file. */
class Backblaze(private val settings: Settings) : VaultRemote {
    override val label = "Backblaze"
    override fun fetch(name: String) = RemoteObject(download(name))
    override fun put(name: String, bytes: ByteArray, previous: RemoteObject): Boolean { upload(name, bytes); return true }
    private fun checkedUrl(value: String): URL {
        val url = URL(value)
        require(url.protocol == "https" || (BuildConfig.DEBUG && url.protocol == "http" && url.host in listOf("10.0.2.2", "127.0.0.1", "localhost"))) { "Backblaze requires HTTPS" }
        require(url.userInfo == null) { "Credentials in URLs are not supported" }
        return url
    }
    private fun request(stage: String, url: String, token: String, body: ByteArray? = null, headers: Map<String, String> = emptyMap(), missingOk: Boolean = false, limit: Int = MAX_METADATA_BYTES): ByteArray? {
        val conn = checkedUrl(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 15000; conn.readTimeout = 30000; conn.instanceFollowRedirects = false
        conn.setRequestProperty("Authorization", token)
        headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
        try {
            if (body != null) { conn.requestMethod = "POST"; conn.doOutput = true; conn.setFixedLengthStreamingMode(body.size); conn.outputStream.use { it.write(body) } }
            val code = conn.responseCode
            if (code == 404 && missingOk) return null
            if (code !in 200..299) {
                // B2 error bodies are small JSON objects: {"status":401,"code":"bad_auth_token","message":"..."}
                val detail = try {
                    val text = conn.errorStream?.use { String(it.readBounded(4096, "Backblaze error")) }.orEmpty()
                    val json = JSONObject(text)
                    listOf(json.optString("code"), json.optString("message")).filter { it.isNotBlank() }.joinToString(": ")
                } catch (_: Exception) { "" }
                error("Backblaze $stage failed (HTTP $code${if (detail.isEmpty()) "" else ", $detail"})")
            }
            // Refuse a declared oversize before reading a byte; a body without a
            // declared length is still cut off at the same limit while reading.
            val declared = conn.contentLengthLong
            check(declared <= limit) { "Backblaze $stage response is too large" }
            return conn.inputStream.use { it.readBounded(limit, "Backblaze $stage response") }
        } finally { conn.disconnect() }
    }
    private fun authorize(): JSONObject {
        val basic = Base64.encodeToString("${settings.keyId}:${settings.appKey}".toByteArray(), Base64.NO_WRAP)
        return JSONObject(String(request("authorization", settings.authUrl.trimEnd('/') + "/b2api/v2/b2_authorize_account", "Basic $basic")!!))
    }
    private fun bucketField(auth: JSONObject, field: String): String {
        val value = auth.getJSONObject("allowed").opt(field) as? String
        require(!value.isNullOrBlank()) { "Use a Backblaze application key restricted to the vault bucket." }
        return value
    }
    private fun encode(value: String) = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    fun download(name: String): ByteArray? {
        val auth = authorize()
        val bucket = encode(bucketField(auth, "bucketName"))
        val file = encode("$name.keptino")
        val body = request("download", auth.getString("downloadUrl").trimEnd('/') + "/file/$bucket/$file", auth.getString("authorizationToken"), missingOk = true, limit = MAX_VAULT_BODY_BYTES) ?: return null
        return Base64.decode(body, Base64.DEFAULT).also { require(it.size <= MAX_VAULT_BYTES) { "Remote vault is too large" } }
    }
    fun upload(name: String, bytes: ByteArray) {
        val auth = authorize()
        val body = JSONObject().put("bucketId", bucketField(auth, "bucketId")).toString().toByteArray()
        val upload = JSONObject(String(request("upload URL request", auth.getString("apiUrl") + "/b2api/v2/b2_get_upload_url", auth.getString("authorizationToken"), body, mapOf("Content-Type" to "application/json"))!!))
        val encoded = Base64.encode(bytes, Base64.NO_WRAP)
        val digest = MessageDigest.getInstance("SHA-1").digest(encoded).joinToString("") { "%02x".format(it) }
        request("upload", upload.getString("uploadUrl"), upload.getString("authorizationToken"), encoded, mapOf(
            "X-Bz-File-Name" to encode("$name.keptino"),
            "Content-Type" to "text/plain", "X-Bz-Content-Sha1" to digest, "X-Bz-Info-Author" to "Keptino", "X-Bz-Server-Side-Encryption" to "AES256"))
    }
}

/** Compare against the encrypted object observed at unlock or the last successful upload. */
// "-" identifies an observed missing object. "?" records an offline rekey.
internal fun fingerprint(bytes: ByteArray?): String = bytes?.let {
    android.util.Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(it), android.util.Base64.NO_WRAP)
} ?: "-"

internal data class RekeyMarker(val salt: String, val revision: ULong, val predecessor: String) {
    fun covers(stamp: ByteArray): Boolean {
        val local = from(stamp, predecessor)
        return salt == local.salt && local.revision >= revision
    }
    fun encode() = "$salt $revision $predecessor"
    companion object {
        fun from(stamp: ByteArray, predecessor: String): RekeyMarker {
            require(stamp.size == 40)
            val salt = android.util.Base64.encodeToString(stamp, 0, 32, android.util.Base64.NO_WRAP)
            return RekeyMarker(salt, ByteBuffer.wrap(stamp, 32, 8).long.toULong(), predecessor)
        }
        fun parse(line: String): RekeyMarker {
            val fields = line.split(' ')
            require(fields.size == 3 && fields[0].length == 44 &&
                (fields[2].length == 44 || fields[2] == "-" || fields[2] == "?")) { "Invalid rekey marker" }
            return RekeyMarker(fields[0], fields[1].toULong(), fields[2])
        }
    }
}

internal class CloudSession(
    private val client: VaultRemote,
    private val name: String,
    original: ByteArray?,
    private var offline: Boolean,
    initiallyPaused: Boolean,
    pendingPredecessor: String? = null,
) {
    val label get() = client.label
    private var expected = pendingPredecessor ?: fingerprint(original)
    val predecessor get() = if (offline && pendingPredecessorAtOpen == null) "?" else expected
    private val pendingPredecessorAtOpen = pendingPredecessor
    fun allowEmpty() { expected = "-"; offline = false; paused = false }
    fun rekeyCommitted() { if (predecessor == "?") paused = true }
    var paused = initiallyPaused
        private set

    suspend fun upload(bytes: ByteArray, active: () -> Boolean): Boolean {
        if (paused) return false
        val remote = withContext(Dispatchers.IO) { client.fetch(name) }
        val observed = fingerprint(remote.bytes)
        if (!active()) return false
        if (observed != expected && !(offline && pendingPredecessorAtOpen == null && observed == "-")) {
            paused = true
            return false
        }
        if (!withContext(Dispatchers.IO) { client.put(name, bytes, remote) }) {
            paused = true
            return false
        }
        expected = fingerprint(bytes)
        offline = false
        return true
    }
}
