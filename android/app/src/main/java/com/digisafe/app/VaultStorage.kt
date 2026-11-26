package com.digisafe.app

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
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject

const val PRODUCTION_MEMORY_KIB = 4194304
const val MAX_VAULT_BYTES = 64 * 1024 * 1024

data class Settings(val pepper: ByteArray, val keyId: String = "", val appKey: String = "", val authUrl: String = "https://api.backblazeb2.com") {
    val sync: Boolean get() = keyId.isNotBlank() && appKey.isNotBlank()
}

class VaultStorage(private val context: Context) {
    private companion object { val settingsLock = Mutex() }

    private val legacy = AtomicFile(File(context.filesDir, "settings.enc"))
    private val secure = AtomicFile(File(context.filesDir, "settings-v2.enc"))
    private val store get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val legacyAlias = "digisafe-settings"
    private val securePrefix = "digisafe-settings-v2-"

    // AtomicFile.openRead also recovers a .bak left by older framework versions.
    private fun AtomicFile.present() = baseFile.exists() || File(baseFile.path + ".bak").exists()

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
            "Set a device PIN, pattern or password to protect DigiSafe setup."
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

    private fun parse(plain: ByteArray): Settings {
        val json = JSONObject(String(plain, Charsets.UTF_8))
        return Settings(Base64.decode(json.getString("pepper"), Base64.DEFAULT), json.getString("keyId"), json.getString("appKey"), json.getString("authUrl"))
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
        replaceSettings(authenticate) {
            JSONObject().put("pepper", Base64.encodeToString(settings.pepper, Base64.NO_WRAP))
                .put("keyId", settings.keyId).put("appKey", settings.appKey).put("authUrl", settings.authUrl).toString().toByteArray()
        }
    }

    suspend fun settings(authenticate: suspend (Cipher) -> Cipher): Settings = settingsLock.withLock {
        if (secure.present()) {
            val bytes = secure.readFully()
            val cipher = authenticate(decryptCipher(alias(bytes), bytes, 16))
            val plain = cipher.doFinal(bytes, 28, bytes.size - 28)
            // Finish retiring the old credential if a prior migration was interrupted after commit.
            return@withLock try { retireLegacy(); parse(plain) } finally { plain.fill(0) }
        }
        val bytes = legacy.readFully()
        require(bytes.size >= 28) { "Invalid legacy settings" }
        var migrated: Settings? = null
        try {
            replaceSettings(authenticate) {
                val plain = decryptCipher(legacyAlias, bytes, 0).doFinal(bytes, 12, bytes.size - 12)
                try { migrated = parse(plain); plain } catch (e: Exception) { plain.fill(0); throw e }
            }
            checkNotNull(migrated)
        } catch (e: Exception) {
            migrated?.pepper?.fill(0)
            throw e
        }
    }
    fun file(name: String): File {
        require(name.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}"))) { "Use a database name containing letters, digits, dots, underscores or hyphens" }
        return File(context.filesDir, "$name.digisafe")
    }
    fun read(name: String): ByteArray? {
        val file = file(name)
        if (!file.exists()) return null
        require(file.length() <= MAX_VAULT_BYTES) { "Vault is too large" }
        return AtomicFile(file).readFully()
    }
    fun write(name: String, bytes: ByteArray) = writeAtomic(AtomicFile(file(name)), bytes)
    private fun writeAtomic(file: AtomicFile, bytes: ByteArray) {
        val stream = file.startWrite()
        try { stream.write(bytes); file.finishWrite(stream) }
        catch (e: Exception) { file.failWrite(stream); throw e }
    }
}

/** B2 carries base64 of the Linux .digisafe file, not the raw file. */
class Backblaze(private val settings: Settings) {
    private fun checkedUrl(value: String): URL {
        val url = URL(value)
        require(url.protocol == "https" || (BuildConfig.DEBUG && url.protocol == "http" && url.host in listOf("10.0.2.2", "127.0.0.1", "localhost"))) { "Backblaze requires HTTPS" }
        require(url.userInfo == null) { "Credentials in URLs are not supported" }
        return url
    }
    private fun request(stage: String, url: String, token: String, body: ByteArray? = null, headers: Map<String, String> = emptyMap(), missingOk: Boolean = false): ByteArray? {
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
                    val text = conn.errorStream?.use { String(it.readNBytes(4096)) }.orEmpty()
                    val json = JSONObject(text)
                    listOf(json.optString("code"), json.optString("message")).filter { it.isNotBlank() }.joinToString(": ")
                } catch (_: Exception) { "" }
                error("Backblaze $stage failed (HTTP $code${if (detail.isEmpty()) "" else ", $detail"})")
            }
            return conn.inputStream.use { stream ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) { val n = stream.read(buffer); if (n < 0) break; check(output.size() + n <= MAX_VAULT_BYTES * 2) { "Remote vault is too large" }; output.write(buffer, 0, n) }
                output.toByteArray()
            }
        } finally { conn.disconnect() }
    }
    private fun authorize(): JSONObject {
        val basic = Base64.encodeToString("${settings.keyId}:${settings.appKey}".toByteArray(), Base64.NO_WRAP)
        return JSONObject(String(request("authorization", settings.authUrl.trimEnd('/') + "/b2api/v2/b2_authorize_account", "Basic $basic")!!))
    }
    fun download(name: String): ByteArray? {
        val auth = authorize()
        val file = URLEncoder.encode("$name.digisafe", "UTF-8").replace("+", "%20")
        val body = request("download", auth.getString("downloadUrl") + "/file/digisafe/$file", auth.getString("authorizationToken"), missingOk = true) ?: return null
        return Base64.decode(body, Base64.DEFAULT).also { require(it.size <= MAX_VAULT_BYTES) { "Remote vault is too large" } }
    }
    fun upload(name: String, bytes: ByteArray) {
        val auth = authorize()
        val body = JSONObject().put("bucketId", auth.getJSONObject("allowed").getString("bucketId")).toString().toByteArray()
        val upload = JSONObject(String(request("upload URL request", auth.getString("apiUrl") + "/b2api/v2/b2_get_upload_url", auth.getString("authorizationToken"), body, mapOf("Content-Type" to "application/json"))!!))
        val encoded = Base64.encode(bytes, Base64.NO_WRAP)
        val digest = MessageDigest.getInstance("SHA-1").digest(encoded).joinToString("") { "%02x".format(it) }
        request("upload", upload.getString("uploadUrl"), upload.getString("authorizationToken"), encoded, mapOf(
            "X-Bz-File-Name" to URLEncoder.encode("$name.digisafe", "UTF-8").replace("+", "%20"),
            "Content-Type" to "text/plain", "X-Bz-Content-Sha1" to digest, "X-Bz-Info-Author" to "DigiSafe", "X-Bz-Server-Side-Encryption" to "AES256"))
    }
}
