package com.digisafe.app

import android.content.Context
import android.app.KeyguardManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

const val PRODUCTION_MEMORY_KIB = 4194304
const val MAX_VAULT_BYTES = 64 * 1024 * 1024

data class Settings(val pepper: ByteArray, val keyId: String = "", val appKey: String = "", val authUrl: String = "https://api.backblazeb2.com") {
    val sync: Boolean get() = keyId.isNotBlank() && appKey.isNotBlank()
}

class VaultStorage(private val context: Context) {
    private val settingsFile = AtomicFile(File(context.filesDir, "settings.enc"))
    fun configured() = settingsFile.baseFile.exists()
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey("digisafe-settings", null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder("digisafe-settings", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUnlockedDeviceRequired(context.getSystemService(KeyguardManager::class.java).isDeviceSecure).build())
        }.generateKey()
    }
    fun writeSettings(settings: Settings) {
        val plain = JSONObject().put("pepper", Base64.encodeToString(settings.pepper, Base64.NO_WRAP))
            .put("keyId", settings.keyId).put("appKey", settings.appKey).put("authUrl", settings.authUrl).toString().toByteArray()
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
            writeAtomic(settingsFile, cipher.iv + cipher.doFinal(plain))
        } finally { plain.fill(0) }
    }
    fun settings(): Settings {
        val bytes = settingsFile.readFully()
        require(bytes.size >= 28) { "Invalid saved settings" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(0, 12))) }
        val plain = cipher.doFinal(bytes, 12, bytes.size - 12)
        return try {
            val json = JSONObject(String(plain, Charsets.UTF_8))
            Settings(Base64.decode(json.getString("pepper"), Base64.DEFAULT), json.getString("keyId"), json.getString("appKey"), json.getString("authUrl"))
        } finally { plain.fill(0) }
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
