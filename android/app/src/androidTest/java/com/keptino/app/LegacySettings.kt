package com.keptino.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Writes `settings.enc` exactly as the application did before device credential
 * binding: AES-GCM under the Keystore alias `digisafe-settings` with no user
 * authentication, IV then ciphertext, JSON body. Test-only, so the migration path
 * can be exercised; production has no writer for this format any more.
 */
object LegacySettings {
    const val ALIAS = "digisafe-settings"
    fun file(context: Context) = File(context.filesDir, "settings.enc")

    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun freshLegacyKey(): SecretKey {
        // A leftover authenticated key under the old alias would refuse to encrypt here.
        store().deleteEntry(ALIAS)
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }

    /**
     * Writes the legacy file and returns its bytes, for later change detection. Any
     * protected settings from an earlier test are removed first, so the application
     * sees a pre-upgrade installation and nothing else.
     */
    fun write(context: Context, settings: Settings): ByteArray {
        context.filesDir.listFiles { f -> f.name.startsWith("settings-v2") }?.forEach { it.delete() }
        val plain = JSONObject().put("pepper", Base64.encodeToString(settings.pepper, Base64.NO_WRAP))
            .put("keyId", settings.keyId).put("appKey", settings.appKey).put("authUrl", settings.authUrl).toString().toByteArray()
        val bytes = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, freshLegacyKey()) }
            cipher.iv + cipher.doFinal(plain)
        } finally { plain.fill(0) }
        val target = AtomicFile(file(context))
        val stream = target.startWrite()
        try { stream.write(bytes); target.finishWrite(stream) } catch (e: Exception) { target.failWrite(stream); throw e }
        return bytes
    }

    /** True while the file still decrypts with the legacy key, that is, was not migrated. */
    fun stillLegacy(context: Context): Boolean {
        val target = file(context)
        if (!target.exists()) return false
        val key = store().getKey(ALIAS, null) as? SecretKey ?: return false
        return try {
            val bytes = target.readBytes()
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes.copyOfRange(0, 12))) }
                .doFinal(bytes, 12, bytes.size - 12)
            true
        } catch (_: Exception) { false }
    }

    /** Removes every saved setup so a following test starts unconfigured. */
    fun clear(context: Context) {
        context.filesDir.listFiles { f -> f.name.startsWith("settings") }?.forEach { it.delete() }
    }
}
