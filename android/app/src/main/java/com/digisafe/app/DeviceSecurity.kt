package com.digisafe.app

import android.content.Context
import android.os.Build
import android.provider.Settings

/** Local indicators only. Some OEMs restrict access to individual boot properties. */
internal fun deviceWarnings(context: Context): List<String> = buildList {
    val properties = try {
        val process = ProcessBuilder("/system/bin/getprop").start()
        val entries = process.inputStream.bufferedReader().useLines { lines ->
            val line = Regex("""^\[([^]]+)]\s*:\s*\[(.*)]$""")
            lines.mapNotNull { line.matchEntire(it)?.destructured?.let { (k, v) -> k to v } }.toMap()
        }
        if (process.waitFor() == 0) entries else emptyMap()
    } catch (_: java.io.IOException) { emptyMap() }
    properties["ro.boot.verifiedbootstate"]?.takeIf { it.isNotBlank() && it != "green" }?.let {
        add("Verified Boot reports $it.")
    }
    if (properties["ro.boot.flash.locked"] == "0" || properties["ro.boot.vbmeta.device_state"] == "unlocked")
        add("The bootloader is unlocked.")
    if (properties["ro.debuggable"] == "1" || Build.TAGS.orEmpty().split(',').contains("test-keys"))
        add("This device runs a debuggable or test-signed system image.")
    val resolver = context.contentResolver
    fun enabled(setting: String) = try { Settings.Global.getInt(resolver, setting, 0) != 0 } catch (_: SecurityException) { false }
    if (enabled(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)) add("Developer options are enabled.")
    if (enabled(Settings.Global.ADB_ENABLED)) add("Android debugging (ADB) is enabled.")
}
