package com.keptino.app

import android.util.Base64
import android.util.Xml
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserException
import java.net.HttpURLConnection
import java.net.URL

data class RemoteObject(val bytes: ByteArray?, val etag: String? = null)

interface VaultRemote {
    val label: String
    fun fetch(name: String): RemoteObject
    /** Returns false when another writer changed the object. */
    fun put(name: String, bytes: ByteArray, previous: RemoteObject): Boolean
}

internal class R2(private val settings: Settings,
                  private val connect: (URL) -> HttpURLConnection = { it.openConnection() as HttpURLConnection }) : VaultRemote {
    override val label = "Cloudflare R2"

    private fun request(name: String, body: ByteArray? = null): HttpURLConnection {
        require(validVaultName(name)) { "Invalid vault name" }
        val (url, date, hash, authorization) = Core.signR2(body != null, settings.account, settings.bucket, name,
            settings.keyId, settings.appKey, body ?: byteArrayOf(), System.currentTimeMillis() / 1000)
        return connect(URL(url)).apply {
            connectTimeout = 15000
            readTimeout = 30000
            instanceFollowRedirects = false
            useCaches = false
            requestMethod = if (body == null) "GET" else "PUT"
            setRequestProperty("Accept-Encoding", "identity")
            setRequestProperty("x-amz-date", date)
            setRequestProperty("x-amz-content-sha256", hash)
            setRequestProperty("Authorization", authorization)
        }
    }

    private fun missingKey(body: ByteArray): Boolean {
        val parser = Xml.newPullParser()
        return try {
            parser.setInput(body.inputStream(), "UTF-8")
            if (parser.nextTag() != XmlPullParser.START_TAG || parser.name != "Error") return false
            var code: String? = null
            while (parser.next() != XmlPullParser.END_DOCUMENT) {
                if (parser.eventType == XmlPullParser.START_TAG && parser.depth == 2 && parser.name == "Code") {
                    if (code != null) return false
                    code = parser.nextText().trim()
                }
            }
            code == "NoSuchKey"
        } catch (_: XmlPullParserException) { false }
    }

    override fun fetch(name: String): RemoteObject {
        val conn = request(name)
        try {
            val code = conn.responseCode
            if (code == 404) {
                val missing = conn.errorStream?.use { it.readBounded(MAX_METADATA_BYTES, "R2 error") }
                if (missing != null && missingKey(missing)) return RemoteObject(null)
            }
            check(code == 200) { "R2 download failed (HTTP $code)." }
            check(conn.contentLengthLong <= MAX_VAULT_BODY_BYTES) { "R2 vault is too large" }
            val body = conn.inputStream.use { it.readBounded(MAX_VAULT_BODY_BYTES, "R2 vault") }
            val bytes = java.util.Base64.getDecoder().decode(body)
            check(bytes.size <= MAX_VAULT_BYTES) { "R2 vault is too large" }
            return RemoteObject(bytes, conn.getHeaderField("ETag"))
        } finally { conn.disconnect() }
    }

    override fun put(name: String, bytes: ByteArray, previous: RemoteObject): Boolean {
        val etag = previous.etag
        if (previous.bytes != null) require(etag != null && etag != "\"*\"" && etag.matches(Regex("\"[!#-~]+\""))) {
            "R2 returned no strong ETag. Reopen before uploading."
        }
        require(bytes.size <= MAX_VAULT_BYTES)
        val body = Base64.encode(bytes, Base64.NO_WRAP)
        val conn = request(name, body)
        try {
            if (previous.bytes == null) conn.setRequestProperty("If-None-Match", "*")
            else conn.setRequestProperty("If-Match", etag)
            conn.setRequestProperty("Content-Type", "text/plain")
            conn.doOutput = true
            conn.setFixedLengthStreamingMode(body.size)
            conn.outputStream.use { it.write(body) }
            val code = conn.responseCode
            if (code in listOf(404, 409, 412)) return false
            check(code in 200..299) { "R2 upload failed (HTTP $code)." }
            return true
        } finally { conn.disconnect() }
    }
}
