package com.keptino.app

/** A foreground operation on one security key. Native code calls these on its I/O worker. */
interface SecurityKeyIo {
    /** Returns 1 for a USB connection, 2 for NFC, or 0 if canceled. */
    fun purpose(message: String) {}
    fun begin(): Int
    fun write(packet: ByteArray)
    fun read(): ByteArray?
    fun apdu(request: ByteArray): ByteArray
    /** Native code wipes the returned byte array after copying the PIN. */
    fun pin(): ByteArray?
}

class DifferentVault(message: String) : RuntimeException(message)

object Core {
    init { System.loadLibrary("droid") }
    @JvmStatic external fun signR2(put: Boolean, account: String, bucket: String, name: String,
        id: String, secret: String, body: ByteArray, seconds: Long): Array<String>
    @JvmStatic external fun preflight(): Array<String>
    @JvmStatic external fun derivePepper(seed: ByteArray, memKib: Int): ByteArray
    fun open(dbName: String, password: ByteArray, pepper: ByteArray, local: ByteArray?, remote: ByteArray?, kdfMemKib: Int, io: SecurityKeyIo? = null): Long =
        openWithKey(dbName, password, pepper, local, remote, kdfMemKib, io)
    @JvmStatic private external fun openWithKey(dbName: String, password: ByteArray, pepper: ByteArray, local: ByteArray?, remote: ByteArray?, kdfMemKib: Int, io: SecurityKeyIo?): Long
    @JvmStatic external fun keySlots(h: Long): Array<String>
    @JvmStatic external fun fileStamp(file: ByteArray): ByteArray
    @JvmStatic external fun prepareKeys(h: Long, file: ByteArray, password: ByteArray, pepper: ByteArray, remove: Int, touchOnly: Boolean, io: SecurityKeyIo): Long
    @JvmStatic external fun modifiedTs(h: Long): Long
    @JvmStatic external fun revision(h: Long): Long
    @JvmStatic external fun uploadsPaused(h: Long): Boolean
    @JvmStatic external fun source(h: Long): Int
    @JvmStatic external fun healthReport(h: Long): Array<String>
    @JvmStatic external fun query(h: Long, q: String): Boolean
    @JvmStatic external fun next(h: Long): Boolean
    @JvmStatic external fun previous(h: Long): Boolean
    @JvmStatic external fun clear(h: Long)
    @JvmStatic external fun getField(h: Long, field: Int): ByteArray
    @JvmStatic external fun setField(h: Long, field: Int, value: ByteArray)
    /** Returns the entropy in whole bits. Only an explicit field read returns the generated text. */
    @JvmStatic external fun generatePassword(h: Long, kind: Int, count: Int, classes: Int): Int
    @JvmStatic external fun deleteSelected(h: Long, confirmedName: String): Boolean
    @JvmStatic external fun commit(h: Long): Int
    @JvmStatic external fun save(h: Long): ByteArray
    @JvmStatic external fun close(h: Long)
}
