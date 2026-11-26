package com.keptino.app

object Core {
    init { System.loadLibrary("droid") }
    @JvmStatic external fun preflight(): Array<String>
    @JvmStatic external fun derivePepper(seed: ByteArray, memKib: Int): ByteArray
    @JvmStatic external fun open(dbName: String, password: ByteArray, pepper: ByteArray, local: ByteArray?, remote: ByteArray?, kdfMemKib: Int): Long
    @JvmStatic external fun modifiedTs(h: Long): Long
    @JvmStatic external fun revision(h: Long): Long
    @JvmStatic external fun uploadsPaused(h: Long): Boolean
    @JvmStatic external fun source(h: Long): Int
    @JvmStatic external fun query(h: Long, q: String): Boolean
    @JvmStatic external fun next(h: Long): Boolean
    @JvmStatic external fun previous(h: Long): Boolean
    @JvmStatic external fun clear(h: Long)
    @JvmStatic external fun getField(h: Long, field: Int): ByteArray
    @JvmStatic external fun setField(h: Long, field: Int, value: ByteArray)
    @JvmStatic external fun commit(h: Long): Int
    @JvmStatic external fun save(h: Long): ByteArray
    @JvmStatic external fun close(h: Long)
}
