package com.keptino.app

/** The caller owns the returned handle. Only confirmed R2 creation commits a local candidate. */
internal data class CreatedVault(val handle: Long, val file: ByteArray)

internal fun createVault(storage: VaultStorage, name: String, password: ByteArray, pepper: ByteArray,
                         r2: R2?, key: AndroidSecurityKey?,
                         newHandle: () -> Long = { Core.create(name, password, pepper) },
                         checkActive: () -> Unit): CreatedVault {
    require(password.isNotEmpty()) { "Enter a master password." }
    storage.requireUnusedName(name)
    if (r2 != null) check(r2.fetch(name).bytes == null) { "This vault already exists in R2. Use Unlock." }
    checkActive()
    var handle = newHandle()
    try {
        val encoded = Core.save(handle)
        check(Core.revision(handle) == 1L) { "Unexpected initial vault revision." }
        storage.requireUnusedName(name)
        checkActive()
        key?.beginCommit()
        if (r2 != null && !r2.put(name, encoded, RemoteObject(null))) {
            key?.endCommit()
            Core.close(handle)
            handle = 0
            val winner = checkNotNull(r2.fetch(name).bytes) { "R2 creation conflicted. Reopen to check the bucket." }
            checkActive()
            handle = Core.open(name, password, pepper, null, winner, PRODUCTION_MEMORY_KIB, key)
            checkActive()
            storage.acceptNewName(name, Core.revision(handle).toULong())
            return CreatedVault(handle, winner).also { handle = 0 }
        }
        try {
            storage.acceptNewName(name, 1uL) { storage.write(name, encoded) }
        } catch (error: Exception) {
            if (r2 != null) throw IllegalStateException("Vault created in R2. Local save failed. Use Unlock to reopen it.", error)
            throw error
        }
        return CreatedVault(handle, encoded).also { handle = 0 }
    } finally {
        if (handle != 0L) Core.close(handle)
    }
}
