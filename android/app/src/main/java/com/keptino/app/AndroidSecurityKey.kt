package com.keptino.app

import android.app.AlertDialog
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.*
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import android.os.SystemClock
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.util.UUID
import java.util.concurrent.TimeoutException
import kotlinx.coroutines.*

// One instance belongs to one unlock. JNI invokes it only for a protected candidate.
internal class AndroidSecurityKey(private val activity: ComponentActivity) : SecurityKeyIo, Closeable {
    private val job = Job()
    private val usb = activity.getSystemService(UsbManager::class.java)
    private var connection: UsbDeviceConnection? = null
    private var claimed: UsbInterface? = null
    private var detachReceiver: BroadcastReceiver? = null
    @Volatile private var detached = false
    private lateinit var input: UsbEndpoint
    private lateinit var output: UsbEndpoint
    private var tag: IsoDep? = null
    var instruction by mutableStateOf("")
        private set
    @Volatile var awaitingDeviceCredential = false
    private var committing = false
    @Synchronized fun beginCommit() {
        job.ensureActive()
        committing = true
    }
    @Synchronized fun endCommit() { committing = false }
    @Synchronized fun cancelPending(): Boolean {
        if (committing) return false
        cancel()
        return true
    }
    @Volatile var awaitingPermission = false
        private set

    private fun <T> prompt(block: suspend () -> T): T = runBlocking(job) {
        withTimeout(60_000) { withContext(Dispatchers.Main) {
            check(activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) { "Return to Keptino and try again." }
            block()
        } }
    }

    private var promptTitle = "Use a security key"
    override fun purpose(message: String) { promptTitle = message }

    private suspend fun choose(labels: List<String>): Int {
        val result = CompletableDeferred<Int>()
        val dialog = AlertDialog.Builder(activity).setTitle(promptTitle)
            .setItems(labels.toTypedArray()) { _, which -> result.complete(which) }
            .setNegativeButton("Cancel") { _, _ -> result.cancel() }
            .setOnCancelListener { result.cancel() }.show()
        try { return result.await() } finally { dialog.dismiss() }
    }

    private suspend fun permission(device: UsbDevice) {
        if (usb.hasPermission(device)) return
        val action = "${activity.packageName}.USB_PERMISSION.${UUID.randomUUID()}"
        val result = CompletableDeferred<Boolean>()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                @Suppress("DEPRECATION")
                val returned = intent.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE)
                // An immutable PendingIntent can arrive without fill-in extras.
                // The action is unique to this request. Check the actual OS grant.
                if (intent.action == action && (returned == null || returned.deviceId == device.deviceId)) {
                    result.complete(usb.deviceList[device.deviceName]?.deviceId == device.deviceId && usb.hasPermission(device))
                }
            }
        }
        ContextCompat.registerReceiver(activity, receiver, IntentFilter(action), ContextCompat.RECEIVER_NOT_EXPORTED)
        val intent = PendingIntent.getBroadcast(activity, 0, Intent(action).setPackage(activity.packageName), PendingIntent.FLAG_IMMUTABLE)
        try {
            awaitingPermission = true
            usb.requestPermission(device, intent)
            check(result.await() && usb.hasPermission(device)) { "USB permission denied." }
            withTimeout(3000) {
                while (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) delay(50)
            }
        } finally {
            awaitingPermission = false
            intent.cancel()
            activity.unregisterReceiver(receiver)
        }
    }

    override fun begin(): Int {
        releaseDevice()
        val devices = usb?.deviceList.orEmpty().values.filter { dev ->
            (0 until dev.interfaceCount).any { dev.getInterface(it).interfaceClass == UsbConstants.USB_CLASS_HID }
        }.sortedBy { it.deviceId }
        val adapter = NfcAdapter.getDefaultAdapter(activity)?.takeIf { it.isEnabled }
        val labels = devices.map { "USB · ${it.productName ?: "Device"} (${it.deviceId})" } +
            if (adapter != null) listOf("Tap an NFC security key (experimental)") else emptyList()
        check(labels.isNotEmpty()) { "Connect a USB security key or enable NFC." }
        val selected = prompt { choose(labels) }
        if (selected < devices.size) {
            val device = devices[selected]
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    @Suppress("DEPRECATION")
                    val gone = intent.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE)
                    if (intent.action == UsbManager.ACTION_USB_DEVICE_DETACHED && gone?.deviceId == device.deviceId) {
                        detached = true
                        cancel()
                    }
                }
            }
            ContextCompat.registerReceiver(activity, receiver, IntentFilter(UsbManager.ACTION_USB_DEVICE_DETACHED),
                ContextCompat.RECEIVER_NOT_EXPORTED)
            detachReceiver = receiver
            prompt { permission(device) }
            job.ensureActive()
            openUsb(device)
            instruction = "Touch the USB security key when it flashes."
            return 1
        }
        instruction = "Keep the NFC security key against the phone until unlock finishes."
        val iso = prompt {
            val result = CompletableDeferred<IsoDep>()
            val dialog = AlertDialog.Builder(activity).setMessage("Hold the security key against the phone.")
                .setNegativeButton("Cancel") { _, _ -> result.cancel() }
                .setOnCancelListener { result.cancel() }.show()
            try {
                adapter!!.enableReaderMode(activity, { discovered -> IsoDep.get(discovered)?.let { result.complete(it) } },
                    NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null)
                readerEnabled = true
                result.await()
            } finally {
                dialog.dismiss()
                // Reader mode must stay on through transceive. close() disables it.
            }
        }
        tag = iso
        job.ensureActive()
        iso.connect()
        iso.timeout = 3000
        return 2
    }

    private fun openUsb(device: UsbDevice) {
        val conn = checkNotNull(usb.openDevice(device)) { "USB key disconnected." }
        connection = conn
        for (index in 0 until device.interfaceCount) {
            val intf = device.getInterface(index)
            if (intf.interfaceClass != UsbConstants.USB_CLASS_HID) continue
            val endpoints = (0 until intf.endpointCount).map(intf::getEndpoint)
                .filter { it.type == UsbConstants.USB_ENDPOINT_XFER_INT && it.maxPacketSize == 64 }
            val incoming = endpoints.singleOrNull { it.direction == UsbConstants.USB_DIR_IN } ?: continue
            val outgoing = endpoints.singleOrNull { it.direction == UsbConstants.USB_DIR_OUT } ?: continue
            // In these two USB configurations Yubico exposes exactly one HID
            // interface, FIDO. Other interfaces, including CCID, stay attached.
            val fidoOnlyHid = device.vendorId == 0x1050 && device.productId in setOf(0x0402, 0x0406) &&
                intf.interfaceSubclass == 0 && intf.interfaceProtocol == 0 &&
                (0 until device.interfaceCount).count { device.getInterface(it).interfaceClass == UsbConstants.USB_CLASS_HID } == 1
            if (!claimFidoInterface(fidoOnlyHid, {
                val hid = ByteArray(9)
                val got = conn.controlTransfer(0x81, 6, 0x2100, intf.id, hid, hid.size, 1000)
                val declared = if (got == hid.size && hid[1] == 0x21.toByte() && hid[6] == 0x22.toByte())
                    (hid[7].toInt() and 255) or ((hid[8].toInt() and 255) shl 8) else null
                val descriptor = ByteArray(declared?.takeIf { it in 1..4096 } ?: 4096)
                val n = conn.controlTransfer(0x81, 6, 0x2200, intf.id, descriptor, descriptor.size, 1000)
                when {
                    n <= 0 -> null
                    declared != null && n != declared -> false
                    else -> isFidoInterface(descriptor, n)
                }
            }, { conn.claimInterface(intf, true) }, { conn.releaseInterface(intf) })) continue
            claimed = intf
            input = incoming
            output = outgoing
            return
        }
        error("The USB device has no supported FIDO interface.")
    }

    private fun transfer(endpoint: UsbEndpoint, buffer: ByteBuffer, abort: Boolean = false) {
        check(!detached) { "USB key disconnected." }
        if (!abort) job.ensureActive()
        val conn = checkNotNull(connection)
        val request = UsbRequest()
        try {
            check(request.initialize(conn, endpoint) && request.queue(buffer)) { "Cannot queue a security key transfer." }
            val deadline = SystemClock.elapsedRealtime() + if (abort) 250 else 30_000
            try {
                while (SystemClock.elapsedRealtime() < deadline) {
                    if (!abort) job.ensureActive()
                    val done = try { conn.requestWait(250) } catch (_: TimeoutException) { continue }
                    check(done === request && buffer.position() == 64) { "Incomplete security key transfer." }
                    return
                }
                error("Security key timed out.")
            } finally { request.cancel() }
        } finally { request.close() }
    }

    override fun write(packet: ByteArray) {
        require(packet.size == 64)
        transfer(output, ByteBuffer.wrap(packet), abort = packet[4] == 0x91.toByte())
    }
    override fun read(): ByteArray? = try {
        ByteArray(64).also { transfer(input, ByteBuffer.wrap(it)) }
    } catch (_: CancellationException) { null }
    override fun apdu(request: ByteArray): ByteArray {
        job.ensureActive()
        val iso = checkNotNull(tag)
        require(request.size <= iso.maxTransceiveLength) { "NFC command exceeds this phone's limit." }
        return iso.transceive(request)
    }

    override fun pin(): ByteArray = prompt {
        val edit = EditText(activity).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        }
        // Keep the editable in this dialog. Encode into bytes only after confirmation.
        val result = CompletableDeferred<Boolean>()
        val dialog = AlertDialog.Builder(activity).setTitle("Security key PIN").setView(edit)
            .setPositiveButton("Continue") { _, _ -> result.complete(true) }
            .setNegativeButton("Cancel") { _, _ -> result.cancel() }
            .setOnCancelListener { result.cancel() }.create()
        dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        try {
            dialog.show()
            result.await()
            val buffer = Charsets.UTF_8.encode(CharBuffer.wrap(edit.text))
            try { ByteArray(buffer.remaining()).also { buffer.get(it) } }
            finally { buffer.clear(); while (buffer.hasRemaining()) buffer.put(0) }
        } finally { edit.text.clear(); dialog.dismiss() }
    }

    // The worker owns the connection. Cancellation wakes prompts immediately
    // and the bounded I/O loop observes it before its next transfer.
    fun cancel() { job.cancel() }

    private fun releaseDevice() {
        detachReceiver?.let(activity::unregisterReceiver)
        detachReceiver = null
        val iso = tag
        tag = null
        try { iso?.close() } finally {
            claimed?.let { connection?.releaseInterface(it) }
            claimed = null
            connection?.close()
            connection = null
            if (readerEnabled) runBlocking(Dispatchers.Main.immediate) {
                NfcAdapter.getDefaultAdapter(activity)?.disableReaderMode(activity)
            }
            readerEnabled = false
        }
    }

    override fun close() {
        cancel()
        releaseDevice()
    }
    private var readerEnabled = false
}

// On some phones usbfs cannot read an interface descriptor while the HID
// driver owns it. Temporarily claim only a known FIDO-only HID function.
internal fun claimFidoInterface(knownFido: Boolean, inspect: () -> Boolean?, claim: () -> Boolean, release: () -> Unit): Boolean {
    when (inspect()) {
        true -> return claim()
        false -> return false
        null -> if (!knownFido || !claim()) return false
    }
    var valid = false
    try {
        valid = inspect() == true
        check(valid) { "Cannot verify the USB key's FIDO report descriptor." }
        return true
    } finally {
        if (!valid) release()
    }
}

internal fun isFidoInterface(bytes: ByteArray, size: Int): Boolean {
    var offset = 0
    var page = 0
    var usage = 0
    var depth = 0
    if (size !in 1..bytes.size) return false
    var found = false
    var reportSize = 0
    var reportCount = 0
    var hasInput = false
    var hasOutput = false
    while (offset < size) {
        val prefix = bytes[offset++].toInt() and 255
        if (prefix == 0xfe) return false
        val length = when (val n = prefix and 3) { 3 -> 4; else -> n }
        if (offset + length > size) return false
        var value = 0
        repeat(length) { value = value or ((bytes[offset++].toInt() and 255) shl (8 * it)) }
        when (prefix and 0xfc) {
            0x04 -> page = value
            0x08 -> usage = if (length == 4) value else (page shl 16) or value
            0x74 -> reportSize = value
            0x94 -> reportCount = value
            0x84, 0xa4, 0xb4 -> return false // Report IDs and global push/pop are unsupported.
            0x80, 0x90 -> {
                val incoming = prefix and 0xfc == 0x80
                val expectedUsage = if (incoming) 0xf1d00020.toInt() else 0xf1d00021.toInt()
                if (depth == 0 || usage != expectedUsage || reportSize != 8 || reportCount != 64 ||
                    value and 3 != 2 || (if (incoming) hasInput else hasOutput)) return false
                if (incoming) hasInput = true else hasOutput = true
            }
            0xa0 -> {
                if (depth == 0) {
                    if (found || value != 1 || usage != 0xf1d00001.toInt()) return false
                    found = true
                }
                depth++
            }
            0xc0 -> if (--depth < 0) return false
        }
        if (prefix and 0x0c == 0) usage = 0
    }
    return found && hasInput && hasOutput && depth == 0
}
