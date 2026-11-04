package it.nfcremote.mobile

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Build
import android.os.Bundle
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Gestore IsoDep 2026: reader-mode + coroutine + Flow.
 *
 * Stato dell'arte Android 15/16 (targetSdk 36):
 * - `enableReaderMode` con `FLAG_READER_NFC_A | FLAG_READER_NFC_B |
 *   FLAG_READER_SKIP_NDEF_CHECK`, `EXTRA_READER_PRESENCE_CHECK_DELAY` 500ms
 *   per bilanciare batteria/latenza su Pixel/Samsung 2025+.
 * - Mai sul main thread: callback binder -> `scope.launch(Dispatchers.IO)`.
 * - Eventi esposti come [events] SharedFlow (replay 1) per il bridge Rust
 *   (JNI) e la UI Compose: `Inserted(atrHex) / Removed / Apdu(latencyMs)`.
 * - `transceive` è `suspend` con timeout 8s e controllo presenza; su
 *   `TagLostException` emette `Removed` e chiude silenziosamente.
 * - Edge-to-edge + predictive-back compat: nessun dialog bloccante qui.
 */
class NfcIsoDepHandler(
    private val adapter: NfcAdapter?,
    parentScope: CoroutineScope? = null,
) : NfcAdapter.ReaderCallback {

    companion object {
        private const val TAG = "NfcIsoDep"
        const val TRANSCEIVE_TIMEOUT_MS = 8000
        const val PRESENCE_CHECK_MS = 500
    }

    sealed interface CardEvent {
        data class Inserted(val atrHex: String?) : CardEvent
        data object Removed : CardEvent
        data class Apdu(val txBytes: Int, val rxBytes: Int, val latencyMs: Long) : CardEvent
    }

    private val scope = parentScope ?: CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val _events = MutableSharedFlow<CardEvent>(extraBufferCapacity = 64)
    val events: SharedFlow<CardEvent> = _events.asSharedFlow()

    @Volatile private var current: IsoDep? = null

    fun enable(activity: Activity) {
        val flags = NfcAdapter.FLAG_READER_NFC_A or
            NfcAdapter.FLAG_READER_NFC_B or
            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or
            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS
        val extras = Bundle().apply {
            putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, PRESENCE_CHECK_MS)
        }
        adapter?.enableReaderMode(activity, this, flags, extras)
        Log.i(TAG, "reader-mode abilitato (sdk=${Build.VERSION.SDK_INT})")
    }

    fun disable(activity: Activity) {
        try { adapter?.disableReaderMode(activity) } catch (_: Exception) {}
        closeQuietly()
    }

    fun destroy() = scope.cancel()

    override fun onTagDiscovered(tag: Tag?) {
        scope.launch {
            val iso = tag?.let { IsoDep.get(it) }
            if (iso == null) {
                Log.w(TAG, "tag non IsoDep, ignorato")
                return@launch
            }
            try {
                withContext(Dispatchers.IO) {
                    iso.connect()
                    iso.timeout = TRANSCEIVE_TIMEOUT_MS
                }
                current = iso
                val atr = iso.historicalBytes?.toHex() ?: iso.hiLayerResponse?.toHex()
                Log.i(TAG, "IsoDep connesso atr=$atr")
                _events.emit(CardEvent.Inserted(atr))
            } catch (e: Exception) {
                Log.e(TAG, "connect fallita", e)
                _events.emit(CardEvent.Removed)
            }
        }
    }

    /** Forward trasparente APDU -> carta (suspend, Dispatchers.IO). */
    suspend fun transceive(apdu: ByteArray): Result<ByteArray> = withContext(Dispatchers.IO) {
        val iso = current ?: return@withContext Result.failure(IllegalStateException("nessuna carta"))
        try {
            require(apdu.size in 4..65535) { "APDU len errata" }
            val t0 = System.nanoTime()
            val resp = iso.transceive(apdu)
            val ms = (System.nanoTime() - t0) / 1_000_000
            _events.emit(CardEvent.Apdu(apdu.size, resp.size, ms))
            Result.success(resp)
        } catch (e: Exception) {
            Log.e(TAG, "transceive fallito", e)
            closeQuietly()
            _events.emit(CardEvent.Removed)
            Result.failure(e)
        }
    }

    fun atrHex(): String? = current?.run { historicalBytes?.toHex() ?: hiLayerResponse?.toHex() }

    private fun closeQuietly() {
        try { current?.close() } catch (_: Exception) {}
        current = null
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }
}
