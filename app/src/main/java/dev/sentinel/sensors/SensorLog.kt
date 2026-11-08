package dev.sentinel.sensors

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Small private, on-device event history for camera/mic activity. */
object SensorLog {
    val events = mutableStateListOf<String>()
    var running by mutableStateOf(false)
    private var loaded = false
    private const val PREFS = "sensors"

    fun init(ctx: Context) {
        if (loaded) return
        loaded = true
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("log", "").orEmpty()
            .split("\n").filter { it.isNotBlank() }.forEach { events.add(it) }
    }

    fun add(ctx: Context, line: String) {
        init(ctx)
        val t = SimpleDateFormat("MMM d HH:mm:ss", Locale.getDefault()).format(Date())
        events.add(0, "$t  ${line.replace('\n', ' ')}")
        while (events.size > 60) events.removeAt(events.size - 1)
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("log", events.joinToString("\n")).apply()
    }
}
