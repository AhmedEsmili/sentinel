package dev.sentinel.sensors

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.hardware.camera2.CameraManager
import android.media.AudioManager
import android.media.AudioRecordingConfiguration
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import androidx.core.content.ContextCompat
import dev.sentinel.MainActivity
import dev.sentinel.audit.PermissionAuditor

/**
 * Watches the DEVICE-LEVEL camera and microphone state, not individual apps.
 * It fires when anything opens the camera or starts recording audio (user apps, hidden apps,
 * system services), because these are OS signals that need no permission to observe.
 * Android hides WHICH app it is from normal apps, so we attribute best-effort via the
 * foreground app (needs Usage access) and raise a high-priority alert if it happens
 * while the screen is off.
 */
class SensorWatchService : Service() {
    private enum class Sensor { CAMERA, MIC }

    private var camActive = false
    private var micActive = false
    private var registered = false
    private val busyCameras = mutableSetOf<String>()

    private val camCb = object : CameraManager.AvailabilityCallback() {
        override fun onCameraUnavailable(cameraId: String) { busyCameras.add(cameraId); update(Sensor.CAMERA, true) }
        override fun onCameraAvailable(cameraId: String) { busyCameras.remove(cameraId); if (busyCameras.isEmpty()) update(Sensor.CAMERA, false) }
    }

    private val micCb = object : AudioManager.AudioRecordingCallback() {
        override fun onRecordingConfigChanged(configs: MutableList<AudioRecordingConfiguration>?) {
            update(Sensor.MIC, !configs.isNullOrEmpty())
        }
    }

    override fun onCreate() {
        super.onCreate()
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH_MON, "Monitoring", NotificationManager.IMPORTANCE_LOW))
        nm.createNotificationChannel(NotificationChannel(CH_ALERT, "Sensor alerts", NotificationManager.IMPORTANCE_HIGH))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            val n = Notification.Builder(this, CH_MON)
                .setSmallIcon(android.R.drawable.ic_menu_view)
                .setContentTitle("Sentinel is watching camera & mic")
                .setContentText("Tap to open")
                .setContentIntent(open)
                .setOngoing(true)
                .build()
            // The specialUse service type only exists on Android 14+. On 13 it must be omitted.
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(1, n)
            }
            if (!registered) {
                getSystemService(CameraManager::class.java).registerAvailabilityCallback(ContextCompat.getMainExecutor(this), camCb)
                getSystemService(AudioManager::class.java).registerAudioRecordingCallback(micCb, Handler(Looper.getMainLooper()))
                registered = true
                SensorLog.add(this, "Monitoring started")
            }
            SensorLog.running = true
            return START_STICKY
        } catch (e: Exception) {
            SensorLog.running = false
            SensorLog.add(this, "Error: ${e.javaClass.simpleName}: ${e.message}")
            stopSelf()
            return START_NOT_STICKY
        }
    }

    private fun update(sensor: Sensor, on: Boolean) {
        val was = if (sensor == Sensor.CAMERA) camActive else micActive
        if (sensor == Sensor.CAMERA) camActive = on else micActive = on
        if (on == was) return
        val name = if (sensor == Sensor.CAMERA) "Camera" else "Microphone"
        if (!on) { SensorLog.add(this, "$name released"); return }

        val screenOn = getSystemService(PowerManager::class.java).isInteractive
        val fg = foregroundPackage()
        val who = fg?.let { label(it) } ?: "unknown"
        if (!screenOn) {
            SensorLog.add(this, "⚠ $name ACTIVE while screen OFF")
            alert("$name in use while your screen is off",
                "Something is using your $name while the phone looks idle. Open Android's Privacy dashboard to see which app, and review recent installs.")
        } else {
            SensorLog.add(this, "$name in use · foreground app: $who")
        }
    }

    private fun foregroundPackage(): String? {
        if (!PermissionAuditor(this).hasUsageAccess()) return null
        return runCatching {
            val usm = getSystemService(UsageStatsManager::class.java)
            val now = System.currentTimeMillis()
            val events = usm.queryEvents(now - 10 * 60_000L, now)
            val e = UsageEvents.Event()
            var last: String? = null
            while (events.hasNextEvent()) {
                events.getNextEvent(e)
                if (e.eventType == UsageEvents.Event.ACTIVITY_RESUMED) last = e.packageName
                else if (e.eventType == UsageEvents.Event.ACTIVITY_PAUSED && e.packageName == last) last = null
            }
            last
        }.getOrNull()
    }

    private fun label(pkg: String): String = runCatching {
        packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))).toString()
    }.getOrDefault(pkg)

    private fun alert(title: String, text: String) {
        val n = Notification.Builder(this, CH_ALERT)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(System.currentTimeMillis().toInt(), n)
    }

    override fun onDestroy() {
        if (registered) {
            runCatching { getSystemService(CameraManager::class.java).unregisterAvailabilityCallback(camCb) }
            runCatching { getSystemService(AudioManager::class.java).unregisterAudioRecordingCallback(micCb) }
            registered = false
            SensorLog.add(this, "Monitoring stopped")
        }
        SensorLog.running = false
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private companion object {
        const val CH_MON = "sentinel_monitor"
        const val CH_ALERT = "sentinel_alerts"
    }
}
