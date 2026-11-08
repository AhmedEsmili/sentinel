package dev.sentinel.audit

import android.Manifest.permission as P
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.app.usage.UsageStatsManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Process
import android.provider.Settings

enum class Risk { HIGH, MEDIUM, LOW }

data class AppRisk(
    val label: String,
    val pkg: String,
    val score: Int,           // 0..10
    val reasons: List<String>,
) {
    val risk get() = when { score >= 8 -> Risk.HIGH; score >= 4 -> Risk.MEDIUM; else -> Risk.LOW }
}

/** Audits user-installed apps. Read-only: Android does not let one app revoke another's permissions. */
class PermissionAuditor(private val ctx: Context) {

    private val dayMs = 24L * 60 * 60 * 1000

    private val weights = mapOf(
        P.ACCESS_BACKGROUND_LOCATION to (4 to "Tracks your location even when closed"),
        P.READ_SMS to (4 to "Can read your text messages (incl. login codes)"),
        P.RECEIVE_SMS to (3 to "Can intercept incoming texts"),
        P.RECORD_AUDIO to (3 to "Can use the microphone"),
        P.READ_CALL_LOG to (3 to "Can read your call history"),
        P.READ_CONTACTS to (2 to "Can read your contacts"),
        P.CAMERA to (2 to "Can use the camera"),
        P.ACCESS_FINE_LOCATION to (2 to "Knows your precise location"),
        P.READ_PHONE_STATE to (1 to "Can read phone identity/state"),
        P.MANAGE_EXTERNAL_STORAGE to (3 to "Can access all files on the device"),
    )

    private val trustedStores = setOf(
        "com.android.vending", "com.sec.android.app.samsungapps", "com.amazon.venezia", "org.fdroid.fdroid",
    )

    fun hasUsageAccess(): Boolean {
        val ops = ctx.getSystemService(AppOpsManager::class.java)
        return ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName) ==
            AppOpsManager.MODE_ALLOWED
    }

    private fun lastUsedMap(): Map<String, Long>? {
        if (!hasUsageAccess()) return null
        val usm = ctx.getSystemService(UsageStatsManager::class.java)
        val now = System.currentTimeMillis()
        return usm.queryAndAggregateUsageStats(now - 365 * dayMs, now).mapValues { it.value.lastTimeUsed }
    }

    private fun enabledPackages(settingKey: String): Set<String> =
        Settings.Secure.getString(ctx.contentResolver, settingKey).orEmpty()
            .split(':').mapNotNull { ComponentName.unflattenFromString(it)?.packageName }.toSet()

    fun audit(): List<AppRisk> {
        val pm = ctx.packageManager
        val a11y = enabledPackages(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        val listeners = enabledPackages("enabled_notification_listeners")
        val admins = ctx.getSystemService(DevicePolicyManager::class.java).activeAdmins
            ?.map { it.packageName }?.toSet().orEmpty()
        val lastUsed = lastUsedMap()
        val now = System.currentTimeMillis()

        val flags = PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
        return pm.getInstalledPackages(flags).mapNotNull { info ->
            val ai = info.applicationInfo ?: return@mapNotNull null
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0 || info.packageName == ctx.packageName) return@mapNotNull null

            var points = 0
            val reasons = mutableListOf<String>()
            fun add(p: Int, msg: String) { points += p; reasons += msg }

            val granted = grantedPermissions(info)
            for ((perm, w) in weights) if (perm in granted) add(w.first, w.second)
            if (P.RECORD_AUDIO in granted && P.ACCESS_FINE_LOCATION in granted && P.READ_CONTACTS in granted)
                add(3, "Combo: can listen, locate you and see your contacts")

            if (info.packageName in a11y) add(6, "Accessibility service ON – can read and control your screen")
            if (info.packageName in listeners) add(4, "Can read all your notifications (incl. 2FA codes)")
            if (info.packageName in admins) add(4, "Device-admin app – hard to remove, can lock/wipe")

            val installer = runCatching { pm.getInstallSourceInfo(info.packageName).installingPackageName }.getOrNull()
            if (installer !in trustedStores) add(2, "Installed outside a major app store")

            if (lastUsed != null && points >= 3) {
                val t = lastUsed[info.packageName] ?: 0L
                val days = if (t <= 0) 365 else ((now - t) / dayMs).toInt()
                if (days >= 90) add(3, "Not opened in ${if (t <= 0) "1+ year" else "$days days"} but still holds sensitive access")
            }

            if (points == 0) null
            else AppRisk(ai.loadLabel(pm).toString(), info.packageName, minOf(10, points), reasons)
        }.sortedByDescending { it.score }
    }

    private fun grantedPermissions(info: PackageInfo): Set<String> {
        val perms = info.requestedPermissions ?: return emptySet()
        val fl = info.requestedPermissionsFlags ?: return emptySet()
        return perms.filterIndexed { i, _ ->
            (fl.getOrNull(i) ?: 0) and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
        }.toSet()
    }
}
