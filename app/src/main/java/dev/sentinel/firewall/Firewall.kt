package dev.sentinel.firewall

import android.content.Context
import android.content.Intent

/** Per-app internet blocking. State lives in private prefs; the VpnService enforces it. */
object Firewall {
    private const val PREFS = "firewall"
    private const val KEY = "blocked"

    fun blocked(ctx: Context): Set<String> =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getStringSet(KEY, emptySet())?.toSet() ?: emptySet()

    fun set(ctx: Context, pkg: String, block: Boolean) {
        val next = if (block) blocked(ctx) + pkg else blocked(ctx) - pkg
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putStringSet(KEY, HashSet(next)).apply()
    }

    /** (Re)builds the tunnel from the saved list. Stops itself if the list is empty. */
    fun apply(ctx: Context) {
        ctx.startService(Intent(ctx, FirewallService::class.java))
    }
}
