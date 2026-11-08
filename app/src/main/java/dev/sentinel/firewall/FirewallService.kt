package dev.sentinel.firewall

import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.IOException

/**
 * A "black-hole" VPN: ONLY the blocked apps are routed into the tunnel, and every packet is read
 * and discarded, so those apps have no connectivity. Nothing is forwarded, so Sentinel needs no
 * INTERNET permission and never sees where your traffic was going. Other apps are untouched.
 */
class FirewallService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        rebuild()
        return START_STICKY
    }

    private fun rebuild() {
        teardown()
        val blocked = Firewall.blocked(this)
        if (blocked.isEmpty()) { stopSelf(); return }

        val builder = Builder()
            .setSession("Sentinel Firewall")
            .addAddress("10.255.255.2", 32)
            .addAddress("fd00:255::2", 128)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .setBlocking(true)

        var any = false
        for (pkg in blocked) {
            try { builder.addAllowedApplication(pkg); any = true } catch (_: PackageManager.NameNotFoundException) { }
        }
        // With zero allowed apps Android would route EVERYONE into the tunnel. Never do that.
        if (!any) { stopSelf(); return }

        val fd = builder.establish()
        if (fd == null) { stopSelf(); return }   // VPN consent was revoked
        tun = fd
        reader = Thread {
            val input = FileInputStream(fd.fileDescriptor)
            val buf = ByteArray(32767)
            try { while (input.read(buf) >= 0) { /* drop */ } } catch (_: IOException) { }
        }.apply { isDaemon = true; start() }
    }

    private fun teardown() {
        reader?.interrupt(); reader = null
        runCatching { tun?.close() }; tun = null
    }

    override fun onRevoke() { teardown(); stopSelf() }
    override fun onDestroy() { teardown(); super.onDestroy() }
}
