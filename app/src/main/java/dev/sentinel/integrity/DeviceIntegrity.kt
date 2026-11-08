package dev.sentinel.integrity

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.LocalDate
import java.time.temporal.ChronoUnit

enum class Status { OK, WARN, BAD, INFO }

data class Check(val title: String, val status: Status, val detail: String)

data class Attestation(
    val securityLevel: Int,        // 0 software, 1 TEE, 2 StrongBox
    val bootState: Int?,           // 0 verified, 1 self-signed, 2 unverified, 3 failed
    val deviceLocked: Boolean?,    // bootloader locked?
    val osPatchLevel: Int?,        // YYYYMM, as attested by hardware
    val chainConsistent: Boolean,
    val rootFingerprint: String,
)

private class Tlv(val cls: Int, val tag: Int, val start: Int, val end: Int)

/** Minimal DER reader, just enough for the Android Key Attestation extension. */
private object Der {
    fun read(b: ByteArray, pos: Int): Tlv {
        var p = pos
        val first = b[p++].toInt() and 0xff
        val cls = first and 0xC0
        var tag = first and 0x1f
        if (tag == 0x1f) {
            tag = 0
            while (true) {
                val x = b[p++].toInt() and 0xff
                tag = (tag shl 7) or (x and 0x7f)
                if (x and 0x80 == 0) break
            }
        }
        var len = b[p++].toInt() and 0xff
        if (len and 0x80 != 0) {
            val n = len and 0x7f
            len = 0
            repeat(n) { len = (len shl 8) or (b[p++].toInt() and 0xff) }
        }
        return Tlv(cls, tag, p, p + len)
    }

    fun children(b: ByteArray, parent: Tlv): List<Tlv> {
        val out = ArrayList<Tlv>()
        var p = parent.start
        while (p < parent.end) {
            val t = read(b, p)
            out.add(t)
            p = t.end
        }
        return out
    }

    fun int(b: ByteArray, t: Tlv): Int {
        var v = 0
        for (i in t.start until t.end) v = (v shl 8) or (b[i].toInt() and 0xff)
        return v
    }
}

/**
 * Reads what the phone's secure hardware (TEE / StrongBox) says about the device itself,
 * plus classic OS-hardening and tamper signals. Everything runs on-device.
 */
class DeviceIntegrity(private val ctx: Context) {

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun attest(): Attestation? {
        val alias = "sentinel_attest_tmp"
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun generate(strongBox: Boolean) {
            val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
            if (strongBox) b.setIsStrongBoxBacked(true)
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            kpg.initialize(b.build())
            kpg.generateKeyPair()
        }

        try { generate(true) } catch (e: StrongBoxUnavailableException) { generate(false) }

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            val chain = ks.getCertificateChain(alias)?.map { it as X509Certificate } ?: return null
            val ext = chain.first().getExtensionValue("1.3.6.1.4.1.11129.2.1.17") ?: return null

            val outer = Der.read(ext, 0)                  // OCTET STRING wrapper
            val seq = Der.read(ext, outer.start)          // KeyDescription SEQUENCE
            val kids = Der.children(ext, seq)
            if (kids.size < 8) return null
            val level = Der.int(ext, kids[1])

            var boot: Int? = null
            var locked: Boolean? = null
            var patch: Int? = null
            for (item in Der.children(ext, kids[7])) {    // teeEnforced AuthorizationList
                if (item.cls != 0x80) continue
                val inner = Der.read(ext, item.start)     // explicit tag wraps one element
                when (item.tag) {
                    704 -> {                              // RootOfTrust
                        val k = Der.children(ext, inner)
                        locked = ext[k[1].start].toInt() != 0
                        boot = Der.int(ext, k[2])
                    }
                    706 -> patch = Der.int(ext, inner)    // osPatchLevel
                }
            }

            val consistent = (0 until chain.size - 1).all {
                runCatching { chain[it].verify(chain[it + 1].publicKey) }.isSuccess
            }
            val rootFp = hex(MessageDigest.getInstance("SHA-256").digest(chain.last().encoded))
            return Attestation(level, boot, locked, patch, consistent, rootFp)
        } finally {
            runCatching { ks.deleteEntry(alias) }
        }
    }

    fun run(): List<Check> {
        val out = mutableListOf<Check>()
        val cr = ctx.contentResolver

        // --- Hardware root of trust ---
        val att = runCatching { attest() }.getOrNull()
        if (att == null) {
            out += Check("Hardware attestation", Status.WARN, "Couldn't get a hardware-backed attestation on this device.")
        } else {
            out += Check(
                "Key storage hardware",
                if (att.securityLevel >= 1) Status.OK else Status.BAD,
                when (att.securityLevel) {
                    2 -> "StrongBox: a dedicated tamper-resistant security chip."
                    1 -> "Trusted Execution Environment (hardware-isolated)."
                    else -> "Software only: keys are NOT protected by hardware."
                },
            )
            out += when (att.bootState) {
                0 -> Check("Verified boot", Status.OK, "The OS image is verified against the device maker's key.")
                1 -> Check("Verified boot", Status.WARN, "Self-signed OS (custom ROM or user-installed key). Only as trustworthy as whoever signed it.")
                2 -> Check("Verified boot", Status.BAD, "OS is NOT verified. The system partition could be modified.")
                3 -> Check("Verified boot", Status.BAD, "Verification FAILED. The OS has been tampered with or corrupted.")
                else -> Check("Verified boot", Status.INFO, "Boot state not reported.")
            }
            att.deviceLocked?.let {
                out += if (it) Check("Bootloader", Status.OK, "Locked.")
                else Check("Bootloader", Status.BAD, "UNLOCKED. Anyone with physical access can flash software or extract data.")
            }
            out += if (att.chainConsistent)
                Check("Attestation chain", Status.INFO,
                    "Internally consistent. Root fingerprint ${att.rootFingerprint.take(24)}… Compare it with Google's published attestation roots. This check does not pin the root, so a fully compromised OS could forge it.")
            else Check("Attestation chain", Status.BAD, "Certificate chain is inconsistent. Treat the results above as untrustworthy.")
        }

        // --- Patch level ---
        val patchStr = Build.VERSION.SECURITY_PATCH
        val patchDate = runCatching { LocalDate.parse(patchStr) }.getOrNull()
        if (patchDate != null) {
            val age = ChronoUnit.DAYS.between(patchDate, LocalDate.now())
            out += Check(
                "Security patch ($patchStr)",
                when { age <= 90 -> Status.OK; age <= 180 -> Status.WARN; else -> Status.BAD },
                "$age days old. Old patches leave publicly known kernel and system bugs open.",
            )
            val claimed = patchDate.year * 100 + patchDate.monthValue
            if (att?.osPatchLevel != null && claimed > att.osPatchLevel)
                out += Check("Patch level consistency", Status.WARN, "The system reports a newer patch date than the hardware attested (${att.osPatchLevel}). Possible spoofing, or an OEM quirk.")
        }

        // --- Lock & encryption ---
        val km = ctx.getSystemService(KeyguardManager::class.java)
        out += if (km.isDeviceSecure) Check("Screen lock", Status.OK, "PIN, pattern or password is set.")
        else Check("Screen lock", Status.BAD, "No secure lock. Anyone holding the phone has everything.")

        val dpm = ctx.getSystemService(DevicePolicyManager::class.java)
        val enc = dpm.storageEncryptionStatus
        out += if (enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
            enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER ||
            enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY
        ) Check("Storage encryption", Status.OK, "Active.")
        else Check("Storage encryption", Status.BAD, "Not active.")

        // --- Attack surface ---
        val dev = Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        val adb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
        val wadb = Settings.Global.getInt(cr, "adb_wifi_enabled", 0) == 1
        out += when {
            adb || wadb -> Check("Debugging (ADB)", Status.BAD, "${if (wadb) "Wireless" else "USB"} debugging is ON. Turn it off unless you're developing.")
            dev -> Check("Developer options", Status.WARN, "Enabled. Debugging itself is off.")
            else -> Check("Debugging (ADB)", Status.OK, "Off.")
        }

        // --- Tamper / root signals (heuristics) ---
        val pm = ctx.packageManager
        val suFound = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su", "/system/sbin/su", "/su/bin/su")
            .filter { File(it).exists() }
        val rootPkgs = listOf("com.topjohnwu.magisk", "me.weishu.kernelsu", "eu.chainfire.supersu", "com.noshufou.android.su", "com.koushikdutta.superuser")
            .filter { runCatching { pm.getPackageInfo(it, PackageManager.PackageInfoFlags.of(0)) }.isSuccess }
        val testKeys = Build.TAGS?.contains("test-keys") == true
        out += if (suFound.isNotEmpty() || rootPkgs.isNotEmpty() || testKeys)
            Check("Root / tamper signs", Status.BAD,
                listOfNotNull(
                    suFound.takeIf { it.isNotEmpty() }?.let { "su binary: ${it.first()}" },
                    rootPkgs.takeIf { it.isNotEmpty() }?.let { "root manager app: ${it.first()}" },
                    if (testKeys) "build signed with public test keys" else null,
                ).joinToString("; "))
        else Check("Root / tamper signs", Status.INFO, "None found. Root hiding tools can defeat this, so rely on Verified boot above.")

        val se = runCatching { File("/sys/fs/selinux/enforce").readText().trim() }.getOrNull()
        out += when (se) {
            "1" -> Check("SELinux", Status.OK, "Enforcing: the kernel's mandatory access control is active.")
            "0" -> Check("SELinux", Status.BAD, "PERMISSIVE: kernel-level app isolation is switched off.")
            else -> Check("SELinux", Status.INFO, "Android doesn't let apps read this on your device.")
        }

        return out
    }
}
