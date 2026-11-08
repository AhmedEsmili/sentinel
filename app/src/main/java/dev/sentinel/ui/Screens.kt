package dev.sentinel.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import dev.sentinel.firewall.Firewall
import dev.sentinel.sensors.SensorLog
import dev.sentinel.sensors.SensorWatchService
import androidx.core.content.ContextCompat
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import dev.sentinel.audit.AppRisk
import dev.sentinel.audit.PermissionAuditor
import dev.sentinel.audit.Risk
import dev.sentinel.integrity.Check
import dev.sentinel.integrity.DeviceIntegrity
import dev.sentinel.integrity.Status
import dev.sentinel.scam.Level
import dev.sentinel.scam.ScamAnalyzer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SentinelApp(sharedText: String?) {
    var tab by remember(sharedText) { mutableIntStateOf(if (sharedText != null) 1 else 0) }
    Scaffold(
        topBar = { TopAppBar(title = { Text("Sentinel") }) },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(tab == 0, { tab = 0 }, icon = { Text("🔐") }, label = { Text("Permissions") })
                NavigationBarItem(tab == 1, { tab = 1 }, icon = { Text("🎣") }, label = { Text("Scam check") })
                NavigationBarItem(tab == 2, { tab = 2 }, icon = { Text("🛡") }, label = { Text("Device") })
                NavigationBarItem(tab == 3, { tab = 3 }, icon = { Text("🎙") }, label = { Text("Sensors") })
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            when (tab) { 0 -> PermissionsScreen(); 1 -> ScamScreen(sharedText); 2 -> DeviceScreen(); else -> SensorScreen() }
        }
    }
}

@Composable
fun LockScreen(onUnlock: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(32.dp), verticalArrangement = Arrangement.Center) {
        Text("Sentinel is locked", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))
        Button(onClick = onUnlock) { Text("Unlock") }
    }
}

@Composable
private fun PermissionsScreen() {
    val ctx = LocalContext.current
    var apps by remember { mutableStateOf<List<AppRisk>?>(null) }
    var usageOk by remember { mutableStateOf(true) }
    var tick by remember { mutableIntStateOf(0) }
    var blocked by remember { mutableStateOf(Firewall.blocked(ctx)) }
    var pendingPkg by remember { mutableStateOf<String?>(null) }
    var queueOn by remember { mutableStateOf(false) }
    var skipped by remember { mutableStateOf(setOf<String>()) }

    // One-time Android consent dialog for the local VPN the firewall uses.
    val vpnLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        val pkg = pendingPkg
        if (r.resultCode == Activity.RESULT_OK && pkg != null) {
            Firewall.set(ctx, pkg, true); blocked = Firewall.blocked(ctx); Firewall.apply(ctx)
        }
        pendingPkg = null
    }
    LifecycleResumeEffect(Unit) { tick++; onPauseOrDispose { } }
    LaunchedEffect(tick) {
        val auditor = PermissionAuditor(ctx)
        usageOk = auditor.hasUsageAccess()
        apps = withContext(Dispatchers.Default) { auditor.audit() }
    }

    fun toggle(pkg: String) {
        if (pkg in blocked) {
            Firewall.set(ctx, pkg, false)
        } else {
            val consent = VpnService.prepare(ctx)
            if (consent != null) { pendingPkg = pkg; vpnLauncher.launch(consent); return }
            Firewall.set(ctx, pkg, true)
        }
        blocked = Firewall.blocked(ctx); Firewall.apply(ctx)
    }

    val list = apps
    if (list == null) { Box(Modifier.fillMaxSize()) { CircularProgressIndicator(Modifier.padding(32.dp)) }; return }

    val queue = list.filter { it.score >= 4 && it.pkg !in skipped }
    if (queueOn) {
        val cur = queue.firstOrNull()
        FixQueue(
            app = cur, remaining = queue.size, isBlocked = cur != null && cur.pkg in blocked,
            onToggle = { cur?.let { toggle(it.pkg) } },
            onSkip = { cur?.let { skipped = skipped + it.pkg } },
            onExit = { queueOn = false; skipped = emptySet() },
        )
        return
    }

    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            val top = list.firstOrNull()
            ElevatedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Top fix", style = MaterialTheme.typography.labelLarge)
                    Text(
                        if (top == null) "No risky apps found 🎉" else "${top.label}: ${top.reasons.first()}",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    if (queue.isNotEmpty()) Button({ queueOn = true }) { Text("Start Fix Queue (${queue.size} apps)") }
                    if (blocked.isNotEmpty()) Text("🔥 ${blocked.size} app(s) blocked from the internet", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        if (!usageOk) item {
            OutlinedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Optional: allow Usage access so Sentinel can flag apps you haven't opened in months. Data stays on this device.")
                    TextButton({ ctx.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) }) { Text("Open settings") }
                }
            }
        }
        items(list, key = { it.pkg }) { app ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("${app.label}  ·  ${app.risk.name} (${app.score}/10)", style = MaterialTheme.typography.titleSmall,
                        color = when (app.risk) { Risk.HIGH -> MaterialTheme.colorScheme.error; Risk.MEDIUM -> MaterialTheme.colorScheme.tertiary; else -> MaterialTheme.colorScheme.onSurface })
                    app.reasons.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                    Row {
                        TextButton({
                            runCatching { ctx.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${app.pkg}"))) }
                        }) { Text("Permissions") }
                        TextButton({ toggle(app.pkg) }) { Text(if (app.pkg in blocked) "Unblock net" else "Block net") }
                        TextButton({
                            runCatching { ctx.startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:${app.pkg}"))) }
                        }) { Text("Uninstall") }
                    }
                }
            }
        }
    }
}

@Composable
private fun FixQueue(
    app: AppRisk?, remaining: Int, isBlocked: Boolean,
    onToggle: () -> Unit, onSkip: () -> Unit, onExit: () -> Unit,
) {
    val ctx = LocalContext.current
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (app == null) {
            Text("Queue finished 🎉", style = MaterialTheme.typography.headlineSmall)
            Button(onExit) { Text("Done") }
            return@Column
        }
        Text("Fix Queue · $remaining left", style = MaterialTheme.typography.labelLarge)
        ElevatedCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(app.label, style = MaterialTheme.typography.titleLarge)
                app.reasons.forEach { Text("• $it", style = MaterialTheme.typography.bodyMedium) }
            }
        }
        Button({
            runCatching { ctx.startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:${app.pkg}"))) }
        }, Modifier.fillMaxWidth()) { Text("Uninstall") }
        OutlinedButton(onToggle, Modifier.fillMaxWidth()) { Text(if (isBlocked) "Unblock its internet" else "Block its internet (keep the app)") }
        OutlinedButton({
            runCatching { ctx.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${app.pkg}"))) }
        }, Modifier.fillMaxWidth()) { Text("Review permissions") }
        TextButton(onSkip) { Text("Keep it, next app") }
        TextButton(onExit) { Text("Exit queue") }
    }
}

private fun fixIntent(c: Check): Intent? = when {
    c.title.startsWith("Debugging") || c.title.startsWith("Developer") -> Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
    c.title.startsWith("Screen lock") || c.title.startsWith("Storage") -> Intent(Settings.ACTION_SECURITY_SETTINGS)
    c.title.startsWith("Security patch") -> Intent("android.settings.SYSTEM_UPDATE_SETTINGS")
    else -> null
}

@Composable
private fun ScamScreen(initial: String?) {
    var text by remember(initial) { mutableStateOf(initial.orEmpty()) }
    val clipboard = LocalClipboardManager.current
    val result = remember(text) { ScamAnalyzer.analyze(text) }

    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            OutlinedTextField(
                value = text, onValueChange = { text = it },
                label = { Text("Paste a suspicious message or link") },
                modifier = Modifier.fillMaxWidth().heightIn(min = 140.dp),
            )
            Row {
                TextButton({ clipboard.getText()?.text?.let { text = it } }) { Text("Paste") }
                TextButton({ text = "" }) { Text("Clear") }
            }
            Text("Tip: use Share → Sentinel in any messaging app.", style = MaterialTheme.typography.bodySmall)
        }
        if (text.isNotBlank()) {
            item {
                val (title, color) = when (result.level) {
                    Level.LIKELY_SCAM -> "Likely a scam (${result.score}/100)" to MaterialTheme.colorScheme.error
                    Level.SUSPICIOUS -> "Suspicious (${result.score}/100)" to MaterialTheme.colorScheme.tertiary
                    Level.NO_FLAGS -> "No red flags found" to MaterialTheme.colorScheme.primary
                }
                ElevatedCard(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp)) {
                        Text(title, style = MaterialTheme.typography.titleLarge, color = color)
                        if (result.level == Level.NO_FLAGS)
                            Text("That doesn't guarantee it's safe. If it asks for money, codes or urgent action, verify via the company's official app or number.", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            items(result.findings) { f ->
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp)) {
                        Text(f.title, style = MaterialTheme.typography.titleSmall)
                        Text(f.why, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun DeviceScreen() {
    val ctx = LocalContext.current
    var checks by remember { mutableStateOf<List<Check>?>(null) }
    LaunchedEffect(Unit) { checks = withContext(Dispatchers.Default) { DeviceIntegrity(ctx).run() } }

    val list = checks
    if (list == null) { Box(Modifier.fillMaxSize()) { CircularProgressIndicator(Modifier.padding(32.dp)) }; return }

    val bad = list.count { it.status == Status.BAD }
    val warn = list.count { it.status == Status.WARN }
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            ElevatedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text(
                        if (bad == 0 && warn == 0) "Device looks healthy" else "$bad critical, $warn warnings",
                        style = MaterialTheme.typography.titleLarge,
                        color = if (bad > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                    )
                    Text("Checks hardware-attested boot state, patch level, lock, encryption and tamper signs. All on-device.", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        items(list.sortedBy { it.status.ordinal.let { o -> if (o == Status.INFO.ordinal) 9 else 3 - o } }) { c ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    val (mark, color) = when (c.status) {
                        Status.OK -> "✓" to MaterialTheme.colorScheme.primary
                        Status.WARN -> "⚠" to MaterialTheme.colorScheme.tertiary
                        Status.BAD -> "✕" to MaterialTheme.colorScheme.error
                        Status.INFO -> "ⓘ" to MaterialTheme.colorScheme.onSurfaceVariant
                    }
                    Text("$mark  ${c.title}", style = MaterialTheme.typography.titleSmall, color = color)
                    Text(c.detail, style = MaterialTheme.typography.bodySmall)
                    if (c.status == Status.BAD || c.status == Status.WARN) fixIntent(c)?.let { i ->
                        TextButton({ runCatching { ctx.startActivity(i) } }) { Text("Open fix") }
                    }
                }
            }
        }
    }
}

@Composable
private fun SensorScreen() {
    val ctx = LocalContext.current
    val running = SensorLog.running
    var usageOk by remember { mutableStateOf(true) }
    LaunchedEffect(Unit) { SensorLog.init(ctx) }
    LifecycleResumeEffect(Unit) { usageOk = PermissionAuditor(ctx).hasUsageAccess(); onPauseOrDispose { } }

    fun startWatch() { ContextCompat.startForegroundService(ctx, Intent(ctx, SensorWatchService::class.java)) }
    val notifLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { startWatch() }
    val notifOk = ContextCompat.checkSelfPermission(ctx, android.Manifest.permission.POST_NOTIFICATIONS) ==
        android.content.pm.PackageManager.PERMISSION_GRANTED

    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            ElevatedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(if (running) "Watching camera & microphone" else "Monitoring is off", style = MaterialTheme.typography.titleLarge)
                    Text("Detects when ANYTHING on the phone opens the camera or records audio: user apps, hidden apps and system services. Alerts you if it happens while your screen is off.", style = MaterialTheme.typography.bodySmall)
                    if (running) Button({ ctx.stopService(Intent(ctx, SensorWatchService::class.java)) }) { Text("Stop monitoring") }
                    else Button({ if (notifOk) startWatch() else notifLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS) }) { Text("Start monitoring") }
                    if (!notifOk) Text("Allow notifications so alerts can reach you.", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        if (!usageOk) item {
            OutlinedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Optional: allow Usage access so Sentinel can name the foreground app when the camera or mic turns on.")
                    TextButton({ runCatching { ctx.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) } }) { Text("Open settings") }
                }
            }
        }
        item {
            OutlinedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Android hides which app is responsible from normal apps. To see exactly who, check Android's own Privacy dashboard.", style = MaterialTheme.typography.bodySmall)
                    TextButton({ runCatching { ctx.startActivity(Intent(Settings.ACTION_PRIVACY_SETTINGS)) } }) { Text("Open Privacy settings") }
                }
            }
        }
        item { Text("Activity log", style = MaterialTheme.typography.titleMedium) }
        if (SensorLog.events.isEmpty()) item { Text("Nothing yet.", style = MaterialTheme.typography.bodySmall) }
        items(SensorLog.events.toList()) { line -> Text(line, style = MaterialTheme.typography.bodySmall) }
    }
}
