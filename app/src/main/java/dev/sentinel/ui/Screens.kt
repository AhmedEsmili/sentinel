package dev.sentinel.ui

import android.content.Intent
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
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            if (tab == 0) PermissionsScreen() else ScamScreen(sharedText)
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
    LifecycleResumeEffect(Unit) { tick++; onPauseOrDispose { } }
    LaunchedEffect(tick) {
        val auditor = PermissionAuditor(ctx)
        usageOk = auditor.hasUsageAccess()
        apps = withContext(Dispatchers.Default) { auditor.audit() }
    }

    val list = apps
    if (list == null) { Box(Modifier.fillMaxSize()) { CircularProgressIndicator(Modifier.padding(32.dp)) }; return }

    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            val top = list.firstOrNull()
            ElevatedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Top fix", style = MaterialTheme.typography.labelLarge)
                    Text(
                        if (top == null) "No risky apps found 🎉" else "${top.label}: ${top.reasons.first()}",
                        style = MaterialTheme.typography.titleMedium,
                    )
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
                            ctx.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${app.pkg}")))
                        }) { Text("Review permissions") }
                        TextButton({
                            ctx.startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:${app.pkg}")))
                        }) { Text("Uninstall") }
                    }
                }
            }
        }
    }
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
