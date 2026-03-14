package com.selinuxassistant.guardx.ui.screens

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.selinuxassistant.guardx.model.BehaviorReport
import com.selinuxassistant.guardx.model.ProcessProfile
import com.selinuxassistant.guardx.ui.components.*
import com.selinuxassistant.guardx.ui.theme.GuardXColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BehaviorScreen(
    onBack: () -> Unit,
    vm: BehaviorViewModel = viewModel()
) {
    val state by vm.state.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Davranış Monitörü", fontWeight = FontWeight.SemiBold) },
                navigationIcon = { IconButton(onClick = onBack) {
                    Icon(Icons.Default.ArrowBack, "Geri") } }
            )
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            when (val s = state) {
                is BehaviorState.Idle    -> BehaviorIdleView(vm)
                is BehaviorState.Scanning-> BehaviorScanningView(s) { vm.reset() }
                is BehaviorState.Done    -> BehaviorResultView(s.report) { vm.reset() }
                is BehaviorState.Error   -> Column(
                    Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(Icons.Default.ErrorOutline, null, Modifier.size(48.dp),
                        tint = GuardXColors.Danger)
                    Text(s.msg, style = MaterialTheme.typography.bodyMedium)
                    Button(onClick = { vm.reset() }, shape = RoundedCornerShape(50)) {
                        Text("Geri")
                    }
                }
            }
        }
    }
}

@Composable
private fun BehaviorIdleView(vm: BehaviorViewModel) {
    var durationSec by remember { mutableStateOf(5) }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Card(shape = RoundedCornerShape(20.dp),
             colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(48.dp).background(GuardXColors.Critical.copy(.15f), CircleShape),
                        contentAlignment = Alignment.Center) {
                        Icon(Icons.Default.MonitorHeart, null,
                            Modifier.size(24.dp), tint = GuardXColors.Critical)
                    }
                    Column {
                        Text("Syscall Analizi",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold)
                        Text("/proc polling ile tüm erişilebilir süreçler",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface.copy(.55f))
                    }
                }

                // Süre seçici
                Text("İzleme Süresi: ${durationSec}s",
                    style = MaterialTheme.typography.bodyMedium)
                Slider(
                    value          = durationSec.toFloat(),
                    onValueChange  = { durationSec = it.toInt() },
                    valueRange     = 3f..30f,
                    steps          = 8
                )

                Button(
                    onClick  = { vm.startScan(durationSec * 1000) },
                    modifier = Modifier.fillMaxWidth(),
                    shape    = RoundedCornerShape(50)
                ) {
                    Icon(Icons.Default.PlayArrow, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Taramayı Başlat")
                }
            }
        }

        // Açıklama
        Card(shape = RoundedCornerShape(16.dp),
             colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Tespit Edilen Tehditler",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
                listOf(
                    Icons.Default.Memory   to "W+X bellek, shellcode, fileless exec",
                    Icons.Default.Security to "setuid(0), capset, privilege escalation",
                    Icons.Default.Code     to "Kernel modülü, BPF prog, io_uring exploit",
                    Icons.Default.Terminal to "Shell spawn, /tmp'den exec, ptrace inject",
                    Icons.Default.CloudOff to "Veri sızdırma, raw socket, bağlantı patlaması"
                ).forEach { (icon, text) ->
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Icon(icon, null, Modifier.size(18.dp), tint = GuardXColors.Primary)
                        Text(text, style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface.copy(.7f))
                    }
                }
            }
        }
    }
}

@Composable
private fun BehaviorScanningView(s: BehaviorState.Scanning, onStop: () -> Unit) {
    val progress = if (s.duration > 0) s.elapsed.toFloat() / s.duration else 0f

    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        ScanPulse(true, Modifier.size(140.dp))
        Text("Süreçler İzleniyor",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold)
        Text("${s.elapsed / 1000} / ${s.duration / 1000} saniye",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(.5f))
        LinearProgressIndicator(
            progress = progress,
            modifier = Modifier.fillMaxWidth().height(6.dp),
            trackColor = MaterialTheme.colorScheme.outline.copy(.2f)
        )
        OutlinedButton(onClick = onStop, shape = RoundedCornerShape(50)) {
            Icon(Icons.Default.Stop, null, Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text("Durdur")
        }
    }
}

@Composable
private fun BehaviorResultView(report: BehaviorReport, onReset: () -> Unit) {
    val compromised = report.profiles.filter { it.isCompromised }

    LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatCard("Süreç", report.profiles.size.toString(),
                    Icons.Default.Apps, GuardXColors.Primary, Modifier.weight(1f))
                StatCard("Şüpheli", compromised.size.toString(),
                    Icons.Default.Warning,
                    if (compromised.isEmpty()) GuardXColors.Safe else GuardXColors.Danger,
                    Modifier.weight(1f))
                StatCard("Event", formatNumber(report.totalEvents),
                    Icons.Default.Speed, GuardXColors.Secondary, Modifier.weight(1f))
            }
        }

        if (compromised.isEmpty()) {
            item {
                Card(shape = RoundedCornerShape(20.dp),
                     colors = CardDefaults.cardColors(GuardXColors.Safe.copy(.08f)),
                     border = BorderStroke(1.dp, GuardXColors.Safe.copy(.3f))) {
                    Row(Modifier.fillMaxWidth().padding(20.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.CheckCircle, null,
                            Modifier.size(32.dp), tint = GuardXColors.Safe)
                        Column {
                            Text("Temiz!", style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold, color = GuardXColors.Safe)
                            Text("Şüpheli davranış tespit edilmedi.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface.copy(.6f))
                        }
                    }
                }
            }
        } else {
            item {
                Text("Şüpheli Süreçler (${compromised.size})",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
            }
            items(compromised) { p -> ProcessRow(p) }
        }

        if (report.profiles.isNotEmpty()) {
            item {
                Spacer(Modifier.height(4.dp))
                Text("Tüm Süreçler", style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
            }
            items(report.profiles.sortedByDescending { it.riskScore }) { p ->
                ProcessRow(p)
            }
        }

        item {
            Spacer(Modifier.height(4.dp))
            OutlinedButton(
                onClick  = onReset,
                modifier = Modifier.fillMaxWidth(),
                shape    = RoundedCornerShape(50)
            ) {
                Icon(Icons.Default.Refresh, null, Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text("Yeniden Tara")
            }
        }
    }
}

@Composable
private fun ProcessRow(p: ProcessProfile) {
    val riskColor = when {
        p.riskScore >= 70 -> GuardXColors.Critical
        p.riskScore >= 40 -> GuardXColors.Danger
        p.riskScore >= 20 -> GuardXColors.Warning
        else              -> GuardXColors.Safe
    }

    Card(shape = RoundedCornerShape(14.dp),
         colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.fillMaxWidth().padding(14.dp),
               verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically) {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(8.dp).background(riskColor, CircleShape))
                    Text(p.comm.ifEmpty { "pid:${p.pid}" },
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold)
                    Text("(${p.pid})", style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(.4f))
                }
                Surface(shape = RoundedCornerShape(50), color = riskColor.copy(.15f)) {
                    Text("${p.riskScore}",
                        Modifier.padding(horizontal = 10.dp, vertical = 3.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold, color = riskColor)
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                LabelValue("Syscall", formatNumber(p.totalSyscalls))
                LabelValue("Hız", "${p.syscallRate}/s")
                if (p.bytesSent > 0) LabelValue("Gönderim", formatBytes(p.bytesSent))
            }
            if (p.findings.isNotEmpty()) {
                Divider(color = MaterialTheme.colorScheme.outline.copy(.15f))
                p.findings.take(3).forEach { f ->
                    Text("• ${f.substringAfter("] ")}",
                        style = MaterialTheme.typography.labelSmall,
                        color = riskColor.copy(.8f))
                }
                if (p.findings.size > 3) {
                    Text("+${p.findings.size - 3} bulgu daha",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(.4f))
                }
            }
        }
    }
}

@Composable
private fun LabelValue(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurface.copy(.45f))
        Text(value, style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium)
    }
}

private fun formatNumber(n: Long) = when {
    n >= 1_000_000 -> "%.1fM".format(n / 1_000_000.0)
    n >= 1_000     -> "%.1fK".format(n / 1_000.0)
    else           -> n.toString()
}

private fun formatBytes(b: Long) = when {
    b >= 1_048_576 -> "%.1f MB".format(b / 1_048_576.0)
    b >= 1024      -> "%.1f KB".format(b / 1024.0)
    else           -> "$b B"
}
