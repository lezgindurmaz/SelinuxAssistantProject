package com.selinuxassistant.guardx.ui.screens

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.selinuxassistant.guardx.model.ApkReport
import com.selinuxassistant.guardx.model.ThreatLevel
import com.selinuxassistant.guardx.ui.components.*
import com.selinuxassistant.guardx.ui.theme.GuardXColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApkScanScreen(
    onBack: () -> Unit,
    vm: ApkScanViewModel = viewModel()
) {
    val state by vm.state.collectAsState()
    var detailReport by remember { mutableStateOf<ApkReport?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Uygulama Taraması", fontWeight = FontWeight.SemiBold) },
                navigationIcon = { IconButton(onClick = onBack) {
                    Icon(Icons.Default.ArrowBack, "Geri") } },
                actions = {
                    if (state is ApkScanState.Done) {
                        IconButton(onClick = { vm.reset() }) {
                            Icon(Icons.Default.Refresh, "Yeniden")
                        }
                    }
                }
            )
        }
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val s = state) {
                is ApkScanState.Idle      -> ApkIdleView(vm)
                is ApkScanState.Scanning  -> ApkScanningView(s)
                is ApkScanState.Done      -> ApkResultsView(s.reports) { detailReport = it }
                is ApkScanState.SingleDone-> ApkDetailContent(s.report)
                is ApkScanState.Error     -> Column(
                    Modifier.fillMaxSize().padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Icon(Icons.Default.ErrorOutline, null, Modifier.size(48.dp),
                        tint = GuardXColors.Danger)
                    Spacer(Modifier.height(12.dp))
                    Text(s.msg, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(12.dp))
                    Button(onClick = { vm.reset() }, shape = RoundedCornerShape(50)) {
                        Text("Geri")
                    }
                }
            }
        }
    }

    // Detail bottom sheet
    detailReport?.let { report ->
        ModalBottomSheet(onDismissRequest = { detailReport = null }) {
            ApkDetailContent(report, Modifier.padding(bottom = 32.dp))
        }
    }
}

@Composable
private fun ApkIdleView(vm: ApkScanViewModel) {
    Column(
        Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Card(shape = RoundedCornerShape(20.dp),
             colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Tüm Yüklü Uygulamaları Tara",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
                Text("Her uygulamanın APK'sı izinler, DEX içeriği ve imza açısından analiz edilir.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(.6f))
                Button(
                    onClick  = { vm.scanAllApps() },
                    modifier = Modifier.fillMaxWidth(),
                    shape    = RoundedCornerShape(50)
                ) {
                    Icon(Icons.Default.Android, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Tüm Uygulamaları Tara")
                }
            }
        }
    }
}

@Composable
private fun ApkScanningView(s: ApkScanState.Scanning) {
    Column(
        Modifier.fillMaxSize().padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        ScanPulse(true, Modifier.size(120.dp))
        Spacer(Modifier.height(24.dp))
        Text("Uygulamalar Analiz Ediliyor",
            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        if (s.total > 0) {
            Text("${s.done} / ${s.total}", style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(.5f))
            Spacer(Modifier.height(16.dp))
            LinearProgressIndicator(
                progress = s.done.toFloat() / s.total,
                modifier = Modifier.fillMaxWidth().height(6.dp)
            )
        } else {
            LinearProgressIndicator(Modifier.fillMaxWidth().height(6.dp))
        }
        Spacer(Modifier.height(12.dp))
        Text(s.pkg, style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurface.copy(.4f),
            maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun ApkResultsView(reports: List<ApkReport>, onDetail: (ApkReport) -> Unit) {
    val threats = reports.filter { it.verdict != "CLEAN" }
    val clean   = reports.filter { it.verdict == "CLEAN" }

    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatCard("Toplam", reports.size.toString(),
                    Icons.Default.Apps, GuardXColors.Primary, Modifier.weight(1f))
                StatCard("Tehditli", threats.size.toString(),
                    Icons.Default.BugReport,
                    if (threats.isEmpty()) GuardXColors.Safe else GuardXColors.Danger,
                    Modifier.weight(1f))
                StatCard("Temiz", clean.size.toString(),
                    Icons.Default.CheckCircle, GuardXColors.Safe, Modifier.weight(1f))
            }
        }

        if (threats.isNotEmpty()) {
            item {
                Spacer(Modifier.height(4.dp))
                Text("Tehditler", style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
            }
            items(threats) { r -> ApkRow(r) { onDetail(r) } }
        }

        if (clean.isNotEmpty()) {
            item {
                Spacer(Modifier.height(4.dp))
                Text("Temiz Uygulamalar", style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
            }
            items(clean) { r -> ApkRow(r) { onDetail(r) } }
        }
    }
}

@Composable
private fun ApkRow(report: ApkReport, onClick: () -> Unit) {
    FindingRow(
        title    = report.packageName.substringAfterLast('.').replaceFirstChar { it.uppercase() }
                       .ifEmpty { report.packageName },
        subtitle = "Skor: ${report.overallScore} • ${report.permissions.size} izin",
        level    = report.threatLevel,
        onClick  = onClick
    )
}

@Composable
fun ApkDetailContent(report: ApkReport, modifier: Modifier = Modifier) {
    LazyColumn(
        modifier.padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            // Başlık
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(52.dp).background(
                        when (report.verdict) {
                            "MALWARE" -> GuardXColors.Danger.copy(.15f)
                            "SUSPICIOUS" -> GuardXColors.Warning.copy(.15f)
                            else -> GuardXColors.Safe.copy(.15f)
                        }, RoundedCornerShape(14.dp)
                    ), contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Default.Android, null, Modifier.size(28.dp),
                        tint = when (report.verdict) {
                            "MALWARE" -> GuardXColors.Danger
                            "SUSPICIOUS" -> GuardXColors.Warning
                            else -> GuardXColors.Safe
                        })
                }
                Column {
                    Text(report.packageName, style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold, maxLines = 1,
                        overflow = TextOverflow.Ellipsis)
                    Text("v${report.versionName}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(.5f))
                }
            }
        }

        item {
            ThreatChip(report.threatLevel)
        }

        // Skor çubukları
        item {
            Card(shape = RoundedCornerShape(16.dp),
                 colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Risk Skorları", style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold)
                    ScoreBar("Genel Risk",   report.overallScore,   GuardXColors.Danger)
                    ScoreBar("İzin Riski",   report.permScore,      GuardXColors.Warning)
                    ScoreBar("Davranış",     report.behaviorScore,  GuardXColors.Critical)
                    ScoreBar("İmza",         report.sigScore,       GuardXColors.Primary)
                }
            }
        }

        // Uyarılar
        val warnings = buildList {
            if (report.debuggable)   add("Hata ayıklama modu açık" to GuardXColors.Warning)
            if (report.cleartext)    add("Şifresiz HTTP trafiğine izin var" to GuardXColors.Warning)
            if (report.isDebugCert)  add("Debug sertifikası kullanıyor" to GuardXColors.Danger)
            if (!report.isSigned)    add("İmzasız APK!" to GuardXColors.Danger)
            if (report.exportedNoPermComponents > 0)
                add("${report.exportedNoPermComponents} korumasız dışa açık bileşen" to GuardXColors.Danger)
        }
        if (warnings.isNotEmpty()) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Uyarılar", style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold)
                    warnings.forEach { (msg, color) ->
                        Row(
                            Modifier.fillMaxWidth()
                                .background(color.copy(.08f), RoundedCornerShape(10.dp))
                                .padding(12.dp),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Icon(Icons.Default.Warning, null, Modifier.size(18.dp), tint = color)
                            Text(msg, style = MaterialTheme.typography.bodyMedium, color = color)
                        }
                    }
                }
            }
        }

        // İzinler
        if (report.permissions.isNotEmpty()) {
            item {
                Text("İzinler (${report.permissions.size})",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
            }
            items(report.permissions.sortedByDescending { it.risk }) { p ->
                PermissionRow(p.name, p.risk, p.description)
                Divider(color = MaterialTheme.colorScheme.outline.copy(.15f))
            }
        }

        // DEX Bulgular
        if (report.dexFindings.isNotEmpty()) {
            item {
                Spacer(Modifier.height(4.dp))
                Text("DEX Bulguları (${report.dexFindings.size})",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
            }
            items(report.dexFindings) { f ->
                val color = when {
                    f.severity >= 9 -> GuardXColors.Critical
                    f.severity >= 7 -> GuardXColors.Danger
                    f.severity >= 5 -> GuardXColors.Warning
                    else            -> GuardXColors.Safe
                }
                FindingRow(
                    title    = f.description,
                    subtitle = f.dexFile,
                    level    = when { f.severity >= 9 -> ThreatLevel.CRITICAL
                                      f.severity >= 7 -> ThreatLevel.MALWARE
                                      f.severity >= 5 -> ThreatLevel.SUSPICIOUS
                                      else            -> ThreatLevel.CLEAN }
                )
            }
        }
        item { Spacer(Modifier.height(20.dp)) }
    }
}
