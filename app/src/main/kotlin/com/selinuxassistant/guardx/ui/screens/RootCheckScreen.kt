package com.selinuxassistant.guardx.ui.screens

import androidx.compose.animation.*
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
import com.selinuxassistant.guardx.model.RootReport
import com.selinuxassistant.guardx.ui.components.*
import com.selinuxassistant.guardx.ui.theme.GuardXColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RootCheckScreen(
    onBack: () -> Unit,
    vm: RootCheckViewModel = viewModel()
) {
    val state by vm.state.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Root Kontrolü", fontWeight = FontWeight.SemiBold) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, "Geri") }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(20.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            when (val s = state) {
                is RootCheckState.Idle     -> RootIdleView(vm)
                is RootCheckState.Scanning -> RootScanningView()
                is RootCheckState.Done     -> RootResultView(s.report, vm)
                is RootCheckState.Error    -> Column(
                    Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(Icons.Default.ErrorOutline, null, Modifier.size(48.dp),
                        tint = GuardXColors.Danger)
                    Text(s.msg)
                    Button(onClick = { vm.quickScan() }, shape = RoundedCornerShape(50)) {
                        Text("Tekrar Dene")
                    }
                }
            }
        }
    }
}

@Composable
private fun RootIdleView(vm: RootCheckViewModel) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card(shape = RoundedCornerShape(20.dp),
             colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(48.dp).background(GuardXColors.Warning.copy(.15f), CircleShape),
                        contentAlignment = Alignment.Center) {
                        Icon(Icons.Default.AdminPanelSettings, null,
                            Modifier.size(24.dp), tint = GuardXColors.Warning)
                    }
                    Column {
                        Text("Sistem Bütünlüğü",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold)
                        Text("Root, hook ve bootloader durumunu analiz eder",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface.copy(.55f))
                    }
                }

                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button(
                        onClick  = { vm.quickScan() },
                        modifier = Modifier.weight(1f),
                        shape    = RoundedCornerShape(50)
                    ) {
                        Icon(Icons.Default.FlashOn, null, Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Hızlı")
                    }
                    OutlinedButton(
                        onClick  = { vm.deepScan() },
                        modifier = Modifier.weight(1f),
                        shape    = RoundedCornerShape(50)
                    ) {
                        Icon(Icons.Default.ManageSearch, null, Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Derin")
                    }
                }
            }
        }

        // Tespit katmanları bilgisi
        Card(shape = RoundedCornerShape(16.dp),
             colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("15 Tespit Katmanı", style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
                listOf(
                    Icons.Default.Memory      to "Build props, SELinux, Kernel integrity",
                    Icons.Default.Code        to "Su binary, root packages, mount points",
                    Icons.Default.Shield      to "Frida, Xposed, Magisk/Zygisk hook tespiti",
                    Icons.Default.Psychology  to "ptrace, ptrace timing, debugger tespiti",
                    Icons.Default.Storage     to "Bootloader: 5 bağımsız kaynak"
                ).forEach { (icon, text) ->
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Icon(icon, null, Modifier.size(18.dp),
                            tint = GuardXColors.Primary)
                        Text(text, style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface.copy(.7f))
                    }
                }
            }
        }
    }
}

@Composable
private fun RootScanningView() {
    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        ScanPulse(true, Modifier.size(140.dp))
        Text("Sistem Analiz Ediliyor…",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold)
        LinearProgressIndicator(Modifier.fillMaxWidth().height(6.dp))
        Text("15 tespit katmanı çalışıyor",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(.5f))
    }
}

@Composable
private fun RootResultView(report: RootReport, vm: RootCheckViewModel) {
    val statusColor = Color(android.graphics.Color.parseColor(report.riskColorHex))

    // Ana sonuç kartı
    Card(
        shape  = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(statusColor.copy(.1f)),
        border = BorderStroke(1.dp, statusColor.copy(.3f))
    ) {
        Column(
            Modifier.fillMaxWidth().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(Modifier.size(72.dp).background(statusColor.copy(.15f), CircleShape),
                contentAlignment = Alignment.Center) {
                Icon(
                    if (report.isRooted || report.isHooked) Icons.Default.GppBad
                    else Icons.Default.GppGood,
                    null, Modifier.size(36.dp), tint = statusColor
                )
            }
            Text(report.riskLabel,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold, color = statusColor)
            Text(
                when {
                    report.isRooted && report.isHooked -> "Cihaz root'lu ve hook tespit edildi"
                    report.isRooted  -> "Root erişimi tespit edildi"
                    report.isHooked  -> "Hook framework tespit edildi"
                    report.bootloaderUnlocked -> "Bootloader açık, sistem değiştirilmiş olabilir"
                    else -> "Sistem bütünlüğü sağlam"
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(.65f)
            )
        }
    }

    // Durum grid
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        StatusCard("Root", report.isRooted, Modifier.weight(1f))
        StatusCard("Hook", report.isHooked, Modifier.weight(1f))
        StatusCard("Bootloader Açık", report.bootloaderUnlocked, Modifier.weight(1f))
    }

    // Kanıtlar
    if (report.evidences.isNotEmpty()) {
        Text("Bulgular (${report.evidences.size})",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold)
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            report.evidences.forEach { ev ->
                Row(
                    Modifier.fillMaxWidth()
                        .background(
                            if (ev.weight >= 7) GuardXColors.Danger.copy(.08f)
                            else MaterialTheme.colorScheme.surfaceVariant,
                            RoundedCornerShape(10.dp)
                        )
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        Modifier.size(28.dp)
                            .background(
                                if (ev.weight >= 7) GuardXColors.Danger.copy(.15f)
                                else GuardXColors.Warning.copy(.15f),
                                CircleShape
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(ev.weight.toString(),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = if (ev.weight >= 7) GuardXColors.Danger else GuardXColors.Warning)
                    }
                    Text(ev.detail, style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(.8f))
                }
            }
        }
    }

    Spacer(Modifier.height(4.dp))
    OutlinedButton(
        onClick  = { vm.quickScan() },
        modifier = Modifier.fillMaxWidth(),
        shape    = RoundedCornerShape(50)
    ) {
        Icon(Icons.Default.Refresh, null, Modifier.size(16.dp))
        Spacer(Modifier.width(6.dp))
        Text("Yeniden Tara")
    }
}

@Composable
private fun StatusCard(label: String, isDetected: Boolean, modifier: Modifier = Modifier) {
    val color = if (isDetected) GuardXColors.Danger else GuardXColors.Safe
    Card(shape = RoundedCornerShape(14.dp),
         colors = CardDefaults.cardColors(color.copy(.1f)),
         modifier = modifier) {
        Column(
            Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Icon(
                if (isDetected) Icons.Default.Close else Icons.Default.Check,
                null, Modifier.size(20.dp), tint = color
            )
            Text(label, style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurface.copy(.6f))
            Text(if (isDetected) "Evet" else "Hayır",
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Bold, color = color)
        }
    }
}
