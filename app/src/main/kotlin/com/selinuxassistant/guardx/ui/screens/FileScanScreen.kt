package com.selinuxassistant.guardx.ui.screens

import androidx.compose.animation.*
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.selinuxassistant.guardx.model.ScanStats
import com.selinuxassistant.guardx.model.ThreatLevel
import com.selinuxassistant.guardx.ui.components.*
import com.selinuxassistant.guardx.ui.theme.GuardXColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FileScanScreen(
    onBack: () -> Unit,
    vm: FileScanViewModel = viewModel()
) {
    val state by vm.state.collectAsState()
    var selectedPath by remember { mutableStateOf(vm.storagePaths.firstOrNull() ?: "/sdcard") }
    var showPathDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Dosya Taraması", fontWeight = FontWeight.SemiBold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Geri")
                    }
                },
                actions = {
                    if (state is ScanUiState.Done) {
                        IconButton(onClick = { vm.reset() }) {
                            Icon(Icons.Default.Refresh, "Yeniden")
                        }
                    }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            when (val s = state) {
                is ScanUiState.Idle -> IdleView(
                    selectedPath  = selectedPath,
                    paths         = vm.storagePaths,
                    onPathChange  = { selectedPath = it },
                    onScan        = { vm.scanPath(selectedPath) }
                )
                is ScanUiState.Scanning -> ScanningView(s) { vm.cancel() }
                is ScanUiState.Done     -> ResultView(s.stats)
                is ScanUiState.Error    -> ErrorView(s.msg) { vm.reset() }
            }
        }
    }
}

@Composable
private fun IdleView(
    selectedPath: String,
    paths:        List<String>,
    onPathChange: (String) -> Unit,
    onScan:       () -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    Card(shape = RoundedCornerShape(20.dp),
         colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("Taranacak Konum", style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold)

            ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
                OutlinedTextField(
                    value          = selectedPath,
                    onValueChange  = {},
                    readOnly       = true,
                    label          = { Text("Konum") },
                    trailingIcon   = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
                    modifier       = Modifier.fillMaxWidth().menuAnchor()
                )
                ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                    paths.forEach { path ->
                        DropdownMenuItem(
                            text    = { Text(path, overflow = TextOverflow.Ellipsis) },
                            onClick = { onPathChange(path); expanded = false }
                        )
                    }
                    DropdownMenuItem(
                        text    = { Text("/data/app — Yüklü APK'lar") },
                        onClick = { onPathChange("/data/app"); expanded = false }
                    )
                }
            }

            Button(
                onClick  = onScan,
                modifier = Modifier.fillMaxWidth(),
                shape    = RoundedCornerShape(50)
            ) {
                Icon(Icons.Default.Search, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Taramayı Başlat")
            }
        }
    }

    // Bilgi kartı
    Card(shape = RoundedCornerShape(16.dp),
         colors = CardDefaults.cardColors(GuardXColors.Primary.copy(.08f))) {
        Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(Icons.Default.Info, null, Modifier.size(20.dp),
                tint = GuardXColors.Primary)
            Text(
                "SHA-256 hash'leri yerel veritabanıyla karşılaştırılır. " +
                "Eşleşme yoksa bulut API'si sorgulanır.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(.7f)
            )
        }
    }
}

@Composable
private fun ScanningView(state: ScanUiState.Scanning, onCancel: () -> Unit) {
    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        ScanPulse(true, Modifier.size(140.dp))

        Column(horizontalAlignment = Alignment.CenterHorizontally,
               verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Taranıyor…", style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold)
            if (state.total > 0)
                Text("${state.scanned} / ${state.total} dosya",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(.55f))
        }

        if (state.total > 0) {
            LinearProgressIndicator(
                progress = state.scanned.toFloat() / state.total,
                modifier = Modifier.fillMaxWidth().height(6.dp),
                trackColor = MaterialTheme.colorScheme.outline.copy(.2f)
            )
        } else {
            LinearProgressIndicator(Modifier.fillMaxWidth().height(6.dp))
        }

        Text(
            state.current.substringAfterLast('/'),
            style    = MaterialTheme.typography.labelSmall,
            color    = MaterialTheme.colorScheme.onSurface.copy(.4f),
            maxLines = 1, overflow = TextOverflow.Ellipsis,
            modifier = Modifier.fillMaxWidth()
        )

        OutlinedButton(onClick = onCancel, shape = RoundedCornerShape(50)) {
            Icon(Icons.Default.Stop, null, Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text("Durdur")
        }
    }
}

@Composable
private fun ResultView(stats: ScanStats) {
    LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            // Özet
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatCard("Toplam", stats.totalFiles.toString(),
                    Icons.Default.FolderOpen, GuardXColors.Primary, Modifier.weight(1f))
                StatCard("Temiz",  stats.cleanFiles.toString(),
                    Icons.Default.CheckCircle, GuardXColors.Safe, Modifier.weight(1f))
                StatCard("Tehdit", stats.threatCount.toString(),
                    Icons.Default.Warning,
                    if (stats.threatCount > 0) GuardXColors.Danger else GuardXColors.Safe,
                    Modifier.weight(1f))
            }
        }

        if (stats.threats.isEmpty()) {
            item {
                Card(shape = RoundedCornerShape(20.dp),
                     colors = CardDefaults.cardColors(GuardXColors.Safe.copy(.08f))) {
                    Row(Modifier.fillMaxWidth().padding(20.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.CheckCircle, null,
                            Modifier.size(32.dp), tint = GuardXColors.Safe)
                        Column {
                            Text("Temiz!", style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold, color = GuardXColors.Safe)
                            Text("Hiçbir tehdit bulunamadı.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface.copy(.6f))
                        }
                    }
                }
            }
        } else {
            item {
                Text("Tehditler (${stats.threats.size})",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
            }
            items(stats.threats) { threat ->
                FindingRow(
                    title    = threat.filePath.substringAfterLast('/'),
                    subtitle = threat.threatName.ifEmpty { "Şüpheli dosya" },
                    level    = threat.threatLevel
                )
            }
        }
    }
}

@Composable
private fun ErrorView(msg: String, onRetry: () -> Unit) {
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally,
           verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Icon(Icons.Default.ErrorOutline, null, Modifier.size(48.dp),
            tint = GuardXColors.Danger)
        Text("Hata", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Text(msg, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(.6f))
        Button(onClick = onRetry, shape = RoundedCornerShape(50)) { Text("Tekrar Dene") }
    }
}
