package com.selinuxassistant.guardx.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.selinuxassistant.guardx.ui.theme.GuardXColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    vm: SettingsViewModel = viewModel()
) {
    val sigCount  by vm.sigCount.collectAsState()
    val dbVersion by vm.dbVersion.collectAsState()
    val updating  by vm.isUpdating.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Ayarlar", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Geri")
                    }
                }
            )
        }
    ) { innerPadding ->
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(innerPadding)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {

        // ── İmza Veritabanı Kartı ──────────────────────────────────
        Card(
            colors = CardDefaults.cardColors(containerColor = GuardXColors.Surface)
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Security, contentDescription = null,
                         tint = GuardXColors.Primary)
                    Spacer(Modifier.width(8.dp))
                    Text("İmza Veritabanı",
                         fontWeight = FontWeight.SemiBold,
                         color = GuardXColors.TextPrimary)
                }
                Divider(color = GuardXColors.Border)

                StatRow("İmza Sayısı",
                        if (sigCount > 0) "%,d".format(sigCount) else "Yükleniyor…")
                StatRow("Versiyon", dbVersion)

                if (updating) {
                    Row(verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                            color = GuardXColors.Primary
                        )
                        Text("Güncelleniyor…",
                             fontSize = 13.sp, color = GuardXColors.TextSecondary)
                    }
                } else {
                    Button(
                        onClick = { vm.refreshDbStats() },
                        colors  = ButtonDefaults.buttonColors(
                            containerColor = GuardXColors.Primary)
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = null,
                             modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("İstatistikleri Yenile")
                    }
                }

                // MalwareBazaar güncelleme notu
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = GuardXColors.SurfaceVariant)
                ) {
                    Column(Modifier.padding(12.dp)) {
                        Text("İmzaları Genişlet",
                             fontWeight = FontWeight.Medium,
                             color = GuardXColors.TextPrimary,
                             fontSize = 13.sp)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "Geliştirici araçlarından build_sigdb.py --malwarebazaar " +
                            "komutu ile MalwareBazaar'dan binlerce gerçek Android " +
                            "malware imzası indirebilirsiniz.",
                            fontSize = 12.sp,
                            color = GuardXColors.TextSecondary,
                            lineHeight = 18.sp
                        )
                    }
                }
            }
        }

        // ── Hakkında ───────────────────────────────────────────────
        Card(colors = CardDefaults.cardColors(containerColor = GuardXColors.Surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Info, contentDescription = null,
                         tint = GuardXColors.Primary)
                    Spacer(Modifier.width(8.dp))
                    Text("Hakkında",
                         fontWeight = FontWeight.SemiBold,
                         color = GuardXColors.TextPrimary)
                }
                Divider(color = GuardXColors.Border)
                StatRow("Uygulama",   "GuardX Antivirus")
                StatRow("Versiyon",   "1.0.0")
                StatRow("Engine",     "guardx_engine (C++17 NDK)")
                StatRow("Min Android","8.0 (API 26)")
            }
        }
    } // Column
    } // Scaffold
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, fontSize = 13.sp, color = GuardXColors.TextSecondary)
        Text(value, fontSize = 13.sp, color = GuardXColors.TextPrimary,
             fontWeight = FontWeight.Medium)
    }
}
