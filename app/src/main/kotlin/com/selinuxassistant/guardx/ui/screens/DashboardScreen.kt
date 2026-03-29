package com.selinuxassistant.guardx.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.selinuxassistant.guardx.model.RootReport
import com.selinuxassistant.guardx.ui.components.*
import com.selinuxassistant.guardx.ui.theme.GuardXColors

@Composable
fun DashboardScreen(
    onNavigate: (String) -> Unit,
    vm: DashboardViewModel = viewModel()
) {
    val rootReport by vm.rootReport.collectAsState()
    val isChecking by vm.isChecking.collectAsState()

    val securityScore = remember(rootReport) {
        rootReport?.let { r ->
            when (r.riskLevel) {
                0 -> 95; 1 -> 72; 2 -> 48; 3 -> 22; else -> 5
            }
        } ?: 0
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        // Başlık
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically) {
            Column {
                Text("GuardX", style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold)
                Text("Güvenlik Merkezi", style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onBackground.copy(.5f))
            }
            IconButton(onClick = { onNavigate("settings") }) {
                Icon(Icons.Default.Settings, "Ayarlar")
            }
        }

        // Güvenlik Gauge
        Card(
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Column(
                Modifier.fillMaxWidth().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text("Güvenlik Skoru", style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(.6f))

                if (isChecking) {
                    ScanPulse(true, Modifier.size(140.dp))
                    Text("Kontrol ediliyor…", style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(.5f))
                } else {
                    SecurityGauge(securityScore)
                    rootReport?.let { r ->
                        Surface(
                            shape = RoundedCornerShape(50),
                            color = Color(android.graphics.Color.parseColor(r.riskColorHex)).copy(.15f)
                        ) {
                            Text(
                                r.riskLabel,
                                Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = Color(android.graphics.Color.parseColor(r.riskColorHex))
                            )
                        }
                    }
                }

                Button(
                    onClick = { vm.quickCheck() },
                    enabled = !isChecking,
                    shape = RoundedCornerShape(50)
                ) {
                    Icon(Icons.Default.Refresh, null, Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Yenile")
                }
            }
        }

        // Durum kartları
        rootReport?.let { r ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                StatCard(
                    title = "Root",
                    value = if (r.isRooted) "Tespit!" else "Temiz",
                    icon  = Icons.Default.Security,
                    color = if (r.isRooted) GuardXColors.Danger else GuardXColors.Safe,
                    modifier = Modifier.weight(1f)
                )
                StatCard(
                    title = "Hook",
                    value = if (r.isHooked) "Tespit!" else "Temiz",
                    icon  = Icons.Default.BugReport,
                    color = if (r.isHooked) GuardXColors.Critical else GuardXColors.Safe,
                    modifier = Modifier.weight(1f)
                )
                StatCard(
                    title = "Bootloader",
                    value = if (r.bootloaderUnlocked) "Açık" else "Kilitli",
                    icon  = Icons.Default.Lock,
                    color = if (r.bootloaderUnlocked) GuardXColors.Warning else GuardXColors.Safe,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Hızlı Eylemler
        Text("Hızlı Tarama", style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold)

        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            QuickActionCard(
                icon   = Icons.Default.FolderOpen,
                title  = "Dosya Taraması",
                sub    = "Depolama alanını tara",
                color  = GuardXColors.Primary,
                onClick= { onNavigate("file_scan") }
            )
            QuickActionCard(
                icon   = Icons.Default.Android,
                title  = "Uygulama Taraması",
                sub    = "Yüklü APK'ları analiz et",
                color  = GuardXColors.Secondary,
                onClick= { onNavigate("apk_scan") }
            )
            QuickActionCard(
                icon   = Icons.Default.AdminPanelSettings,
                title  = "Root Kontrolü",
                sub    = "Sistem bütünlüğünü denetle",
                color  = GuardXColors.Warning,
                onClick= { onNavigate("root_check") }
            )
            QuickActionCard(
                icon   = Icons.Default.MonitorHeart,
                title  = "Davranış Monitörü",
                sub    = "Süreç syscall analizi",
                color  = GuardXColors.Critical,
                onClick= { onNavigate("behavior") }
            )
            QuickActionCard(
                icon   = Icons.Default.VerifiedUser,
                title  = "Cihaz Doğrulama",
                sub    = "TEE + Play Integrity",
                color  = GuardXColors.Primary,
                onClick= { onNavigate("integrity") }
            )
        }
    }
}

@Composable
private fun QuickActionCard(
    icon:    androidx.compose.ui.graphics.vector.ImageVector,
    title:   String,
    sub:     String,
    color:   Color,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        shape   = RoundedCornerShape(16.dp),
        colors  = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Box(
                Modifier.size(44.dp)
                    .background(color.copy(.15f), RoundedCornerShape(12.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, null, Modifier.size(22.dp), tint = color)
            }
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
                Text(sub, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(.55f))
            }
            Icon(Icons.Default.ChevronRight, null,
                tint = MaterialTheme.colorScheme.onSurface.copy(.3f))
        }
    }
}
