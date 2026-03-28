package com.selinuxassistant.guardx.ui.screens

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.selinuxassistant.guardx.service.IntegrityResult
import com.selinuxassistant.guardx.service.IntegrityVerdict
import androidx.compose.material3.Divider
import com.selinuxassistant.guardx.ui.components.ScanPulse
import com.selinuxassistant.guardx.ui.theme.GuardXColors

// ══════════════════════════════════════════════════════════════════
//  IntegrityScreen — Google Play Integrity API sonuç ekranı
// ══════════════════════════════════════════════════════════════════
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IntegrityScreen(
    onBack: () -> Unit,
    vm: IntegrityViewModel = viewModel()
) {
    val state by vm.state.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Default.VerifiedUser, null,
                            Modifier.size(20.dp), tint = GuardXColors.Primary)
                        Text("Play Integrity", fontWeight = FontWeight.SemiBold)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Geri")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            when (val s = state) {
                is IntegrityUiState.Idle    -> IntegrityIdleView(vm)
                is IntegrityUiState.Loading -> IntegrityLoadingView()
                is IntegrityUiState.Done    -> IntegrityResultView(s.result, vm)
                is IntegrityUiState.Error   -> IntegrityErrorView(s.message, vm)
            }
        }
    }
}

// ── Boşta görünüm ────────────────────────────────────────────────
@Composable
private fun IntegrityIdleView(vm: IntegrityViewModel) {
    // Açıklama kartı
    Card(
        shape  = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(
            Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // Başlık
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    Modifier.size(48.dp)
                        .clip(CircleShape)
                        .background(GuardXColors.Primary.copy(.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Default.Shield, null,
                        Modifier.size(26.dp), tint = GuardXColors.Primary)
                }
                Column {
                    Text("Google Play Integrity",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold)
                    Text("Google sunucularından cihaz doğrulaması",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(.55f))
                }
            }

            Divider(color = MaterialTheme.colorScheme.outline.copy(.15f))

            // Doğrulama katmanları
            listOf(
                Icons.Default.PhoneAndroid  to "Cihaz bütünlüğü — Bootloader ve donanım",
                Icons.Default.Apps          to "Uygulama tanıma — İmza ve Play Store kaydı",
                Icons.Default.AccountCircle to "Lisans doğrulama — Play hesabı kontrolü",
                Icons.Default.Cloud         to "Google sunucusu imzalı — manipüle edilemez"
            ).forEach { (icon, text) ->
                Row(
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(icon, null, Modifier.size(18.dp), tint = GuardXColors.Primary)
                    Text(text, style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(.75f))
                }
            }

            // Uyarı notu
            Surface(
                shape  = RoundedCornerShape(10.dp),
                color  = GuardXColors.Warning.copy(.08f),
                border = BorderStroke(1.dp, GuardXColors.Warning.copy(.25f))
            ) {
                Row(
                    Modifier.padding(12.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Default.Info, null,
                        Modifier.size(16.dp), tint = GuardXColors.Warning)
                    Text(
                        "Bu doğrulama internet bağlantısı gerektirir ve Google Play " +
                        "hizmetleri kurulu olmalıdır.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(.65f),
                        lineHeight = 18.sp
                    )
                }
            }

            // Buton
            Button(
                onClick  = { vm.requestVerdict() },
                modifier = Modifier.fillMaxWidth(),
                shape    = RoundedCornerShape(50)
            ) {
                Icon(Icons.Default.Verified, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Doğrulama Başlat")
            }
        }
    }
}

// ── Yükleniyor görünümü ──────────────────────────────────────────
@Composable
private fun IntegrityLoadingView() {
    Column(
        Modifier.fillMaxWidth().padding(vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        ScanPulse(true, Modifier.size(130.dp))

        Text("Google Sunucularıyla İletişim",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold)

        Text("Cihaz bütünlüğü doğrulanıyor…",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(.5f))

        LinearProgressIndicator(
            modifier = Modifier.fillMaxWidth().height(4.dp),
            trackColor = MaterialTheme.colorScheme.outline.copy(.2f)
        )
    }
}

// ── Hata görünümü ────────────────────────────────────────────────
@Composable
private fun IntegrityErrorView(message: String, vm: IntegrityViewModel) {
    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Spacer(Modifier.height(16.dp))
        Box(
            Modifier.size(72.dp).clip(CircleShape)
                .background(GuardXColors.Warning.copy(.15f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(Icons.Default.CloudOff, null,
                Modifier.size(36.dp), tint = GuardXColors.Warning)
        }
        Text("Doğrulama Başarısız",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold)
        Text(message,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(.6f),
            textAlign = TextAlign.Center)
        Button(onClick = { vm.requestVerdict() }, shape = RoundedCornerShape(50)) {
            Icon(Icons.Default.Refresh, null, Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text("Tekrar Dene")
        }
        OutlinedButton(onClick = { vm.reset() }, shape = RoundedCornerShape(50)) {
            Text("Vazgeç")
        }
    }
}

// ── Sonuç görünümü ───────────────────────────────────────────────
@Composable
private fun IntegrityResultView(result: IntegrityResult.Success, vm: IntegrityViewModel) {
    val v = result.verdict

    // ── Ana skor kartı ───────────────────────────────────────────
    val scoreColor = when {
        v.trustScore >= 80 -> GuardXColors.Safe
        v.trustScore >= 50 -> GuardXColors.Warning
        else               -> GuardXColors.Danger
    }
    val scoreIcon = when {
        v.trustScore >= 80 -> Icons.Default.VerifiedUser
        v.trustScore >= 50 -> Icons.Default.GppMaybe
        else               -> Icons.Default.GppBad
    }

    Card(
        shape  = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(scoreColor.copy(.08f)),
        border = BorderStroke(1.dp, scoreColor.copy(.3f))
    ) {
        Column(
            Modifier.fillMaxWidth().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Box(
                Modifier.size(72.dp).clip(CircleShape)
                    .background(scoreColor.copy(.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(scoreIcon, null, Modifier.size(38.dp), tint = scoreColor)
            }

            Text("Güven Skoru: ${v.trustScore}/100",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold, color = scoreColor)

            // Özet mesajı
            Text(
                when {
                    v.trustScore >= 90 -> "Cihaz ve uygulama tam doğrulandı"
                    v.trustScore >= 70 -> "Cihaz güvenilir, bazı kontroller geçemedi"
                    v.trustScore >= 40 -> "Kısmi güvence — dikkatli olun"
                    else               -> "Cihaz doğrulaması başarısız"
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(.65f),
                textAlign = TextAlign.Center
            )
        }
    }

    // ── Cihaz bütünlüğü ─────────────────────────────────────────
    SectionCard(title = "Cihaz Bütünlüğü", icon = Icons.Default.PhoneAndroid) {
        IntegrityRow(
            label   = "Cihaz Bütünlüğü",
            passed  = v.meetsDeviceIntegrity,
            detail  = if (v.meetsDeviceIntegrity)
                "Gerçek Android donanımı, TrustZone aktif"
            else
                "Emülatör, rootlu cihaz veya değiştirilmiş sistem"
        )
        IntegrityRow(
            label   = "Güçlü Donanım Kanıtı",
            passed  = v.meetsStrongIntegrity,
            detail  = if (v.meetsStrongIntegrity)
                "Play Protect sertifikalı, donanım destekli doğrulama"
            else
                "Donanım destekli kanıt yok (eski cihaz veya rootlu)"
        )
        if (v.meetsVirtualIntegrity) {
            IntegrityRow(
                label  = "Sanal Ortam",
                passed = false,
                detail = "Emülatör veya CI ortamı tespit edildi"
            )
        }

        // Cihaz label'larını göster
        if (v.deviceLabels.isNotEmpty()) {
            Spacer(Modifier.height(4.dp))
            Text("Cihaz Etiketleri:",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurface.copy(.5f))
            v.deviceLabels.forEach { label ->
                val (labelColor, labelText) = when (label) {
                    "MEETS_STRONG_INTEGRITY"  -> GuardXColors.Safe    to "✓ STRONG"
                    "MEETS_DEVICE_INTEGRITY"  -> GuardXColors.Safe    to "✓ DEVICE"
                    "MEETS_VIRTUAL_INTEGRITY" -> GuardXColors.Warning to "⚠ VIRTUAL"
                    else                      -> GuardXColors.Warning to label
                }
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = labelColor.copy(.12f)
                ) {
                    Text(labelText,
                        Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = labelColor)
                }
            }
        }
    }

    // ── Uygulama bütünlüğü ───────────────────────────────────────
    SectionCard(title = "Uygulama Bütünlüğü", icon = Icons.Default.Apps) {
        IntegrityRow(
            label  = "Play Store Tanıma",
            passed = v.appRecognized,
            detail = when {
                v.appRecognized    -> "Orijinal Play Store imzası — değiştirilmemiş"
                v.appUnrecognized  -> "Bilinmeyen sürüm veya değiştirilmiş APK"
                else               -> "Play Store'da kayıtsız"
            }
        )
        if (v.appPackageName.isNotEmpty()) {
            LabelValue("Paket", v.appPackageName)
        }
        if (v.versionCode > 0) {
            LabelValue("Sürüm Kodu", v.versionCode.toString())
        }
        if (v.certDigests.isNotEmpty()) {
            LabelValue("İmza (SHA-256)", v.certDigests.first().take(16) + "…")
        }
    }

    // ── Lisans ──────────────────────────────────────────────────
    if (v.licensingVerdict.isNotEmpty() && v.licensingVerdict != "UNEVALUATED") {
        SectionCard(title = "Lisans Durumu", icon = Icons.Default.CardMembership) {
            val (licPassed, licDetail) = when (v.licensingVerdict) {
                "LICENSED"   -> true  to "Play Store üzerinden yasal olarak yüklendi"
                "UNLICENSED" -> false to "Lisanssız kurulum tespit edildi"
                else         -> false to "Lisans değerlendirilemedi"
            }
            IntegrityRow(
                label  = "Lisans",
                passed = licPassed,
                detail = licDetail
            )
        }
    }

    // ── Ham verdict label'ları ───────────────────────────────────
    if (v.environmentVerdict.isNotEmpty()) {
        SectionCard(title = "Ortam", icon = Icons.Default.Dns) {
            LabelValue("Ortam Durumu", v.environmentVerdict)
        }
    }

    // ── Butonlar ─────────────────────────────────────────────────
    OutlinedButton(
        onClick  = { vm.requestVerdict() },
        modifier = Modifier.fillMaxWidth(),
        shape    = RoundedCornerShape(50)
    ) {
        Icon(Icons.Default.Refresh, null, Modifier.size(16.dp))
        Spacer(Modifier.width(6.dp))
        Text("Yeniden Doğrula")
    }
}

// ── Yardımcı composable'lar ──────────────────────────────────────
@Composable
private fun SectionCard(
    title:   String,
    icon:    ImageVector,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        shape  = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment     = Alignment.CenterVertically
            ) {
                Icon(icon, null, Modifier.size(18.dp), tint = GuardXColors.Primary)
                Text(title, style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold)
            }
            Divider(color = MaterialTheme.colorScheme.outline.copy(.12f))
            content()
        }
    }
}

@Composable
private fun IntegrityRow(label: String, passed: Boolean, detail: String) {
    val color = if (passed) GuardXColors.Safe else GuardXColors.Danger
    val icon  = if (passed) Icons.Default.CheckCircle else Icons.Default.Cancel

    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment     = Alignment.Top
    ) {
        Icon(icon, null, Modifier.size(18.dp).padding(top = 2.dp), tint = color)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(label, style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium)
            Text(detail, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(.55f),
                lineHeight = 17.sp)
        }
    }
}

@Composable
private fun LabelValue(label: String, value: String) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface.copy(.5f))
        Text(value, style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurface.copy(.85f))
    }
}
