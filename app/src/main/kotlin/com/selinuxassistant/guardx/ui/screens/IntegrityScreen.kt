package com.selinuxassistant.guardx.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
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
import com.selinuxassistant.guardx.service.PlayIntegrityManager
import com.selinuxassistant.guardx.service.TeeAttestationManager
import com.selinuxassistant.guardx.ui.components.ScanPulse
import com.selinuxassistant.guardx.ui.theme.GuardXColors

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
                        Text("Cihaz Doğrulama", fontWeight = FontWeight.SemiBold)
                    }
                },
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
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            when (val s = state) {
                is IntegrityUiState.Idle    -> IdleView(vm)
                is IntegrityUiState.Loading -> LoadingView()
                is IntegrityUiState.Done    -> ResultView(s, vm)
            }
        }
    }
}

// ── Boşta ────────────────────────────────────────────────────────
@Composable
private fun IdleView(vm: IntegrityViewModel) {
    Card(
        shape  = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(
            Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    Modifier.size(48.dp).clip(CircleShape)
                        .background(GuardXColors.Primary.copy(.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Default.Security, null,
                        Modifier.size(26.dp), tint = GuardXColors.Primary)
                }
                Column {
                    Text("İki Katmanlı Doğrulama",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold)
                    Text("TEE + Google Play Integrity",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(.5f))
                }
            }

            Divider(color = MaterialTheme.colorScheme.outline.copy(.15f))

            // TEE katmanı
            LayerRow(
                icon   = Icons.Default.Hardware,
                color  = GuardXColors.Primary,
                title  = "TEE Donanım Kanıtlaması (Birincil)",
                detail = "AndroidKeyStore üzerinden çevrimdışı — API anahtarı gerekmez"
            )
            LayerRow(
                icon   = Icons.Default.Cloud,
                color  = GuardXColors.Secondary,
                title  = "Play Integrity (İkincil)",
                detail = "Google sunucuları üzerinden — internet gerektirir"
            )

            // Uyarı
            Surface(
                shape  = RoundedCornerShape(10.dp),
                color  = GuardXColors.Primary.copy(.07f),
                border = BorderStroke(1.dp, GuardXColors.Primary.copy(.2f))
            ) {
                Row(
                    Modifier.padding(12.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Default.Bolt, null,
                        Modifier.size(16.dp), tint = GuardXColors.Primary)
                    Text(
                        "TEE kanıtlaması her zaman çalışır. " +
                        "Play Integrity internet bağlantısı olmadan hata verebilir.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(.65f),
                        lineHeight = 18.sp
                    )
                }
            }

            Button(
                onClick  = { vm.startVerification() },
                modifier = Modifier.fillMaxWidth(),
                shape    = RoundedCornerShape(50)
            ) {
                Icon(Icons.Default.Shield, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Doğrulamayı Başlat")
            }
        }
    }
}

// ── Yükleniyor ───────────────────────────────────────────────────
@Composable
private fun LoadingView() {
    Column(
        Modifier.fillMaxWidth().padding(vertical = 40.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        ScanPulse(true, Modifier.size(130.dp))
        Text("Doğrulanıyor…",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold)
        LinearProgressIndicator(
            modifier    = Modifier.fillMaxWidth().height(4.dp),
            trackColor  = MaterialTheme.colorScheme.outline.copy(.2f)
        )
        Text("TEE → Play Integrity sırayla çalışıyor",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface.copy(.45f))
    }
}

// ── Sonuç ────────────────────────────────────────────────────────
@Composable
private fun ResultView(state: IntegrityUiState.Done, vm: IntegrityViewModel) {

    // ── Birleşik skor kartı ───────────────────────────────────────
    val combinedScore = state.combinedScore
    val scoreColor = when {
        combinedScore >= 80 -> GuardXColors.Safe
        combinedScore >= 50 -> GuardXColors.Warning
        else                -> GuardXColors.Danger
    }
    val scoreIcon = when {
        combinedScore >= 80 -> Icons.Default.VerifiedUser
        combinedScore >= 50 -> Icons.Default.GppMaybe
        else                -> Icons.Default.GppBad
    }

    Card(
        shape  = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(scoreColor.copy(.08f)),
        border = BorderStroke(1.dp, scoreColor.copy(.3f))
    ) {
        Column(
            Modifier.fillMaxWidth().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Box(
                Modifier.size(70.dp).clip(CircleShape)
                    .background(scoreColor.copy(.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(scoreIcon, null, Modifier.size(36.dp), tint = scoreColor)
            }
            Text(
                "Güven Skoru: $combinedScore / 100",
                style      = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color      = scoreColor
            )
            Text(
                when {
                    combinedScore >= 90 -> "Cihaz doğrulandı — yüksek güvence"
                    combinedScore >= 70 -> "Cihaz büyük ölçüde güvenli"
                    combinedScore >= 40 -> "Bazı kontroller başarısız — dikkat"
                    else                -> "Cihaz güvensiz veya değiştirilmiş"
                },
                style     = MaterialTheme.typography.bodyMedium,
                color     = MaterialTheme.colorScheme.onSurface.copy(.6f),
                textAlign = TextAlign.Center
            )
        }
    }

    // ── TEE Kanıtlama Bölümü ─────────────────────────────────────
    SectionCard(
        title = "TEE Donanım Kanıtlaması",
        icon  = Icons.Default.Hardware,
        badge = when (state.teeResult) {
            is TeeAttestationManager.TeeResult.Success ->
                if (state.teeResult.data.isHardwareBacked) "DONANIM" to GuardXColors.Safe
                else "YAZILIM" to GuardXColors.Warning
            is TeeAttestationManager.TeeResult.Error -> "HATA" to GuardXColors.Danger
        }
    ) {
        when (val tee = state.teeResult) {
            is TeeAttestationManager.TeeResult.Success -> {
                val d = tee.data

                CheckRow(
                    label  = "Donanım Desteği",
                    passed = d.isHardwareBacked,
                    detail = if (d.isHardwareBacked)
                        "Anahtar TEE/StrongBox içinde oluşturuldu"
                    else
                        "Anahtar yazılımda oluşturuldu (donanım desteği yok)"
                )
                CheckRow(
                    label  = "Güvenlik Seviyesi",
                    passed = d.securityLevel != TeeAttestationManager.SecurityLevel.SOFTWARE,
                    detail = d.securityLevel.label
                )
                CheckRow(
                    label  = "Doğrulanmış Önyükleme",
                    passed = d.verifiedBootState.isClean,
                    detail = d.verifiedBootState.label
                )
                CheckRow(
                    label  = "Bootloader",
                    passed = d.deviceLocked,
                    detail = if (d.deviceLocked)
                        "Kilitli ✓ (kaynak: ${d.bootStateSource})"
                    else
                        "AÇIK — değiştirilebilir sistem (kaynak: ${d.bootStateSource})"
                )
                if (d.certChainLength > 0) {
                    CheckRow(
                        label  = "Sertifika Zinciri",
                        passed = d.certChainLength >= 3,
                        detail = "${d.certChainLength} sertifika (Google CA'ya kadar)"
                    )
                }
                CheckRow(
                    label  = "Nonce Doğrulama",
                    passed = d.challengeVerified,
                    detail = if (d.challengeVerified)
                        "Challenge eşleşti — tekrar saldırısı yok"
                    else
                        "Challenge eşleşmedi"
                )
            }
            is TeeAttestationManager.TeeResult.Error -> {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.ErrorOutline, null,
                        Modifier.size(16.dp), tint = GuardXColors.Warning)
                    Text(
                        tee.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(.6f)
                    )
                }
            }
        }
    }

    // ── Play Integrity Bölümü ─────────────────────────────────────
    SectionCard(
        title = "Google Play Integrity",
        icon  = Icons.Default.Cloud,
        badge = when (val pi = state.playIntegrity) {
            null -> "ATLAYI" to MaterialTheme.colorScheme.outline
            is PlayIntegrityManager.IntegrityResult.Success ->
                if (pi.verdict.meetsDeviceIntegrity) "GEÇTI" to GuardXColors.Safe
                else "BAŞARISIZ" to GuardXColors.Danger
            is PlayIntegrityManager.IntegrityResult.Error -> "HATA" to GuardXColors.Warning
        }
    ) {
        when (val pi = state.playIntegrity) {
            null -> {
                Text(
                    "Play Integrity bu çalışmada atlandı.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(.5f)
                )
            }
            is PlayIntegrityManager.IntegrityResult.Success -> {
                val v = pi.verdict
                CheckRow(
                    label  = "Cihaz Bütünlüğü",
                    passed = v.meetsDeviceIntegrity,
                    detail = if (v.meetsDeviceIntegrity)
                        "Gerçek Android donanımı, TrustZone aktif"
                    else
                        "Emülatör, rootlu veya değiştirilmiş sistem"
                )
                CheckRow(
                    label  = "Güçlü Donanım Kanıtı",
                    passed = v.meetsStrongIntegrity,
                    detail = if (v.meetsStrongIntegrity)
                        "Play Protect sertifikalı cihaz"
                    else
                        "Güçlü donanım kanıtı yok"
                )
                CheckRow(
                    label  = "Uygulama Tanıma",
                    passed = v.appRecognized,
                    detail = if (v.appRecognized)
                        "Play Store kayıtlı, orijinal imza"
                    else
                        "Bilinmeyen sürüm veya değiştirilmiş APK"
                )
                if (v.meetsVirtualIntegrity) {
                    CheckRow(
                        label  = "Sanal Ortam",
                        passed = false,
                        detail = "Emülatör veya CI ortamı tespit edildi"
                    )
                }
                if (v.licensingVerdict != "UNEVALUATED") {
                    CheckRow(
                        label  = "Lisans",
                        passed = v.licensingVerdict == "LICENSED",
                        detail = when (v.licensingVerdict) {
                            "LICENSED"   -> "Play Store üzerinden yasal kurulum"
                            "UNLICENSED" -> "Lisanssız kurulum"
                            else         -> v.licensingVerdict
                        }
                    )
                }
                // Verdict label'ları
                if (v.deviceLabels.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        v.deviceLabels.forEach { label ->
                            val (col, txt) = when (label) {
                                "MEETS_STRONG_INTEGRITY"  -> GuardXColors.Safe    to "STRONG"
                                "MEETS_DEVICE_INTEGRITY"  -> GuardXColors.Safe    to "DEVICE"
                                "MEETS_VIRTUAL_INTEGRITY" -> GuardXColors.Warning to "VIRTUAL"
                                else                      -> GuardXColors.Warning to label.take(10)
                            }
                            Surface(shape = RoundedCornerShape(4.dp), color = col.copy(.12f)) {
                                Text(txt,
                                    Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = col)
                            }
                        }
                    }
                }
            }
            is PlayIntegrityManager.IntegrityResult.Error -> {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.WifiOff, null,
                        Modifier.size(16.dp), tint = GuardXColors.Warning)
                    Text(
                        pi.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(.6f)
                    )
                }
                Text(
                    "TEE kanıtlaması başarıyla tamamlandı. " +
                    "Play Integrity sonuçsuz kalsa da TEE sonucu güvenilirdir.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(.45f),
                    lineHeight = 17.sp
                )
            }
        }
    }

    // ── Yeniden tara ────────────────────────────────────────────
    OutlinedButton(
        onClick  = { vm.startVerification() },
        modifier = Modifier.fillMaxWidth(),
        shape    = RoundedCornerShape(50)
    ) {
        Icon(Icons.Default.Refresh, null, Modifier.size(16.dp))
        Spacer(Modifier.width(6.dp))
        Text("Yeniden Doğrula")
    }
}

// ── Yardımcı Composable'lar ──────────────────────────────────────
@Composable
private fun LayerRow(icon: ImageVector, color: Color, title: String, detail: String) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment     = Alignment.Top
    ) {
        Icon(icon, null, Modifier.size(18.dp).padding(top = 2.dp), tint = color)
        Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
            Text(title, style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium)
            Text(detail, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(.5f))
        }
    }
}

@Composable
private fun SectionCard(
    title   : String,
    icon    : ImageVector,
    badge   : Pair<String, Color>,
    content : @Composable ColumnScope.() -> Unit
) {
    Card(
        shape  = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment     = Alignment.CenterVertically
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment     = Alignment.CenterVertically
                ) {
                    Icon(icon, null, Modifier.size(18.dp), tint = GuardXColors.Primary)
                    Text(title, style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold)
                }
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = badge.second.copy(.15f)
                ) {
                    Text(
                        badge.first,
                        Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = badge.second
                    )
                }
            }
            Divider(color = MaterialTheme.colorScheme.outline.copy(.12f))
            content()
        }
    }
}

@Composable
private fun CheckRow(label: String, passed: Boolean, detail: String) {
    val color = if (passed) GuardXColors.Safe else GuardXColors.Danger
    val icon  = if (passed) Icons.Default.CheckCircle else Icons.Default.Cancel
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment     = Alignment.Top
    ) {
        Icon(icon, null, Modifier.size(16.dp).padding(top = 2.dp), tint = color)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
            Text(label, style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium)
            Text(detail, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(.5f),
                lineHeight = 16.sp)
        }
    }
}
