package com.selinuxassistant.guardx.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.*
import com.selinuxassistant.guardx.model.ThreatLevel
import com.selinuxassistant.guardx.ui.theme.GuardXColors

// ── Güvenlik skoru animasyonlu gauge ─────────────────────────────
@Composable
fun SecurityGauge(score: Int, modifier: Modifier = Modifier) {
    val animScore by animateIntAsState(
        targetValue = score,
        animationSpec = tween(1200, easing = EaseOutCubic),
        label = "gauge"
    )
    val color = when {
        score >= 80 -> GuardXColors.Safe
        score >= 50 -> GuardXColors.Warning
        else        -> GuardXColors.Danger
    }
    val sweepAngle by animateFloatAsState(
        targetValue = (animScore / 100f) * 240f,
        animationSpec = tween(1200, easing = EaseOutCubic),
        label = "sweep"
    )

    Box(modifier, contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(180.dp)) {
            val strokeWidth = 18.dp.toPx()
            val inset = strokeWidth / 2
            // Arka plan arc
            drawArc(
                color = Color.White.copy(alpha = 0.08f),
                startAngle = 150f, sweepAngle = 240f,
                useCenter = false,
                topLeft = Offset(inset, inset),
                size = androidx.compose.ui.geometry.Size(size.width - strokeWidth, size.height - strokeWidth),
                style = androidx.compose.ui.graphics.drawscope.Stroke(strokeWidth, cap = StrokeCap.Round)
            )
            // Dolgu arc
            drawArc(
                brush = Brush.sweepGradient(
                    listOf(color.copy(alpha = 0.4f), color),
                    center = center
                ),
                startAngle = 150f, sweepAngle = sweepAngle,
                useCenter = false,
                topLeft = Offset(inset, inset),
                size = androidx.compose.ui.geometry.Size(size.width - strokeWidth, size.height - strokeWidth),
                style = androidx.compose.ui.graphics.drawscope.Stroke(strokeWidth, cap = StrokeCap.Round)
            )
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text("$animScore", style = MaterialTheme.typography.headlineLarge,
                 fontWeight = FontWeight.Bold, color = color)
            Text("/ 100", style = MaterialTheme.typography.bodyMedium,
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
        }
    }
}

// ── Tehdit seviyesi chip'i ────────────────────────────────────────
@Composable
fun ThreatChip(level: ThreatLevel, modifier: Modifier = Modifier) {
    val color = Color(android.graphics.Color.parseColor(level.colorHex))
    val icon  = when (level) {
        ThreatLevel.CLEAN      -> Icons.Default.CheckCircle
        ThreatLevel.SUSPICIOUS -> Icons.Default.Warning
        ThreatLevel.MALWARE    -> Icons.Default.BugReport
        ThreatLevel.CRITICAL   -> Icons.Default.GppBad
    }
    Surface(
        modifier  = modifier,
        shape     = RoundedCornerShape(50),
        color     = color.copy(alpha = 0.15f),
        border    = BorderStroke(1.dp, color.copy(alpha = 0.4f))
    ) {
        Row(Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            Icon(icon, null, Modifier.size(14.dp), tint = color)
            Text(level.label, style = MaterialTheme.typography.labelSmall,
                 fontWeight = FontWeight.SemiBold, color = color)
        }
    }
}

// ── İstatistik kartı ──────────────────────────────────────────────
@Composable
fun StatCard(
    title:    String,
    value:    String,
    icon:     ImageVector,
    color:    Color,
    modifier: Modifier = Modifier
) {
    Card(modifier = modifier, shape = RoundedCornerShape(16.dp),
         colors = CardDefaults.cardColors(
             containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(Modifier.size(36.dp).clip(CircleShape)
                .background(color.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center) {
                Icon(icon, null, Modifier.size(20.dp), tint = color)
            }
            Text(value, style = MaterialTheme.typography.headlineMedium,
                 fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
            Text(title, style = MaterialTheme.typography.bodyMedium,
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
        }
    }
}

// ── Tarama bulgu satırı ───────────────────────────────────────────
@Composable
fun FindingRow(
    title:    String,
    subtitle: String,
    level:    ThreatLevel,
    onClick:  () -> Unit = {}
) {
    val color = Color(android.graphics.Color.parseColor(level.colorHex))
    Surface(
        onClick = onClick,
        shape   = RoundedCornerShape(12.dp),
        color   = MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(color))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyMedium,
                     fontWeight = FontWeight.Medium, maxLines = 1,
                     overflow = TextOverflow.Ellipsis)
                Text(subtitle, style = MaterialTheme.typography.bodyMedium,
                     color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f),
                     maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            ThreatChip(level)
        }
    }
}

// ── Animasyonlu tarama dalgası ────────────────────────────────────
@Composable
fun ScanPulse(isScanning: Boolean, modifier: Modifier = Modifier) {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val scale by infiniteTransition.animateFloat(
        initialValue = 0.8f, targetValue = 1.2f,
        animationSpec = infiniteRepeatable(tween(900, easing = EaseInOut),
                                           RepeatMode.Reverse),
        label = "scale"
    )
    val alpha by infiniteTransition.animateFloat(
        initialValue = 0.3f, targetValue = 0.8f,
        animationSpec = infiniteRepeatable(tween(900, easing = EaseInOut),
                                           RepeatMode.Reverse),
        label = "alpha"
    )

    if (!isScanning) return

    Box(modifier, contentAlignment = Alignment.Center) {
        Box(Modifier.size((80 * scale).dp)
            .clip(CircleShape)
            .background(GuardXColors.Primary.copy(alpha = alpha * 0.2f)))
        Box(Modifier.size((60 * scale).dp)
            .clip(CircleShape)
            .background(GuardXColors.Primary.copy(alpha = alpha * 0.3f)))
        Box(Modifier.size(44.dp).clip(CircleShape)
            .background(GuardXColors.Primary),
            contentAlignment = Alignment.Center) {
            Icon(Icons.Default.Shield, null, Modifier.size(24.dp), tint = Color.White)
        }
    }
}

// ── İzin risk satırı ─────────────────────────────────────────────
@Composable
fun PermissionRow(name: String, risk: Int, description: String) {
    val (color, label) = when (risk) {
        4    -> GuardXColors.Critical to "Kritik"
        3    -> GuardXColors.Danger   to "Yüksek"
        2    -> GuardXColors.Warning  to "Orta"
        1    -> GuardXColors.Safe     to "Düşük"
        else -> Color(0xFF64748B)     to "Zararsız"
    }
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Box(Modifier.size(6.dp).clip(CircleShape).background(color).padding(top = 6.dp))
        Column(Modifier.weight(1f)) {
            Text(name.substringAfterLast('.'),
                 style = MaterialTheme.typography.bodyMedium,
                 fontWeight = FontWeight.Medium,
                 color = MaterialTheme.colorScheme.onSurface)
            if (description.isNotEmpty())
                Text(description, style = MaterialTheme.typography.labelSmall,
                     color = MaterialTheme.colorScheme.onSurface.copy(0.5f))
        }
        Surface(shape = RoundedCornerShape(50), color = color.copy(0.12f)) {
            Text(label, Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                 style = MaterialTheme.typography.labelSmall,
                 fontWeight = FontWeight.SemiBold, color = color)
        }
    }
}

// ── Skaler çubuk ─────────────────────────────────────────────────
@Composable
fun ScoreBar(label: String, score: Int, color: Color, modifier: Modifier = Modifier) {
    val width by animateFloatAsState(
        targetValue = score / 100f,
        animationSpec = tween(800, easing = EaseOutCubic),
        label = "bar"
    )
    Column(modifier, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, style = MaterialTheme.typography.bodyMedium,
                 color = MaterialTheme.colorScheme.onSurface.copy(0.7f))
            Text("$score", style = MaterialTheme.typography.bodyMedium,
                 fontWeight = FontWeight.SemiBold, color = color)
        }
        Box(Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(50))
            .background(MaterialTheme.colorScheme.outline.copy(0.2f))) {
            Box(Modifier.fillMaxWidth(width).fillMaxHeight()
                .clip(RoundedCornerShape(50)).background(
                    Brush.horizontalGradient(listOf(color.copy(0.7f), color))
                ))
        }
    }
}
