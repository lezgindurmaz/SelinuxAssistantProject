package com.selinuxassistant.guardx.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// ── Renk Paleti ───────────────────────────────────────────────────
object GuardXColors {
    // Marka renkleri
    val Primary      = Color(0xFF0EA5E9)   // Gökyüzü mavisi
    val PrimaryDark  = Color(0xFF0284C7)
    val Secondary    = Color(0xFF06B6D4)

    // Durum renkleri
    val Safe         = Color(0xFF22C55E)
    val Warning      = Color(0xFFF59E0B)
    val Danger       = Color(0xFFEF4444)
    val Critical     = Color(0xFF7C3AED)

    // Zemin
    val DarkBg       = Color(0xFF0A0F1C)
    val DarkSurface  = Color(0xFF111827)
    val DarkCard     = Color(0xFF1F2937)
    val DarkBorder   = Color(0xFF374151)

    val LightBg      = Color(0xFFF8FAFC)
    val LightSurface = Color(0xFFFFFFFF)
    val LightCard    = Color(0xFFF1F5F9)

    // Semantik UI renkleri (koyu tema)
    val Surface         = Color(0xFF111827)
    val SurfaceVariant  = Color(0xFF1F2937)
    val Border          = Color(0xFF374151)
    val TextPrimary     = Color(0xFFE2E8F0)
    val TextSecondary   = Color(0xFF94A3B8)
}

private val DarkColorScheme = darkColorScheme(
    primary          = GuardXColors.Primary,
    onPrimary        = Color.White,
    primaryContainer = GuardXColors.PrimaryDark,
    secondary        = GuardXColors.Secondary,
    background       = GuardXColors.DarkBg,
    surface          = GuardXColors.DarkSurface,
    surfaceVariant   = GuardXColors.DarkCard,
    onBackground     = Color.White,
    onSurface        = Color(0xFFE2E8F0),
    outline          = GuardXColors.DarkBorder,
    error            = GuardXColors.Danger,
)

private val LightColorScheme = lightColorScheme(
    primary          = GuardXColors.PrimaryDark,
    onPrimary        = Color.White,
    secondary        = GuardXColors.Secondary,
    background       = GuardXColors.LightBg,
    surface          = GuardXColors.LightSurface,
    surfaceVariant   = GuardXColors.LightCard,
    onBackground     = Color(0xFF0F172A),
    onSurface        = Color(0xFF1E293B),
    outline          = Color(0xFFCBD5E1),
    error            = GuardXColors.Danger,
)

val GuardXTypography = Typography(
    headlineLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Bold,
        fontSize = 28.sp, lineHeight = 34.sp
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp, lineHeight = 28.sp
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 18.sp
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium,
        fontSize = 15.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal,
        fontSize = 15.sp, lineHeight = 22.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal,
        fontSize = 13.sp, lineHeight = 20.sp
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium,
        fontSize = 11.sp
    )
)

@Composable
fun GuardXTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colors = if (darkTheme) DarkColorScheme else LightColorScheme
    MaterialTheme(
        colorScheme = colors,
        typography  = GuardXTypography,
        content     = content
    )
}
