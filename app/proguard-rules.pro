# GuardX ProGuard Kuralları

# ── JNI: native metodlar asla yeniden adlandırılmasın ─────────────
-keepclasseswithmembernames class * {
    native <methods>;
}

# ── NativeEngine ve callback arayüzleri ───────────────────────────
-keep class com.selinuxassistant.guardx.engine.** { *; }

# ── Veri modelleri (JSON parse için alan adları korunmalı) ─────────
-keep class com.selinuxassistant.guardx.model.** { *; }

# ── WorkManager worker sınıfı ─────────────────────────────────────
-keep class com.selinuxassistant.guardx.service.BackgroundScanWorker { *; }

# ── Compose runtime ───────────────────────────────────────────────
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# ── Genel ─────────────────────────────────────────────────────────
-keepattributes *Annotation*
-keepattributes SourceFile,LineNumberTable
