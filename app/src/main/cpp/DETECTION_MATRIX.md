# Root & Hook Tespit — Ağırlık Matrisi

Bu tablo, hangi kanıtın kaç puan taşıdığını ve neden false-positive riski
düşük tutulduğunu açıklar.

## Karar Eşikleri
| Karar          | Puan Eşiği |
|----------------|-----------|
| ROOTED         | ≥ 7       |
| HOOKED         | ≥ 6       |
| RISK: LOW      | 1–4       |
| RISK: MEDIUM   | 5–6       |
| RISK: HIGH     | ≥ 7       |
| RISK: CRITICAL | ROOT + HOOK birlikte |

---

## Kanıt Ağırlık Tablosu

### Root Kanıtları
| Kanıt                              | Ağırlık | False-Positive Riski |
|------------------------------------|---------|----------------------|
| su binary (çalıştırılabilir)       | 9       | Çok düşük            |
| su binary (sadece var)             | 6       | Düşük                |
| magisk binary                      | 10      | Yok                  |
| Magisk yolları (/data/adb/magisk)  | 9       | Yok                  |
| /system rw mount                   | 8       | Çok düşük            |
| /system/xbin yazılabilir           | 9       | Yok                  |
| ro.build.tags ≠ release-keys       | 6       | Düşük (GSI)          |
| ro.debuggable=1                    | 5 (2*)  | Orta* (dev cihaz)    |
| ro.build.type=userdebug            | 4 (1*)  | Yüksek* (geliştirici)|
| ro.secure=0                        | 5       | Düşük                |
| Bootloader orange/unlocked         | 8       | Düşük                |
| AVB disabled (cmdline)             | 9       | Çok düşük            |
| dm-verity kapalı                   | 9       | Çok düşük            |
| Kernel tainted bit0                | 8       | Orta                 |
| Kernel tainted bit12 (imzasız)     | 9       | Düşük                |
| SELinux permissive                 | 9       | Çok düşük            |
| /proc/kallsyms gerçek adres        | 8       | Düşük                |
| Seccomp=0                          | 8       | Çok düşük            |
| tmpfs overlay şüphesi              | 7       | Orta                 |
| Root paket (/data/app)             | 8       | Çok düşük            |

*tolerateDeveloperDevice=true ise ağırlık düşürülür

### Hook Kanıtları
| Kanıt                              | Ağırlık | False-Positive Riski |
|------------------------------------|---------|----------------------|
| Frida port 27042 açık + banner     | 9       | Yok                  |
| Frida maps'de                      | 10      | Yok                  |
| Frida dosyaları                    | 9       | Yok                  |
| Xposed dosyaları                   | 9       | Yok                  |
| ro.xposed.version                  | 10      | Yok                  |
| Zygisk maps'de                     | 10      | Yok                  |
| TracerPid ≠ 0                      | 10      | Çok düşük            |
| ptrace EPERM                       | 9       | Çok düşük            |
| Timing anomali (>100ms)            | 5       | Orta                 |
| Şüpheli .so maps'de                | 8       | Düşük                |
| /data/local/tmp'den .so            | 7       | Orta                 |
| Şüpheli fd hedefi                  | 9       | Düşük                |
| /proc/net/unix Magisk socket       | 9       | Yok                  |

---

## False-Positive Önleme Stratejileri

1. **Ağırlıklı puanlama**: Tek bir zayıf kanıt hiçbir zaman yeterli değil.
   Örneğin sadece `ro.debuggable=1` = 2 puan (eşik 7), alarm vermez.

2. **tolerateDeveloperDevice**: Geliştirici modunu aktif eden cihazlarda
   debug prop ağırlıkları düşürülür.

3. **Çift kaynak doğrulama**: Bootloader için 5 farklı kaynak kontrol edilir.
   Hepsinin aynı sonucu vermesi gerekir (OR değil, toplam puan).

4. **Sembolik link farkındalığı**: `lstat()` kullanılarak link mi yoksa
   gerçek dosya mı olduğu ayrıştırılır.

5. **Kernel taint hassasiyeti**: Tüm taint değil, sadece 0x1 ve 0x1000
   bitleri agresif sayılır. Staging driver biti (0x2000) sayılmaz.

---

## Kontrol Sırası ve Performans

| Kontrol               | Süre (yaklaşık) | Öncelik |
|-----------------------|-----------------|---------|
| Build Properties      | < 1ms           | 1       |
| Root Binaries         | 5–15ms          | 2       |
| Root Packages         | 10–30ms         | 3       |
| Mount Points          | 2–5ms           | 4       |
| Bootloader            | < 2ms           | 5       |
| SELinux               | < 1ms           | 6       |
| Frida                 | 200–600ms*      | 7       |
| Xposed                | 5–10ms          | 8       |
| Magisk                | 3–8ms           | 9       |
| Memory Maps           | 5–20ms          | 10      |
| File Descriptors      | 5–15ms          | 11      |
| Ptrace                | 100–200ms**     | 12      |
| Kernel Integrity      | 5–20ms          | 13      |
| Kernel Modules        | 5–15ms          | 14      |
| Seccomp               | < 1ms           | 15      |

*Frida: 3 ayrı porta 200ms bağlantı denemesi
**Ptrace: timing testi 100ms bekler

**Toplam quickScan:** ~400–800ms
**Toplam fullScan:**  ~600–1200ms
