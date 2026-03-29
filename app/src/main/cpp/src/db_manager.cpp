// ══════════════════════════════════════════════════════════════════
//  DbManager — Assets'ten imza DB kopyalama + delta update
//
//  JNI fonksiyonu:
//    dbInit(assetMgr, filesDir) → Boolean
//    dbGetVersion()             → String
//    dbGetCount()               → Long
//    dbApplyDelta(deltaPath)    → Int  (eklenen kayıt sayısı)
// ══════════════════════════════════════════════════════════════════
#include "local_db.h"
#include <jni.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <memory>
#include <string>

#define LOG_TAG "GX_DBMgr"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char* ASSET_NAME    = "signatures.bin";
static const char* DB_FILENAME   = "signatures.bin";
static const char* DELTA_DIRNAME = "sig_deltas";

static std::unique_ptr<AntiVirus::LocalDB> g_db;
static std::string                          g_files_dir;

// ── Asset'ten dosyaya kopyala ─────────────────────────────────────
static bool copy_asset_to_file(AAssetManager* amgr,
                                const char* asset_name,
                                const char* dest_path)
{
    AAsset* asset = AAssetManager_open(amgr, asset_name, AASSET_MODE_STREAMING);
    if (!asset) { LOGE("Asset açılamadı: %s", asset_name); return false; }

    FILE* out = fopen(dest_path, "wb");
    if (!out) {
        AAsset_close(asset);
        LOGE("Hedef dosya açılamadı: %s", dest_path);
        return false;
    }

    char buf[65536];
    int  read;
    while ((read = AAsset_read(asset, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, read, out);
    }
    fclose(out);
    AAsset_close(asset);
    return true;
}

// ── Asset ve hedef dosya boyutlarını karşılaştır ──────────────────
static bool asset_newer_than_file(AAssetManager* amgr,
                                   const char* asset_name,
                                   const char* file_path)
{
    AAsset* asset = AAssetManager_open(amgr, asset_name, AASSET_MODE_UNKNOWN);
    if (!asset) return false;

    off_t asset_size = AAsset_getLength(asset);
    AAsset_close(asset);

    struct stat st;
    if (stat(file_path, &st) != 0) return true;   // dosya yok → kopyala
    return asset_size > st.st_size;                // asset daha büyük → güncelle
}

// ── JNI: dbInit ──────────────────────────────────────────────────
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_dbInit(
    JNIEnv*  env,
    jobject  /*thiz*/,
    jobject  jasset_mgr,
    jstring  jfiles_dir)
{
    const char* files_dir = env->GetStringUTFChars(jfiles_dir, nullptr);
    g_files_dir = files_dir;
    env->ReleaseStringUTFChars(jfiles_dir, files_dir);

    std::string db_path = g_files_dir + "/" + DB_FILENAME;

    AAssetManager* amgr = AAssetManager_fromJava(env, jasset_mgr);
    if (!amgr) { LOGE("AAssetManager alınamadı"); return JNI_FALSE; }

    // Assets'teki versiyon mevcut dosyadan büyükse kopyala
    if (asset_newer_than_file(amgr, ASSET_NAME, db_path.c_str())) {
        LOGI("Asset daha yeni — kopyalanıyor: %s", db_path.c_str());
        if (!copy_asset_to_file(amgr, ASSET_NAME, db_path.c_str())) {
            LOGE("Kopyalama başarısız");
            // Var olan dosyayı kullanmaya devam et
        }
    }

    // DB'yi aç
    auto db = std::make_unique<AntiVirus::LocalDB>(db_path);
    bool ok = db->open();
    LOGI("DB init: %s, %zu imza", ok ? "OK" : "FAIL", db->getSignatureCount());
    AntiVirus::LocalDB::setGlobalInstance(std::move(db));
    return ok ? JNI_TRUE : JNI_FALSE;
}

// ── JNI: dbGetVersion ────────────────────────────────────────────
extern "C"
JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_dbGetVersion(
    JNIEnv* env, jobject /*thiz*/)
{
    auto* db = AntiVirus::LocalDB::getGlobalInstance();
    std::string ver = db ? db->getDBVersion() : "0.0.0";
    return env->NewStringUTF(ver.c_str());
}

// ── JNI: dbGetCount ──────────────────────────────────────────────
extern "C"
JNIEXPORT jlong JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_dbGetCount(
    JNIEnv* /*env*/, jobject /*thiz*/)
{
    auto* db = AntiVirus::LocalDB::getGlobalInstance();
    return db ? static_cast<jlong>(db->getSignatureCount()) : 0L;
}

// ── JNI: dbApplyDelta ────────────────────────────────────────────
// delta_path: indirilen JSON delta dosyasının tam yolu
extern "C"
JNIEXPORT jint JNICALL
Java_com_selinuxassistant_guardx_engine_NativeEngine_dbApplyDelta(
    JNIEnv* env, jobject /*thiz*/, jstring jdelta_path)
{
    auto* db = AntiVirus::LocalDB::getGlobalInstance();
    if (!db || !db->isOpen()) return -1;

    const char* delta_path = env->GetStringUTFChars(jdelta_path, nullptr);
    bool ok = db->importSignatures(delta_path);
    env->ReleaseStringUTFChars(jdelta_path, delta_path);

    if (!ok) return -1;
    return static_cast<jint>(db->getSignatureCount());
}
