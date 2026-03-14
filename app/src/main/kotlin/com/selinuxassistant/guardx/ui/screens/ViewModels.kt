package com.selinuxassistant.guardx.ui.screens

import android.app.Application
import androidx.lifecycle.*
import com.selinuxassistant.guardx.GuardXApp
import com.selinuxassistant.guardx.engine.NativeEngine
import com.selinuxassistant.guardx.model.*
import com.selinuxassistant.guardx.service.ScanRepository
import com.selinuxassistant.guardx.service.SecurityState
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import com.selinuxassistant.guardx.model.RootReport
import com.selinuxassistant.guardx.model.ApkReport
import com.selinuxassistant.guardx.model.BehaviorReport

// ══════════════════════════════════════════════════════════════════
//  Dashboard ViewModel
// ══════════════════════════════════════════════════════════════════
class DashboardViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = (app as GuardXApp).repository

    val rootReport = SecurityState.rootReport
    val securityScore = MutableStateFlow(0)

    private val _isChecking = MutableStateFlow(false)
    val isChecking: StateFlow<Boolean> = _isChecking

    fun quickCheck() {
        viewModelScope.launch {
            _isChecking.value = true
            val report = runCatching { repo.rootQuickScan() }.getOrNull()
            report?.let { SecurityState.updateRoot(it) }
            updateScore()
            _isChecking.value = false
        }
    }

    fun updateScore() {
        securityScore.value = SecurityState.calculateOverallScore()
    }

    init {
        quickCheck()
        viewModelScope.launch {
            combine(
                SecurityState.rootReport,
                SecurityState.lastApkReports,
                SecurityState.lastBehaviorReport
            ) { r: RootReport?, a: List<ApkReport>, b: BehaviorReport? ->
                SecurityState.calculateOverallScore()
            }.collect { score ->
                securityScore.value = score
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  File Scan ViewModel
// ══════════════════════════════════════════════════════════════════
sealed class ScanUiState {
    object Idle : ScanUiState()
    data class Scanning(val scanned: Int, val total: Int, val current: String) : ScanUiState()
    data class Done(val stats: ScanStats) : ScanUiState()
    data class Error(val msg: String) : ScanUiState()
}

class FileScanViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = (app as GuardXApp).repository

    private val _state = MutableStateFlow<ScanUiState>(ScanUiState.Idle)
    val state: StateFlow<ScanUiState> = _state

    val storagePaths: List<String> get() = repo.storagePaths()

    fun scanPath(path: String) {
        viewModelScope.launch {
            _state.value = ScanUiState.Scanning(0, 0, "Hazırlanıyor…")
            repo.scanDirectory(path) { s, t, f ->
                _state.value = ScanUiState.Scanning(s, t, f)
            }.catch { e ->
                _state.value = ScanUiState.Error(e.message ?: "Hata")
            }.collect { stats ->
                _state.value = ScanUiState.Done(stats)
            }
        }
    }

    fun cancel() { repo.cancelScan(); _state.value = ScanUiState.Idle }
    fun reset()  { _state.value = ScanUiState.Idle }
}

// ══════════════════════════════════════════════════════════════════
//  APK Scan ViewModel
// ══════════════════════════════════════════════════════════════════
sealed class ApkScanState {
    object Idle : ApkScanState()
    data class Scanning(val pkg: String, val done: Int, val total: Int) : ApkScanState()
    data class Done(val reports: List<ApkReport>) : ApkScanState()
    data class SingleDone(val report: ApkReport) : ApkScanState()
    data class Error(val msg: String) : ApkScanState()
}

class ApkScanViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = (app as GuardXApp).repository

    private val _state = MutableStateFlow<ApkScanState>(ApkScanState.Idle)
    val state: StateFlow<ApkScanState> = _state

    fun scanAllApps() {
        viewModelScope.launch {
            _state.value = ApkScanState.Scanning("", 0, 0)
            repo.scanInstalledApps { done, total, pkg ->
                _state.value = ApkScanState.Scanning(pkg, done, total)
            }.catch { e ->
                _state.value = ApkScanState.Error(e.message ?: "Hata")
            }.collect { reports ->
                SecurityState.updateApks(reports)
                val sorted = reports.sortedByDescending { it.overallScore }
                _state.value = ApkScanState.Done(sorted)
            }
        }
    }

    fun analyzeApkFile(path: String) {
        viewModelScope.launch {
            _state.value = ApkScanState.Scanning(path, 0, 1)
            runCatching { repo.analyzeApk(path) }
                .onSuccess { _state.value = ApkScanState.SingleDone(it) }
                .onFailure { _state.value = ApkScanState.Error(it.message ?: "Hata") }
        }
    }

    fun reset() { _state.value = ApkScanState.Idle }
}

// ══════════════════════════════════════════════════════════════════
//  Root Check ViewModel
// ══════════════════════════════════════════════════════════════════
sealed class RootCheckState {
    object Idle : RootCheckState()
    object Scanning : RootCheckState()
    data class Done(val report: RootReport) : RootCheckState()
    data class Error(val msg: String) : RootCheckState()
}

class RootCheckViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = (app as GuardXApp).repository

    private val _state = MutableStateFlow<RootCheckState>(RootCheckState.Idle)
    val state: StateFlow<RootCheckState> = _state

    fun quickScan() { scan(deep = false) }
    fun deepScan()  { scan(deep = true)  }

    private fun scan(deep: Boolean) {
        viewModelScope.launch {
            _state.value = RootCheckState.Scanning
            runCatching {
                if (deep) repo.rootFullScan(true) else repo.rootQuickScan()
            }.onSuccess {
                SecurityState.updateRoot(it)
                _state.value = RootCheckState.Done(it)
            }.onFailure { _state.value = RootCheckState.Error(it.message ?: "Hata") }
        }
    }
}

// ══════════════════════════════════════════════════════════════════
//  Behavior Monitor ViewModel
// ══════════════════════════════════════════════════════════════════
sealed class BehaviorState {
    object Idle : BehaviorState()
    data class Scanning(val elapsed: Int, val duration: Int) : BehaviorState()
    data class Done(val report: BehaviorReport) : BehaviorState()
    data class Error(val msg: String) : BehaviorState()
}

class BehaviorViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = (app as GuardXApp).repository

    private val _state = MutableStateFlow<BehaviorState>(BehaviorState.Idle)
    val state: StateFlow<BehaviorState> = _state

    fun startScan(durationMs: Int = 5000) {
        viewModelScope.launch {
            _state.value = BehaviorState.Scanning(0, durationMs)

            val startTime = System.currentTimeMillis()

            // We use supervisorScope to ensure ticker and repo scan are independent but manageable
            supervisorScope {
                val ticker = launch {
                    while (isActive) {
                        val elapsed = (System.currentTimeMillis() - startTime).toInt()
                        if (elapsed >= durationMs) {
                            _state.value = BehaviorState.Scanning(durationMs, durationMs)
                            break
                        }
                        _state.value = BehaviorState.Scanning(elapsed, durationMs)
                        delay(250) // Reduce update frequency for stability
                    }
                }

                val result = runCatching {
                    // Native call is blocking, it should respect durationMs internally
                    repo.scanProcesses(durationMs)
                }

                ticker.cancel()

                result.onSuccess {
                    // Ensure the final state reflects the full duration
                    _state.value = BehaviorState.Scanning(durationMs, durationMs)
                    delay(100)
                    SecurityState.updateBehavior(it)
                    _state.value = BehaviorState.Done(it)
                }.onFailure {
                    _state.value = BehaviorState.Error(it.message ?: "Hata")
                }
            }
        }
    }

    fun reset() { _state.value = BehaviorState.Idle }
}

// ── Settings ViewModel ──────────────────────────────────────────────────────
class SettingsViewModel(application: android.app.Application) :
    AndroidViewModel(application) {

    private val _sigCount = MutableStateFlow(0L)
    val sigCount: StateFlow<Long> = _sigCount.asStateFlow()

    private val _dbVersion = MutableStateFlow("–")
    val dbVersion: StateFlow<String> = _dbVersion.asStateFlow()

    private val _isUpdating = MutableStateFlow(false)
    val isUpdating: StateFlow<Boolean> = _isUpdating.asStateFlow()

    init { refreshDbStats() }

    fun refreshDbStats() {
        viewModelScope.launch(Dispatchers.IO) {
            _sigCount.value  = NativeEngine.dbGetCount()
            _dbVersion.value = NativeEngine.dbGetVersion()
        }
    }

    fun applyDelta(deltaPath: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _isUpdating.value = true
            val newCount = NativeEngine.dbApplyDelta(deltaPath)
            if (newCount > 0) {
                _sigCount.value  = NativeEngine.dbGetCount()
                _dbVersion.value = NativeEngine.dbGetVersion()
            }
            _isUpdating.value = false
        }
    }
}
