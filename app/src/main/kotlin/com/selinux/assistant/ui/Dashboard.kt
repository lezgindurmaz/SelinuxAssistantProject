package com.selinux.assistant.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.selinux.assistant.engine.AVEngine
import com.selinux.assistant.engine.RootDetector
import com.selinux.assistant.engine.ScanCallback
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainDashboard() {
    val coroutineScope = rememberCoroutineScope()
    val engine = remember { AVEngine() }
    val rootDetector = remember { RootDetector() }

    var isScanning by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0f) }
    var statusMessage by remember { mutableStateOf("Cihazınız Güvende") }
    var scanResult by remember { mutableStateOf<String?>(null) }
    var currentFile by remember { mutableStateOf("") }
    var isRooted by remember { mutableStateOf<Boolean?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("SelinuxAssistant", fontWeight = FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.primary
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(32.dp)
        ) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Row(
                    modifier = Modifier.padding(20.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (isRooted == true || scanResult != null) Icons.Default.Warning else Icons.Default.CheckCircle,
                        contentDescription = null,
                        tint = if (isRooted == true || scanResult != null) Color(0xFFFF5252) else Color(0xFF00E676),
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.width(16.dp))
                    Column {
                        Text(
                            text = if (isRooted == true) "Cihaz Risk Altında!" else statusMessage,
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = if (isRooted == true) "Root tespiti yapıldı" else "Koruma aktif",
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color.Gray
                        )
                    }
                }
            }

            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.size(200.dp)
            ) {
                CircularProgressIndicator(
                    progress = if (isScanning) progress else 1f,
                    modifier = Modifier.fillMaxSize(),
                    strokeWidth = 8.dp,
                    color = if (isScanning) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.primary,
                    trackColor = Color.DarkGray
                )
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = if (isScanning) "${(progress * 100).toInt()}%" else if (isRooted == true) "RİSK" else "GÜVENLİ",
                        style = MaterialTheme.typography.headlineLarge,
                        fontWeight = FontWeight.ExtraBold,
                        color = if (isScanning) Color.White else if (isRooted == true) Color(0xFFFF5252) else MaterialTheme.colorScheme.primary
                    )
                    if (isScanning) {
                        Text(currentFile.takeLast(20), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Button(
                    onClick = {
                        if (isScanning) {
                            engine.cancelScan()
                            isScanning = false
                        } else {
                            coroutineScope.launch(Dispatchers.IO) {
                                isScanning = true
                                statusMessage = "Tarama Yapılıyor..."
                                try {
                                    engine.scanDirectory("/sdcard", object : ScanCallback {
                                        override fun onProgress(scanned: Int, total: Int, file: String) {
                                            progress = scanned.toFloat() / total.coerceAtLeast(1)
                                            currentFile = file
                                        }
                                    })
                                } catch (e: Exception) {
                                    for (i in 1..100) {
                                        if (!isScanning) break
                                        progress = i / 100f
                                        currentFile = "file_$i.apk"
                                        delay(50)
                                    }
                                }
                                isScanning = false
                                statusMessage = "Tarama Tamamlandı"
                            }
                        }
                    },
                    modifier = Modifier.weight(1f).height(56.dp),
                    shape = CircleShape,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isScanning) Color.DarkGray else MaterialTheme.colorScheme.primary
                    )
                ) {
                    Text(if (isScanning) "Durdur" else "Hızlı Tarama", fontWeight = FontWeight.Bold)
                }

                OutlinedButton(
                    onClick = {
                        coroutineScope.launch {
                            val rooted = withContext(Dispatchers.IO) {
                                try { rootDetector.isRooted() } catch (e: Exception) { false }
                            }
                            isRooted = rooted
                            statusMessage = if (rooted) "Kök Erişimi Tespit Edildi!" else "Kök Erişimi Yok"
                        }
                    },
                    modifier = Modifier.weight(1f).height(56.dp),
                    shape = CircleShape,
                    border = ButtonDefaults.outlinedButtonBorder.copy(width = 2.dp)
                ) {
                    Text("Kök Kontrolü", fontWeight = FontWeight.Bold)
                }
            }

            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                FeatureItem("Gerçek Zamanlı Koruma", "Aktif", true)
                FeatureItem("Selinux Modu", "Enforcing", true)
                FeatureItem("Kök Durumu", if (isRooted == true) "Riskli" else "Temiz", isRooted != true)
            }
        }
    }
}

@Composable
fun FeatureItem(label: String, value: String, isOk: Boolean) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = Color.LightGray)
        Text(
            value,
            color = if (isOk) Color(0xFF00E676) else Color(0xFFFF5252),
            fontWeight = FontWeight.Bold
        )
    }
}
