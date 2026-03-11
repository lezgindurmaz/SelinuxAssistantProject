package com.selinux.assistant.engine

interface ScanCallback {
    fun onProgress(scanned: Int, total: Int, currentFile: String)
}

class AVEngine {
    companion object {
        init {
            System.loadLibrary("selinux_assistant")
        }
    }

    external fun scanFile(path: String): String
    external fun hashFile(path: String): String
    external fun scanDirectory(path: String, callback: ScanCallback): String
    external fun cancelScan()
}
