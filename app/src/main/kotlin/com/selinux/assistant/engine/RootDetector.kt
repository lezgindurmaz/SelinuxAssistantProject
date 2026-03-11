package com.selinux.assistant.engine

class RootDetector {
    companion object {
        init {
            System.loadLibrary("selinux_assistant")
        }
    }

    external fun fullScan(deepKernel: Boolean, tolerateDev: Boolean): String
    external fun quickScan(): String
    external fun isRooted(): Boolean
    external fun isBootloaderUnlocked(): Boolean
}
