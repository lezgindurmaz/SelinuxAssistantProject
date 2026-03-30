package com.selinuxassistant.guardx

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.selinuxassistant.guardx.ui.screens.*
import com.selinuxassistant.guardx.ui.theme.GuardXTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)
        setContent {
            GuardXTheme {
                GuardXNavHost()
            }
        }
    }
}

@Composable
fun GuardXNavHost() {
    val nav = rememberNavController()

    NavHost(navController = nav, startDestination = "dashboard") {

        composable("dashboard") {
            DashboardScreen(onNavigate = { route -> nav.navigate(route) })
        }

        composable("file_scan") {
            FileScanScreen(onBack = { nav.popBackStack() })
        }

        composable("apk_scan") {
            ApkScanScreen(onBack = { nav.popBackStack() })
        }

        composable("root_check") {
            RootCheckScreen(onBack = { nav.popBackStack() })
        }

        composable("behavior") {
            BehaviorScreen(onBack = { nav.popBackStack() })
        }

        composable("integrity") {
            IntegrityScreen(onBack = { nav.popBackStack() })
        }

        composable("settings") {
            SettingsScreen(onBack = { nav.popBackStack() })
        }
    }
}
