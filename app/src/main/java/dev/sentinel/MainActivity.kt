package dev.sentinel

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.sentinel.ui.LockScreen
import dev.sentinel.ui.SentinelApp

class MainActivity : FragmentActivity() {
    private var unlocked by mutableStateOf(false)
    private var sharedText by mutableStateOf<String?>(null)
    private var prompting = false
    private val authenticators = BIOMETRIC_STRONG or DEVICE_CREDENTIAL

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Block screenshots, screen recording and the recents thumbnail.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        sharedText = extractShared(intent)
        setContent {
            val ctx = LocalContext.current
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)) {
                if (unlocked) SentinelApp(sharedText) else LockScreen(::authenticate)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        sharedText = extractShared(intent)
    }

    override fun onStart() { super.onStart(); if (!unlocked) authenticate() }

    // Re-lock whenever the app leaves the foreground.
    override fun onStop() { super.onStop(); unlocked = false }

    private fun extractShared(i: Intent?): String? =
        if (i?.action == Intent.ACTION_SEND && i.type == "text/plain") i.getStringExtra(Intent.EXTRA_TEXT) else null

    private fun authenticate() {
        if (prompting) return
        if (BiometricManager.from(this).canAuthenticate(authenticators) != BiometricManager.BIOMETRIC_SUCCESS) {
            unlocked = true // no lock screen set up on this device: nothing to gate on
            return
        }
        prompting = true
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) { prompting = false; unlocked = true }
            override fun onAuthenticationError(code: Int, msg: CharSequence) { prompting = false }
        })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock Sentinel")
                .setAllowedAuthenticators(authenticators)
                .build()
        )
    }
}
