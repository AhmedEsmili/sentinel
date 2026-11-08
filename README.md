# Sentinel

Open-source, **100% on-device** Android security helper with two tools:

1. **Permission Auditor** – ranks installed apps by risk: dangerous permission combos, enabled
   accessibility services / notification listeners / device admins, sideloaded apps, and (optionally)
   sensitive apps not opened in 90+ days. One tap to the app's permission page or uninstall.
2. **Scam Checker** – paste a message or use *Share → Sentinel*. Explains each red flag in plain
   language: look-alike brand domains, homograph/punycode, shorteners, `user@host` tricks, urgency,
   gift-card/crypto payment, OTP/credential requests, secrecy, family impersonation, remote-access bait.

3. **Firewall + Fix Queue** – block any app's internet with one tap (a local black-hole VPN: only
   chosen apps are routed into it and every packet is dropped, so Sentinel still needs no INTERNET
   permission). The Fix Queue walks you through uninstalling, blocking or restricting each risky app.
4. **Device integrity** – hardware key attestation (verified boot, bootloader, patch level), lock,
   encryption, debugging, root/tamper signs, with shortcuts to the matching settings screens.

## Security design
- **No `INTERNET` permission** – verifiable in the manifest; nothing can be exfiltrated.
- `FLAG_SECURE` (no screenshots / recents thumbnail), `allowBackup=false`, cleartext disabled.
- Gated by **BiometricPrompt** (Class 3 biometric or device credential); re-locks when leaving the foreground.
- Targets **Android 15 (API 35)**, min **Android 13**; Kotlin 2, Jetpack Compose Material 3, R8-minified release.

## Limits
- Android won't let an app revoke other apps' permissions; Sentinel sends you to the system screen.
- The scam checker uses heuristics. "No flags" does not mean safe.
- `QUERY_ALL_PACKAGES` is needed to list all apps (fine for sideload/F-Droid; restricted on Google Play).

## Build
Open in Android Studio (Ladybug or newer), or:
`gradle wrapper --gradle-version 8.11.1 && ./gradlew testDebugUnitTest assembleDebug`

## Roadmap
On-device LLM (Gemini Nano / ML Kit GenAI) for context-aware scam judgement, notification scanning,
sensor-use alerts via AppOps, reproducible builds.
