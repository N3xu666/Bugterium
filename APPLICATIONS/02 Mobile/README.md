# Mobile

Mobile application security reference. Covers Android and iOS attack surfaces, testing methodology, and defensive controls.

Writeups and references in this category follow the two-track format (Pentest / AppSec) where applicable.

> [!CAUTION]
> Authorized use only. All material is provided for educational purposes and authorized testing.<br>
> See [../../SECURITY.md](../../SECURITY.md) for the full policy.
## Table of Contents

| # | Section | Description |
|---|---------|-------------|
| - | [Quick Reference](#quick-reference) | Common ports, tools, and one-liners for mobile |
| - | [Decision Tree](#decision-tree) | Choose the right path based on the artifact (APK/IPA) |
| 1 | [Mobile Security Fundamentals](./01%20Mobile%20Security%20Fundamentals.md) | Architecture, threat modeling, shared attack vectors |
| 2 | [OWASP Mobile Top 10](./02%20OWASP%20Mobile%20Top%2010.md) | 2024 list (M1-M10) with 2016 mapping and MASVS categories |
| 3 | [Android Security](./03%20Android%20Security.md) | APK structure, manifest, exported components, WebView, Frida hooks |
| 4 | [iOS Security](./04%20iOS%20Security.md) | IPA structure, Mach-O, Keychain, Data Protection, jailbreak detection |
| 5 | [Mobile Defense and Testing](./05%20Mobile%20Defense%20and%20Testing.md) | MASTG/MASVS methodology, MobSF, supply chain (M2), privacy (M6) |

---

## Quick Reference

### Common Ports

| Port | Common Use |
|------|------------|
| 5555 | ADB over TCP (Android Debug Bridge) |
| 27042 | Frida default port (frida-server) |
| 8080 | mitmproxy / Burp Suite proxy |
| 8000 | MobSF web UI |
| 1337 | Common Metasploit / custom C2 port |
| 8443 | HTTPS alt (custom APIs) |

### Tools

| Tool | Purpose |
|------|---------|
| `adb` | Android Debug Bridge: install, shell, logcat, backup |
| `frida` | Runtime hooking (Android/iOS) |
| `objection` | Frida-based exploration without writing scripts |
| `jadx` | Decompile Android DEX to Java |
| `apktool` | Decode/rebuild Android APK (smali, manifest) |
| `class-dump` | Dump Objective-C headers from iOS binaries |
| `frida-ios-dump` | Decrypt iOS app from memory (jailbroken) |
| `MobSF` | Automated static + dynamic analysis (APK/IPA) |
| `mitmproxy` | Traffic interception with user CA |
| `Burp Suite` | Traffic interception, scanner |
| `keychain_dumper` | Dump iOS Keychain (jailbroken) |
| `ideviceinstaller` | Install/manage iOS apps from Linux/macOS |

### One-liners

```bash
# Android: install and launch
adb install app.apk
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1

# Android: decompile
apktool d app.apk -o app-decoded
jadx -d app-jadx app.apk

# iOS: unzip and inspect
unzip app.ipa -d app-decoded
plutil -p app-decoded/Payload/App.app/Info.plist

# Frida: spawn and attach
frida -U -f com.example.app -l script.js --no-pause

# MobSF: upload and scan (API)
curl -F "file=@app.apk" http://localhost:8000/api/v1/upload -H "Authorization: <KEY>"
```

---

## Decision Tree

When you receive a mobile app artifact, follow this tree.

```text
Artifact received (APK / IPA)
|
+-- Android (APK)
|   |
|   +-- Static: apktool d app.apk
|   |   +-- Check AndroidManifest.xml (exported, debuggable, allowBackup)
|   |   +-- Check network_security_config.xml (cleartext, pinning)
|   |
|   +-- Static: jadx -d out app.apk
|   |   +-- Search for hardcoded secrets (api_key, token, password)
|   |   +-- Check WebView settings, JS bridges
|   |
|   +-- Dynamic: adb install app.apk
|       +-- adb shell am start -n com.example/.Activity
|       +-- Frida: hook root detection, SSL pinning
|       +-- adb logcat | grep com.example
|
+-- iOS (IPA)
    |
    +-- Static: unzip app.ipa
    |   +-- plutil -p Info.plist (URL schemes, ATS)
    |   +-- codesign -d --entitlements (get-task-allow, keychain groups)
    |   +-- class-dump / Hopper (if decrypted)
    |
    +-- Dynamic: (jailbroken or Corellium)
        +-- frida-ios-dump -u com.example -o out.ipa
        +-- Frida: hook jailbreak detection, SSL pinning
        +-- Keychain dump (keychain_dumper)
```

---

## Workflow

1. **Scope** - list the apps, versions, and backend APIs.
2. **Static** - manifest/plist, permissions, exported components, hardcoded secrets, pinning, ATS/cleartext, debuggable flag.
3. **Dynamic** - install, launch, browse all screens, capture traffic, exercise deep links and IPC.
4. **Abuse** - try exported components, content providers, WebView bridges, deep links, jailbreak/root detection bypass, pinning bypass.
5. **Backend** - test the API directly (auth, IDOR, rate limiting, token lifetime).
6. **Report** - per MASVS category, with severity and evidence.

## References

- OWASP Mobile Top 10 - https://owasp.org/www-project-mobile-top-10/
- OWASP MASVS - https://mas.owasp.org/MASVS/
- OWASP MASTG - https://mas.owasp.org/MASTG/
- Android Security Documentation - https://source.android.com/docs/security
- iOS Security Guide - https://support.apple.com/guide/security/welcome/web

---

## Related Sections

- [../01 Web/](../01%20Web/) - browser-facing web application security (CSRF, XSS, SQLi).
- [../03 API/](../03%20API/) - machine-facing API security (REST, GraphQL, Auth).
- [../../CHEATSHEET.md](../../CHEATSHEET.md) - general pentest commands.
- [../../METHODOLOGY.md](../../METHODOLOGY.md) - engagement workflow.
- [../../methodology/OSCP-Reporting.md](../../methodology/OSCP-Reporting.md) - exam reporting.

---

*Last updated: 2026-10-24. Part of Bugterium. English only by design.*