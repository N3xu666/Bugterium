# ============================================================
# FINAL AUDIT v3 - Bugterium
# ============================================================
# Changes vs v2:
#   - No hardcoded "45 walkthroughs" - counts dynamically.
#   - New section [21]: language pairs per category.
#   - New section [22]: summary (N machines x 3 languages).
#   - All other checks unchanged.
#
# Stub detection (twelfth pass):
#   Files whose first 15 lines contain a "Status: **Completed**" marker
#   (any language: En/Ru/Az) are treated as stubs (active machines)
#   and excluded from walkthrough structure/Attack Chain/Note checks
#   and from machine counts.
#   The txt/ directory (drafts, .gitignore) is excluded from all scans.
# ============================================================

param(
    [switch]$SkipLocalChecks
)

cd $PSScriptRoot

# Stub markers (active machines - placeholder files)
$stubMarkers = @(
    'Status: Completed',      # En
    'Status: **Completed**',  # En (bold)
    'Status: Пройдено',        # Ru (English prefix)
    'Статус: Пройдено',        # Ru (native prefix)
    'Статус: **Завершено**',      # Ru (bold)
    'Status: Tamamlandı',      # Az
    'Status: **Tamamlandı**'        # Az (bold)
)

function Test-StubFile([string]$filePath) {
    try {
        $head = Get-Content -Path $filePath -TotalCount 15 -ErrorAction Stop
        foreach ($line in $head) {
            foreach ($marker in $stubMarkers) {
                if ($line -like "*$marker*") { return $true }
            }
        }
    } catch {
        return $false
    }
    return $false
}

$utf8 = [System.Text.Encoding]::UTF8
$script:pass = 0
$script:fail = 0
$script:warn = 0

function Write-Pass($msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green; $script:pass++ }
function Write-Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red; $script:fail++ }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow; $script:warn++ }
function Write-Info($msg) { Write-Host "  $msg" -ForegroundColor Gray }

# P1.2: git exit code tracking
$script:gitErrors = 0

function Invoke-GitSafe {
    param(
        [string[]]$GitArgs,
        [string]$Context = "",
        [int[]]$AllowedExitCodes = @(0)
    )
    $output = & git @GitArgs 2>&1
    $code = $LASTEXITCODE
    if ($code -notin $AllowedExitCodes) {
        $script:gitErrors++
        $ctx = if ($Context) { " [$Context]" } else { "" }
        Write-Warn "git $($GitArgs -join ' ')$ctx failed (exit=$code)"
    }
    return $output
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "     FINAL AUDIT v3 - Bugterium" -ForegroundColor Cyan
Write-Host "     $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. GIT STATE
Write-Host "`n[1] Git state" -ForegroundColor Yellow
$gitBefore = $script:gitErrors
$status = Invoke-GitSafe -GitArgs @("status", "--short") -Context "status"
if ($script:gitErrors -gt $gitBefore) { Write-Fail "git status failed - cannot determine working tree state" } elseif (-not $status -or ($status | Out-String).Trim() -eq "") { Write-Pass "working tree clean" } else { Write-Warn "working tree has changes (may be expected)" }
Write-Info "last 5 commits:"
git log -5 --oneline | ForEach-Object { Write-Info "    $_" }
$remote = Invoke-GitSafe -GitArgs @("remote", "get-url", "origin") -Context "remote" -AllowedExitCodes @(0, 2, 128)
if ($remote) { Write-Pass "remote: $remote" } else { Write-Warn "no remote origin (local-only mode)" }
$local = Invoke-GitSafe -GitArgs @("rev-parse", "HEAD") -Context "rev-parse HEAD"
$remoteSha = Invoke-GitSafe -GitArgs @("rev-parse", "origin/main") -Context "rev-parse origin/main" -AllowedExitCodes @(0, 128)
if ($local -and $remoteSha -and $local -eq $remoteSha) { Write-Pass "local == origin/main (pushed)" } elseif (-not $remoteSha) { Write-Warn "origin/main not found (local-only mode)" } else { Write-Warn "local != origin/main (ahead or behind)" }
if ($script:gitErrors -gt 0) { Write-Fail "$($script:gitErrors) git command(s) failed in section [1]" }

# 2. FILES IN ROOT
Write-Host "`n[2] Files in root" -ForegroundColor Yellow
Get-ChildItem -Force | Where-Object { $_.Name -ne '.git' } | Select-Object Name, Length | Format-Table -AutoSize

# 3. GITIGNORE
Write-Host "[3] .gitignore" -ForegroundColor Yellow
$gitignoreContent = Get-Content ".gitignore" -ErrorAction SilentlyContinue
if ($gitignoreContent) { Write-Pass ".gitignore exists" } else { Write-Fail ".gitignore missing" }
$mustIgnore = @('masking-dict.ps1', 'MASTER_WORKFLOW.md', 'update-readmes.ps1', '_SITE_PLAN.md', 'txt/')
foreach ($f in $mustIgnore) {
    $gitBefore3 = $script:gitErrors
    $checkPath = if ($f -eq 'txt/') { "WRITEUPS/01 Hack The Box/02 OSCP/01 Linux/txt/ru/01 Sea.txt" } else { $f }
    $ignored = Invoke-GitSafe -GitArgs @("check-ignore", $checkPath) -Context "check-ignore $checkPath" -AllowedExitCodes @(0, 1)
    if ($script:gitErrors -gt $gitBefore3) { Write-Warn "$f - git check-ignore failed (exit != 0/1)" } elseif ($ignored) { Write-Pass "$f is ignored" } else { Write-Fail "$f NOT ignored" }
}

# 4. TRACKED FILES
Write-Host "`n[4] Tracked files" -ForegroundColor Yellow
$gitBefore4 = $script:gitErrors
$trackedMd = Invoke-GitSafe -GitArgs @("ls-files", "*.md") -Context "ls-files md"
if ($script:gitErrors -gt $gitBefore4) { Write-Fail "git ls-files *.md failed" } else { Write-Pass "tracked .md: $($trackedMd.Count)" }
$trackedPs1 = Invoke-GitSafe -GitArgs @("ls-files", "*.ps1") -Context "ls-files ps1"
Write-Info "tracked .ps1 ($($trackedPs1.Count)):"
$trackedPs1 | ForEach-Object { Write-Info "    $_" }
$gitBefore4b = $script:gitErrors
$trackedTxt = Invoke-GitSafe -GitArgs @("ls-files", "*.txt") -Context "ls-files txt"
$txtWhitelist = @("tools/python/tests/requirements.txt")
$nonWhitelisted = @($trackedTxt | Where-Object { $txtWhitelist -notcontains $_ })
if ($script:gitErrors -gt $gitBefore4b) { Write-Fail "git ls-files *.txt failed" } elseif ($trackedTxt.Count -eq 0) { Write-Pass "0 tracked .txt" } elseif ($nonWhitelisted.Count -eq 0) { Write-Pass "$($trackedTxt.Count) tracked .txt (all whitelisted)" } else { Write-Warn "$($trackedTxt.Count) tracked .txt (not whitelisted: $($nonWhitelisted -join ", "))" }

# 5. UNTRACKED FILES
Write-Host "`n[5] Untracked files" -ForegroundColor Yellow
if ($SkipLocalChecks) {
    Write-Info "skipped (--SkipLocalChecks)"
} else {
    $gitBefore5 = $script:gitErrors
$untracked = Invoke-GitSafe -GitArgs @("ls-files", "--others", "--exclude-standard") -Context "ls-files --others"
if ($script:gitErrors -gt $gitBefore5) { Write-Fail "git ls-files --others failed" } elseif (-not $untracked) { Write-Pass "no untracked files" } else { Write-Warn "untracked files:"; $untracked | ForEach-Object { Write-Info "    $_" } }
}

# 6. WALKTHROUGHS (DYNAMIC COUNT)
Write-Host "`n[6] Walkthroughs" -ForegroundColor Yellow
$walkthroughs = Get-ChildItem -Recurse -Filter *.md -Path "WRITEUPS/01 Hack The Box" | Where-Object {
    $_.FullName -match '\\0[123] (Az|En|Ru)\\' -and
    -not (Test-StubFile $_.FullName)
}
Write-Info "found $($walkthroughs.Count) walkthrough files"
if ($walkthroughs.Count % 3 -eq 0) {
    $machineCount = $walkthroughs.Count / 3
    Write-Pass "$($walkthroughs.Count) walkthroughs = $machineCount machines x 3 languages"
} else {
    Write-Fail "$($walkthroughs.Count) walkthroughs is NOT divisible by 3"
}

# 7. WALKTHROUGH STRUCTURE
Write-Host "`n[7] Walkthrough structure" -ForegroundColor Yellow
$badStructure = @()
foreach ($wt in $walkthroughs) {
    $c = [System.IO.File]::ReadAllText($wt.FullName, $utf8)
    $hasHeader = $c -match '(?m)^#\s+.+\s+\(HTB\)'
    $hasBlockquote = ([regex]::Matches($c, '(?m)^>\s*\S+:').Count) -ge 3
    if (-not ($hasHeader -and $hasBlockquote)) { $badStructure += $wt.Name }
}
if ($badStructure.Count -eq 0) { Write-Pass "all walkthroughs have valid headers" } else { Write-Fail "walkthroughs with broken headers:"; $badStructure | ForEach-Object { Write-Info "    $_" } }

# 8. ATTACK CHAIN
Write-Host "`n[8] Attack Chain" -ForegroundColor Yellow
$noAttackChain = @()
foreach ($wt in $walkthroughs) {
    $c = [System.IO.File]::ReadAllText($wt.FullName, $utf8)
    if (-not ($c -match '(?m)^##\s+(Attack Chain|Hücum Zənciri|Цепочка Атаки)')) { $noAttackChain += $wt.Name }
}
if ($noAttackChain.Count -eq 0) { Write-Pass "all walkthroughs have Attack Chain" } else { Write-Fail "missing Attack Chain:"; $noAttackChain | ForEach-Object { Write-Info "    $_" } }

# 9. NOTE PLACEMENT
Write-Host "`n[9] Ethical note placement" -ForegroundColor Yellow
$badNote = @()
$noteText = '(All flags, passwords, hashes, and session tokens have been masked for ethical reasons|Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям|Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir)'
foreach ($wt in $walkthroughs) {
    $c = [System.IO.File]::ReadAllText($wt.FullName, $utf8)
    if ($c -notmatch $noteText) { $badNote += "$($wt.Name) - MISSING"; continue }
    $pattern = '(?s)(```text.*?```)\s*(>\s*\[!NOTE\][^\r\n]*\r?\n>\s*[^\r\n]+)\s*\r?\n\s*---'
    if ($c -notmatch $pattern) { $badNote += "$($wt.Name) - wrong position" }
}
if ($badNote.Count -eq 0) { Write-Pass "all walkthroughs: Note right after Attack Chain" } else { Write-Fail "Note issues:"; $badNote | ForEach-Object { Write-Info "    $_" } }

# 10. REAL 32-HEX FLAGS
Write-Host "`n[10] Real 32-hex flags (case-insensitive)" -ForegroundColor Yellow
$flagCount = 0
Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\app\\' -and $_.Name -ne 'MASTER_WORKFLOW.md' -and $_.Name -ne 'APP_WORKFLOW.md' -and $_.Name -ne '_SITE_PLAN.md' -and $_.Name -ne 'SESSION_CLOSING_PROTOCOL.md' } | ForEach-Object {
    $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $flagCount += [regex]::Matches($c, "\b[a-fA-F0-9]{32}\b").Count
}
if ($flagCount -eq 0) { Write-Pass "0 real flags" } else { Write-Fail "$flagCount real flags" }

# 11. LEAKS FROM DICT
Write-Host "`n[11] Leaks from masking-dict.ps1" -ForegroundColor Yellow
if (Test-Path "masking-dict.ps1") {
    Remove-Variable replacements -ErrorAction SilentlyContinue
    . .\masking-dict.ps1 | Out-Null
    Write-Pass "masking-dict.ps1 loaded: $($replacements.Count) entries"
    $leaks = @()
    foreach ($key in $replacements.Keys) {
        if ($key -match '^<.*>$') { continue }
        if ($key -match '^[a-fA-F0-9]{32}$') { continue }
        $count = 0
        Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\app\\' -and $_.Name -ne 'MASTER_WORKFLOW.md' -and $_.Name -ne 'APP_WORKFLOW.md' -and $_.Name -ne '_SITE_PLAN.md' -and $_.Name -ne 'SESSION_CLOSING_PROTOCOL.md' } | ForEach-Object {
            $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
            $count += ([regex]::Matches($c, [regex]::Escape($key))).Count
        }
        if ($count -gt 0) { $leaks += "LEAK: '$key' x$count" }
    }
    if ($leaks.Count -eq 0) { Write-Pass "0 leaks" } else { Write-Fail "$($leaks.Count) leaks:"; $leaks | ForEach-Object { Write-Info "    $_" } }
} else { Write-Fail "masking-dict.ps1 missing" }

# 12. LONG DASHES / BROKEN CHARS
Write-Host "`n[12] Long dashes / broken chars" -ForegroundColor Yellow
$d = 0; $b = 0
Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\app\\' -and $_.Name -ne 'MASTER_WORKFLOW.md' -and $_.Name -ne 'APP_WORKFLOW.md' -and $_.Name -ne '_SITE_PLAN.md' -and $_.Name -ne 'SESSION_CLOSING_PROTOCOL.md' } | ForEach-Object {
    $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $d += [regex]::Matches($c, "[\u2013\u2014\u2212]").Count
    $b += [regex]::Matches($c, "[\uFFFD]").Count
}
if ($d -eq 0) { Write-Pass "0 long dashes" } else { Write-Fail "$d long dashes" }
if ($b -eq 0) { Write-Pass "0 broken chars" } else { Write-Fail "$b broken chars" }

# 13. MASKING ARTIFACTS
Write-Host "`n[13] Masking artifacts" -ForegroundColor Yellow
$artifacts = @('<PASSWORD>blog', '<PASSWORD>.htb', '<USER_FLAG>FLAG', '<ROOT_FLAG>FLAG', '<PASSWORD><PASSWORD>')
$a = 0
foreach ($art in $artifacts) {
    $count = 0
    Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\app\\' -and $_.Name -ne 'MASTER_WORKFLOW.md' -and $_.Name -ne 'APP_WORKFLOW.md' -and $_.Name -ne '_SITE_PLAN.md' -and $_.Name -ne 'SESSION_CLOSING_PROTOCOL.md' } | ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $count += ([regex]::Matches($c, [regex]::Escape($art))).Count
    }
    if ($count -gt 0) { Write-Fail "artifact '$art' x$count"; $a += $count }
}
if ($a -eq 0) { Write-Pass "0 artifacts" }

# 14. PLACEHOLDERS USAGE
Write-Host "`n[14] Placeholders usage" -ForegroundColor Yellow
$placeholders = @('<USER_FLAG>', '<ROOT_FLAG>', '<PASSWORD>', '<BCRYPT_HASH>', '<MYSQL_HASH>', '<SHA256_HASH>', '<TOKEN>', '<SESSION_ID>')
foreach ($ph in $placeholders) {
    $count = 0
    Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\app\\' -and $_.Name -ne 'MASTER_WORKFLOW.md' -and $_.Name -ne 'APP_WORKFLOW.md' -and $_.Name -ne '_SITE_PLAN.md' -and $_.Name -ne 'SESSION_CLOSING_PROTOCOL.md' } | ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $count += ([regex]::Matches($c, [regex]::Escape($ph))).Count
    }
    if ($count -gt 0) { Write-Pass "$ph used x$count" } else { Write-Warn "$ph not used" }
}

# 15. DOCUMENTATION
Write-Host "`n[15] Documentation" -ForegroundColor Yellow
if (Test-Path "CHEATSHEET.md") {
    $cs = [System.IO.File]::ReadAllText((Join-Path (Get-Location) "CHEATSHEET.md"), $utf8)
    $sections = [regex]::Matches($cs, '(?m)^##\s+\d+\.\s').Count
    if ($sections -ge 10) { Write-Pass "CHEATSHEET.md has $sections sections" } else { Write-Warn "CHEATSHEET.md has only $sections sections" }
} else { Write-Fail "CHEATSHEET.md missing" }
if (Test-Path "METHODOLOGY.md") {
    $mt = [System.IO.File]::ReadAllText((Join-Path (Get-Location) "METHODOLOGY.md"), $utf8)
    $phases = [regex]::Matches($mt, '(?m)^##\s+Phase').Count
    if ($phases -ge 5) { Write-Pass "METHODOLOGY.md has $phases phases" } else { Write-Warn "METHODOLOGY.md has only $phases phases" }
} else { Write-Fail "METHODOLOGY.md missing" }
if (Test-Path "methodology/OSCP-Reporting.md") {
    $or = [System.IO.File]::ReadAllText((Join-Path (Get-Location) "methodology/OSCP-Reporting.md"), $utf8)
    $oscpSections = [regex]::Matches($or, '(?m)^##\s+\d+\.\s').Count
    if ($oscpSections -ge 4) { Write-Pass "methodology/OSCP-Reporting.md has $oscpSections sections" } else { Write-Warn "OSCP-Reporting.md has only $oscpSections sections" }
} else { Write-Warn "methodology/OSCP-Reporting.md missing (optional)" }

# 16. SCRIPTS
Write-Host "`n[16] Scripts" -ForegroundColor Yellow
if (Test-Path "mask.ps1") { Write-Pass "mask.ps1 exists" } else { Write-Fail "mask.ps1 missing" }
if (Test-Path "check.ps1") { Write-Pass "check.ps1 exists" } else { Write-Fail "check.ps1 missing" }
if (Test-Path "masking-dict.ps1") { Write-Pass "masking-dict.ps1 exists" } else { Write-Fail "masking-dict.ps1 missing" }
if (Test-Path "MASTER_WORKFLOW.md") { Write-Pass "MASTER_WORKFLOW.md exists" } else { Write-Warn "MASTER_WORKFLOW.md missing" }
if (Test-Path "update-readmes.ps1") { Write-Pass "update-readmes.ps1 exists" } else { Write-Warn "update-readmes.ps1 missing" }
if (Test-Path "mask.ps1") {
    $m = Get-Content "mask.ps1" -Raw
    if ($m -match 'masking-dict\.ps1') { Write-Pass "mask.ps1 references masking-dict.ps1" } else { Write-Fail "mask.ps1 does not reference dict" }
    if ($m -match 'gizlədilmişdir') { Write-Pass "mask.ps1 recognizes Az Note" } else { Write-Warn "mask.ps1 does not recognize Az Note" }
}
if (Test-Path "check.ps1") {
    $chk = Get-Content "check.ps1" -Raw
    if ($chk -match '\[a-fA-F0-9\]') { Write-Pass "check.ps1 uses [a-fA-F0-9]" } else { Write-Fail "check.ps1 does not use [a-fA-F0-9]" }
    if ($chk -match '_WORKFLOW\.md') { Write-Pass "check.ps1 excludes MASTER_WORKFLOW.md" } else { Write-Warn "check.ps1 does not exclude MASTER_WORKFLOW.md" }
}

# 17. PRE-COMMIT HOOK
Write-Host "`n[17] Pre-commit hook" -ForegroundColor Yellow
if ($SkipLocalChecks) {
    Write-Info "skipped (--SkipLocalChecks)"
} else {
    if (Test-Path ".git\hooks\pre-commit") {
    $hook = Get-Content ".git\hooks\pre-commit" -Raw
    if ($hook -match 'check\.ps1') { Write-Pass "hook runs check.ps1" } else { Write-Fail "hook does not run check.ps1" }
    if ($hook -match 'exit 1') { Write-Pass "hook can block commit" } else { Write-Warn "hook does not block commit" }
    } else { Write-Warn "pre-commit hook missing (local-only mode)" }
}

# 18. ENCODING (UTF-8 BOM)
Write-Host "`n[18] Encoding (UTF-8 BOM)" -ForegroundColor Yellow
$bomIssues = @()
Get-ChildItem -Recurse -Filter *.md | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\app\\' -and $_.Name -ne 'MASTER_WORKFLOW.md' -and $_.Name -ne 'APP_WORKFLOW.md' -and $_.Name -ne '_SITE_PLAN.md' -and $_.Name -ne 'SESSION_CLOSING_PROTOCOL.md' } | ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    if ($bytes.Length -lt 3 -or $bytes[0] -ne 0xEF -or $bytes[1] -ne 0xBB -or $bytes[2] -ne 0xBF) { $bomIssues += ($_.FullName.Replace((Get-Location).Path + '\', '')) }
}
if ($bomIssues.Count -eq 0) { Write-Pass "all .md files have UTF-8 BOM" } else { Write-Warn "$($bomIssues.Count) .md files missing BOM:"; $bomIssues | Select-Object -First 5 | ForEach-Object { Write-Info "    $_" } }

# 19. LOCAL vs ORIGIN FILE LIST
Write-Host "`n[19] Local vs origin/main file list" -ForegroundColor Yellow
if ($SkipLocalChecks) {
    Write-Info "skipped (--SkipLocalChecks)"
} else {
    $localFiles = Invoke-GitSafe -GitArgs @("ls-files") -Context "ls-files" | Sort-Object
    $remoteFiles = Invoke-GitSafe -GitArgs @("ls-tree", "-r", "--name-only", "origin/main") -Context "ls-tree origin/main" -AllowedExitCodes @(0, 128) | Sort-Object

    if ($null -eq $remoteFiles -or $remoteFiles.Count -eq 0) {
        Write-Warn "origin/main not found or empty (local-only mode)"
    } else {
        $diff = Compare-Object $localFiles $remoteFiles
        if (-not $diff) { Write-Pass "local and origin/main track the same files" } else { Write-Warn "file list differs (may be expected if ahead of origin)"; $diff | Select-Object -First 10 | ForEach-Object { Write-Info "    $($_.SideIndicator) $($_.InputObject)" } }
    }
}

# 20. LANGUAGE PAIRS PER CATEGORY
Write-Host "`n[20] Language pairs per category" -ForegroundColor Yellow
$categories = Get-ChildItem -Path "WRITEUPS/01 Hack The Box" -Directory -Recurse | Where-Object {
    (Test-Path (Join-Path $_.FullName "01 Az")) -and
    (Test-Path (Join-Path $_.FullName "02 En")) -and
    (Test-Path (Join-Path $_.FullName "03 Ru"))
}
Write-Info "categories with 01 Az/02 En/03 Ru: $($categories.Count)"
foreach ($cat in $categories) {
    $azKeys = @()
    $enKeys = @()
    $ruKeys = @()
    foreach ($f in Get-ChildItem (Join-Path $cat.FullName "01 Az") -Filter *.md -EA SilentlyContinue) {
        if (-not (Test-StubFile $f.FullName) -and $f.Name -match '^(\d+)\s+([A-Za-z0-9_]+)\s+\(') {
            $azKeys += "$($Matches[1]) $($Matches[2])"
        }
    }
    foreach ($f in Get-ChildItem (Join-Path $cat.FullName "02 En") -Filter *.md -EA SilentlyContinue) {
        if (-not (Test-StubFile $f.FullName) -and $f.Name -match '^(\d+)\s+([A-Za-z0-9_]+)\s+\(') {
            $enKeys += "$($Matches[1]) $($Matches[2])"
        }
    }
    foreach ($f in Get-ChildItem (Join-Path $cat.FullName "03 Ru") -Filter *.md -EA SilentlyContinue) {
        if (-not (Test-StubFile $f.FullName) -and $f.Name -match '^(\d+)\s+([A-Za-z0-9_]+)\s+\(') {
            $ruKeys += "$($Matches[1]) $($Matches[2])"
        }
    }
    $azKeys = $azKeys | Sort-Object
    $enKeys = $enKeys | Sort-Object
    $ruKeys = $ruKeys | Sort-Object
    $catName = $cat.FullName.Replace((Get-Location).Path + '\', '')
    $azStr = $azKeys -join '|'
    $enStr = $enKeys -join '|'
    $ruStr = $ruKeys -join '|'
    if ($azStr -eq $enStr -and $enStr -eq $ruStr) {
        Write-Pass "$catName - Az=$($azKeys.Count) En=$($enKeys.Count) Ru=$($ruKeys.Count) (same set)"
    } else {
        Write-Fail "$catName - sets differ"
        $diffAzEn = Compare-Object $azKeys $enKeys
        $diffAzRu = Compare-Object $azKeys $ruKeys
        if ($diffAzEn) {
            Write-Info "  Az vs En:"
            $diffAzEn | ForEach-Object { Write-Info "    $($_.SideIndicator) $($_.InputObject)" }
        }
        if ($diffAzRu) {
            Write-Info "  Az vs Ru:"
            $diffAzRu | ForEach-Object { Write-Info "    $($_.SideIndicator) $($_.InputObject)" }
        }
    }
}

# 21. SUMMARY BY MACHINE COUNT
Write-Host "`n[21] Summary" -ForegroundColor Yellow
$totalMachines = 0
if ($categories.Count -gt 0) {
    foreach ($cat in $categories) {
        $az = @(Get-ChildItem (Join-Path $cat.FullName "01 Az") -Filter *.md -EA SilentlyContinue | Where-Object { -not (Test-StubFile $_.FullName) }).Count
        $totalMachines += $az
    }
}
Write-Info "Total machines: $totalMachines"
Write-Info "Total walkthrough files: $($totalMachines * 3)"
if ($totalMachines * 3 -eq $walkthroughs.Count) {
    Write-Pass "machines x 3 = walkthrough files ($totalMachines x 3 = $($walkthroughs.Count))"
} else {
    Write-Warn "mismatch: $totalMachines x 3 = $($totalMachines * 3) vs found $($walkthroughs.Count)"
}

# SUMMARY
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "     SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
if ($script:gitErrors -gt 0) {
    Write-Host "  git errors: $($script:gitErrors)" -ForegroundColor Red
}
Write-Host "  PASS: $pass" -ForegroundColor Green
Write-Host "  WARN: $warn" -ForegroundColor Yellow
Write-Host "  FAIL: $fail" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($SkipLocalChecks) { Write-Host "  (local checks skipped)" -ForegroundColor DarkGray }
if ($fail -eq 0 -and $warn -eq 0) { Write-Host "`n  PERFECT - repo fully ready" -ForegroundColor Green } elseif ($fail -eq 0) { Write-Host "`n  PASS - repo ready (some warnings)" -ForegroundColor Green } else { Write-Host "`n  FAIL - repo has issues" -ForegroundColor Red }
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "     FINAL AUDIT v3 COMPLETE" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
exit $(if ($fail -gt 0 -or $script:gitErrors -gt 0) { 1 } else { 0 })
