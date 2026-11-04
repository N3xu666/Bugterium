# check.ps1
# Repository check: leaks and artifacts.
# Requires masking-dict.ps1 in the same directory.
# Usage: .\check.ps1
#
# Stub detection:
#   Files whose first 15 lines contain a "Status: **Completed**" marker
#   (any language: En/Ru/Az) are treated as stubs (active machines) and
#   excluded from the "Ethical note in walkthroughs" check.
#   All other checks (flags, leaks, dashes, chars, artifacts, heuristic)
#   still apply to stub files.
#
# The txt/ directory (drafts, .gitignore) is excluded from all checks.

param(
    [string]$DictPath = 'masking-dict.ps1'
)

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
Set-Location $repo

$dictPath = Join-Path $repo $DictPath
if (-not (Test-Path $dictPath)) {
    Write-Host "ERROR: masking-dict.ps1 not found" -ForegroundColor Red
    exit 1
}
. $dictPath

$utf8 = [System.Text.Encoding]::UTF8
$totalIssues = 0

# Stub markers (active machines - placeholder files)
# Read from writeup-spec.psd1 (SeasonStub.StubMarker) with inline fallback.
$stubMarkers = @()
if ($spec -and $spec.Overlays -and $spec.Overlays.SeasonStub -and $spec.Overlays.SeasonStub.StubMarker) {
    $sm = $spec.Overlays.SeasonStub.StubMarker
    if ($sm.En) { $stubMarkers += $sm.En }
    if ($sm.Ru) { $stubMarkers += $sm.Ru }
    if ($sm.Az) { $stubMarkers += $sm.Az }
}
$stubMarkersFallback = @(
    'Status: Completed',
    'Status: **Completed**',
    'Пройдено',
    'Статус: Пройдено',
    'Статус: **Завершено**',
    'Status: Tamamlandı',
    'Status: **Tamamlandı**'
)
foreach ($m in $stubMarkersFallback) { if ($stubMarkers -notcontains $m) { $stubMarkers += $m } }

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

# Not-published files (skip in all content checks)
$excluded = @('ROADMAP.md', 'MASTER_WORKFLOW.md', 'APP_WORKFLOW.md', 'masking-dict.ps1', '_SITE_PLAN.md', 'SESSION_CLOSING_PROTOCOL.md')
# Files that are not walkthroughs (no Note, no Attack Chain)
$notWalkthrough = @('ROADMAP.md', 'README.md', 'CHEATSHEET.md', 'METHODOLOGY.md', 'OSCP-Reporting.md', 'MASTER_WORKFLOW.md', 'APP_WORKFLOW.md', 'masking-dict.ps1', 'SECURITY.md', '_SITE_PLAN.md', 'SESSION_CLOSING_PROTOCOL.md')

# ============================================================
# 1. Real 32-hex flags
# ============================================================

# --- Load writeup-spec.psd1 (single source of truth; fallback to literals) ---
$specPath = Join-Path $PSScriptRoot 'writeup-spec.psd1'
$spec = $null
if (Test-Path $specPath) {
    try { $spec = Import-PowerShellDataFile -Path $specPath } catch { $spec = $null }
}
if (-not $spec) { Write-Host 'WARN: writeup-spec.psd1 not loaded, using inline literals' -ForegroundColor Yellow }

# Resolved spec values (with fallback to literals if spec missing)
$specCvePattern   = if ($spec) { $spec.Base.CvePattern }   else { 'CVE-\d{4}-\d{4,}' }
$specNoCveText    = if ($spec) { $spec.Base.CveNoCveText } else { 'No CVE (custom vulnerability)' }
$specOscpMarker   = if ($spec) { $spec.Base.OscpMarker }   else { 'OSCP report: take a screenshot' }
$specUserFlag     = '<USER_FLAG>'
$specRootFlag     = '<ROOT_FLAG>'
# A2a: resolved spec values for [12/27], [19/27], [22/27]
$specCveLinkHosts = if ($spec) { $spec.Base.CveLinkHosts } else { @('nvd.nist.gov', 'cve.mitre.org') }
$specTermOldAz    = if ($spec) { $spec.Base.Terminology.Az.Old } else { 'Defolt Kredensiallar' }
$specCyrClass     = if ($spec) { $spec.Base.CharClasses.Cyr } else { $null }
$specAzeClass     = if ($spec) { $spec.Base.CharClasses.Aze } else { $null }
$specEngWhitelist = if ($spec) { $spec.Base.EngWhitelist } else { @() }
$specEthicalNote      = if ($spec) { $spec.Base.EthicalNote }      else { $null }
$specEthicalNoteShort = if ($spec) { $spec.Base.EthicalNoteShort } else { $null }
$specRefEtalon        = if ($spec) { $spec.Base.ReferencesEtalon } else { $null }
$specFlagsRegex       = if ($spec) { $spec.Base.FlagsRegex }       else { '\b[a-fA-F0-9]{32}\b' }
$specBrokenCharsPat   = if ($spec) { $spec.Base.BrokenCharsPattern } else { '[\uFFFD]' }
$specMaskingArtifacts = if ($spec) { $spec.Base.MaskingArtifacts } else { @('<PASSWORD>blog','<PASSWORD>.htb','<USER_FLAG>FLAG','<ROOT_FLAG>FLAG') }
$specReadmeCounterPat = if ($spec) { $spec.Base.ReadmeCounterPattern } else { 'Currently:\s+\*\*(\d+)\s+published.*?\+\s+(\d+)\s+active stubs\*\*\s+=\s+\*\*(\d+)\s+completed' }
$specLongDashesPat    = if ($spec) { $spec.Base.LongDashesPattern }    else { '[\u2013\u2014\u2212]' }
$specUnreplacedPat    = if ($spec) { $spec.Base.UnreplacedPlaceholderPattern } else { '%%[A-Z0-9]+%%' }
$specDocRootFiles     = if ($spec) { $spec.Base.DocRootFiles }         else { @('README.md','CHEATSHEET.md','METHODOLOGY.md','SECURITY.md') }
$specBackslashPat     = if ($spec) { $spec.Base.BackslashEscapePattern } else { '^\\[#\[\]_()]' }
$specDocsRoots        = if ($spec) { $spec.Base.DocsRoots }             else { @('APPLICATIONS','INFRASTRUCTURE','ANONYMITY-PRIVACY-OPSEC','AI','NETWORKS','tools') }
$specCitationPat      = if ($spec) { $spec.Base.CitationPattern }       else { 'citation:\d+' }
$specDraftPath        = if ($spec) { $spec.Base.DraftPath }             else { 'txt/active-drafts' }
$specDraftCitationPat = if ($spec) { $spec.Base.DraftCitationPattern }  else { '\[citation:\d+\]' }
$specStaleRefs        = if ($spec) { $spec.Base.StaleRefs }        else { @('02 Web','01 HTB','OSCP-grade') }
$specDocExcludeNames  = if ($spec) { $spec.Base.DocExcludeNames }  else { @('MASTER_WORKFLOW.md','_SITE_PLAN.md','PROMPT_NEXT_SESSION.txt') }
$specTimesSign        = if ($spec) { $spec.Base.TimesSign }        else { [string][char]0x00D7 }
$specWrongDifficultyRu    = if ($spec) { $spec.Base.WrongDifficultyRu }     else { @() }
Write-Host "`n=== [1/27] Real 32-hex flags ===" -ForegroundColor Cyan
$flags = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\03 Pro Labs' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.FullName -notmatch '\\NETWORKS\\' -and $_.FullName -notmatch '\\CLOUD\\' -and $_.FullName -notmatch '\\VIRTUALIZATION\\' -and $_.FullName -notmatch '\\INFORMATION_SECURITY\\' -and $_.FullName -notmatch '\\OSINT\\' -and $_.Name -notin $excluded } |
  ForEach-Object {
    $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $flags += [regex]::Matches($c, $specFlagsRegex).Count
  }
if ($flags -eq 0) { Write-Host "OK: 0 flags" -ForegroundColor Green }
else { Write-Host "FAIL: $flags flags left" -ForegroundColor Red; $totalIssues += $flags }

# ============================================================
# 2. Real passwords/hashes/keys from dictionary
# ============================================================
Write-Host "`n=== [2/27] Real passwords/hashes/keys from dict ===" -ForegroundColor Cyan
$leaks = 0
foreach ($key in $replacements.Keys) {
    if ($key -match '^<.*>$') { continue }
    if ($key -match '^[a-fA-F0-9]{32}$') { continue }
    $count = 0
    Get-ChildItem -Recurse -Filter *.md |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\03 Pro Labs' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.FullName -notmatch '\\NETWORKS\\' -and $_.FullName -notmatch '\\CLOUD\\' -and $_.FullName -notmatch '\\VIRTUALIZATION\\' -and $_.FullName -notmatch '\\INFORMATION_SECURITY\\' -and $_.FullName -notmatch '\\OSINT\\' -and $_.Name -notin $excluded } |
      ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $count += ([regex]::Matches($c, [regex]::Escape($key))).Count
      }
    if ($count -gt 0) {
        Write-Host ("  LEAK: '{0}' x{1}" -f $key, $count) -ForegroundColor Red
        $leaks += $count
    }
}
if ($leaks -eq 0) { Write-Host "OK: 0 leaks" -ForegroundColor Green }
else { Write-Host "FAIL: $leaks leaks" -ForegroundColor Red; $totalIssues += $leaks }

# ============================================================
# 3. Note after Attack Chain (walkthroughs only, skip stubs)
# ============================================================
Write-Host "`n=== [3/27] Ethical note in walkthroughs ===" -ForegroundColor Cyan
$withNote = 0
$withoutNote = 0
$stubCount = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\03 Pro Labs' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.FullName -notmatch '\\NETWORKS\\' -and $_.FullName -notmatch '\\CLOUD\\' -and $_.FullName -notmatch '\\VIRTUALIZATION\\' -and $_.FullName -notmatch '\\INFORMATION_SECURITY\\' -and $_.FullName -notmatch '\\OSINT\\' -and $_.Name -notin $notWalkthrough } |
  ForEach-Object {
    if (Test-StubFile $_.FullName) {
        $stubCount++
    } else {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        # Note texts come from writeup-spec.psd1 (EthicalNote + EthicalNoteShort).
        $noteTexts = @()
        if ($null -ne $specEthicalNote)     { $noteTexts += $specEthicalNote.Values }
        if ($null -ne $specEthicalNoteShort) { $noteTexts += $specEthicalNoteShort.Values }
        if ($noteTexts.Count -eq 0) {
            $noteTexts = @(
                'All flags, passwords, hashes, and session tokens have been masked for ethical reasons',
                'Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям',
                'Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir'
            )
        }
        $hasNote = $false
        foreach ($nt in $noteTexts) { if ($c.Contains($nt)) { $hasNote = $true; break } }
        if ($hasNote) { $withNote++ }
        else { Write-Host "  MISSING NOTE: $($_.Name)" -ForegroundColor Yellow; $withoutNote++ }
    }
  }
Write-Host "Files with note: $withNote"
Write-Host "Files without note: $withoutNote"
Write-Host "Stub files skipped: $stubCount" -ForegroundColor Gray
if ($withoutNote -gt 0) { $totalIssues += $withoutNote }

# ============================================================
# 4. Long dashes
# ============================================================
Write-Host "`n=== [4/27] Long dashes ===" -ForegroundColor Cyan
$d = 0
foreach ($ext in @("*.md")) {
    Get-ChildItem -Recurse -Filter $ext |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\03 Pro Labs' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.FullName -notmatch '\\NETWORKS\\' -and $_.FullName -notmatch '\\CLOUD\\' -and $_.FullName -notmatch '\\VIRTUALIZATION\\' -and $_.FullName -notmatch '\\INFORMATION_SECURITY\\' -and $_.FullName -notmatch '\\OSINT\\' -and $_.Name -notin $excluded } |
      ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $d += [regex]::Matches($c, $specLongDashesPat).Count
      }
}
if ($d -eq 0) { Write-Host "OK: 0 dashes" -ForegroundColor Green }
else { Write-Host "FAIL: $d long dashes" -ForegroundColor Red; $totalIssues += $d }

# ============================================================
# 5. Broken chars
# ============================================================
Write-Host "`n=== [5/27] Broken chars (U+FFFD) ===" -ForegroundColor Cyan
$b = 0
foreach ($ext in @("*.md")) {
    Get-ChildItem -Recurse -Filter $ext |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\03 Pro Labs' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.FullName -notmatch '\\NETWORKS\\' -and $_.FullName -notmatch '\\CLOUD\\' -and $_.FullName -notmatch '\\VIRTUALIZATION\\' -and $_.FullName -notmatch '\\INFORMATION_SECURITY\\' -and $_.FullName -notmatch '\\OSINT\\' -and $_.Name -notin $excluded } |
      ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $b += [regex]::Matches($c, $specBrokenCharsPat).Count
      }
}
if ($b -eq 0) { Write-Host "OK: 0 broken chars" -ForegroundColor Green }
else { Write-Host "FAIL: $b broken chars" -ForegroundColor Red; $totalIssues += $b }

# ============================================================
# 6. Masking artifacts
# ============================================================
Write-Host "`n=== [6/27] Masking artifacts ===" -ForegroundColor Cyan
$artifacts = $specMaskingArtifacts
$a = 0
foreach ($art in $artifacts) {
    $count = 0
    Get-ChildItem -Recurse -Filter *.md |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\03 Pro Labs' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.FullName -notmatch '\\NETWORKS\\' -and $_.FullName -notmatch '\\CLOUD\\' -and $_.FullName -notmatch '\\VIRTUALIZATION\\' -and $_.FullName -notmatch '\\INFORMATION_SECURITY\\' -and $_.FullName -notmatch '\\OSINT\\' -and $_.Name -notin $excluded } |
      ForEach-Object {
        $c = [System.IO.File]::ReadAllText($_.FullName, $utf8)
        $count += ([regex]::Matches($c, [regex]::Escape($art))).Count
      }
    if ($count -gt 0) {
        Write-Host ("  ARTIFACT: '{0}' x{1}" -f $art, $count) -ForegroundColor Red
        $a += $count
    }
}
if ($a -eq 0) { Write-Host "OK: 0 artifacts" -ForegroundColor Green }
else { Write-Host "FAIL: $a artifacts" -ForegroundColor Red; $totalIssues += $a }

# ============================================================
# 7. Heuristic: possibly unmasked secrets (WARN only, does not block)
# ============================================================
Write-Host "`n=== [7/27] Heuristic: suspicious passwords (WARN only) ===" -ForegroundColor Cyan
$suspicious = @()
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\03 Pro Labs' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.FullName -notmatch '\\NETWORKS\\' -and $_.FullName -notmatch '\\CLOUD\\' -and $_.FullName -notmatch '\\VIRTUALIZATION\\' -and $_.FullName -notmatch '\\INFORMATION_SECURITY\\' -and $_.FullName -notmatch '\\OSINT\\' -and $_.Name -notin $excluded } |
  ForEach-Object {
    $ct = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $mm = [regex]::Matches($ct, '(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey)\s*[:=]\s*([^\s`<>]{5,})')
    foreach ($x in $mm) {
        $val = $x.Groups[2].Value
        if ($val -match '^<.*>$') { continue }
        if ($val -match '^\$2[aby]\$' -or $val -match '^\*?[A-F0-9]{32,}$') { continue }
        # P1.1: skip sudo directives and path segments (PASSWD: /usr/bin/wget)
if ($val -match '^[/\\]') { continue }
if ($val -match '^\.') { continue }
# P1.1: skip Hydra placeholders (^PASS^, ^USER^)
if ($val -match '\^') { continue }
# P1.1: skip ALL_CAPS identifiers (env var refs, constants)
if ($val -match '^[A-Z_]{3,5}$') { continue }
$val = $val.TrimEnd('"').TrimEnd("'")
if ($val -match '^(password|null|none|undefined|example|test|changeme|N/A)$') { continue }
        $suspicious += "$($_.Name): $($x.Value)"
    }
  }
if ($suspicious.Count -eq 0) {
    Write-Host "OK: 0 suspicious (all matches look masked or benign)" -ForegroundColor Green
} else {
    Write-Host "WARN: $($suspicious.Count) possible unmasked secrets (manual review):" -ForegroundColor Yellow
    $suspicious | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($suspicious.Count -gt 10) { Write-Host "  ... and $($suspicious.Count - 10) more" -ForegroundColor Gray }
}

# ============================================================
# 8. CVE reference in Exploitation/Foothold (FAIL if section missing or no CVE)
# ============================================================
Write-Host "`n=== [8/27] Exploitation/Foothold CVE reference (FAIL) ===" -ForegroundColor Cyan
$missingCve = @()
$sectionPattern = '^## (Exploitation|Foothold|Эксплуатация|Первичный Доступ|İstismar|İlkin Giriş)'
$checkedExpl = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\03 Pro Labs' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.FullName -notmatch '\\NETWORKS\\' -and $_.FullName -notmatch '\\CLOUD\\' -and $_.FullName -notmatch '\\VIRTUALIZATION\\' -and $_.FullName -notmatch '\\INFORMATION_SECURITY\\' -and $_.FullName -notmatch '\\OSINT\\' -and $_.Name -notin $notWalkthrough } |
  ForEach-Object {
    if (Test-StubFile $_.FullName) { return }
    $ct = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $lines2 = $ct -split "`n"
    $inCode = $false
    $explText = ""
    $inExpl = $false
    $hasExpl = $false
    foreach ($ln in $lines2) {
        if ($ln -match '^```') { $inCode = -not $inCode; continue }
        if ($inCode) { continue }
        if ($ln -match '^## ') {
            $inExpl = $false
            if ($ln -match $sectionPattern) {
                $inExpl = $true
                $hasExpl = $true
            }
        }
        if ($inExpl) { $explText += $ln + "`n" }
    }
    $script:checkedExpl++
    if (-not $hasExpl) {
        $rel = if ($_.FullName.StartsWith($repo)) { $_.FullName.Substring($repo.Length).TrimStart('\') } else { $_.FullName }
        $script:missingCve += "$rel (no Exploitation/Foothold section)"
    } else {
        $hasCve = ($explText -match $specCvePattern)
        $hasNoCve = ($explText -match ([regex]::Escape($specNoCveText)))
        if (-not $hasCve -and -not $hasNoCve) {
            $rel = if ($_.FullName.StartsWith($repo)) { $_.FullName.Substring($repo.Length).TrimStart('\') } else { $_.FullName }
            $script:missingCve += "$rel (no CVE/No CVE in Exploitation/Foothold)"
        }
    }
  }
if ($missingCve.Count -eq 0) {
    Write-Host "OK: all Exploitation/Foothold sections have a CVE reference ($checkedExpl checked)" -ForegroundColor Green
} else {
    Write-Host "FAIL: $($missingCve.Count) walkthrough(s) with missing section or missing CVE:" -ForegroundColor Red
    $missingCve | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($missingCve.Count -gt 10) { Write-Host "  ... and $($missingCve.Count - 10) more" -ForegroundColor Gray }
    $totalIssues += $missingCve.Count
}

# ============================================================
# 9. Unreplaced placeholders in docs (FAIL)
# Scans: APPLICATIONS/01 Web/**, methodology/**, root *.md (README, CHEATSHEET,
# METHODOLOGY, SECURITY). Looks for %%XX%% style markers.
# ============================================================
Write-Host "`n=== [9/27] Unreplaced placeholders in docs ===" -ForegroundColor Cyan
$docRootFiles = $specDocRootFiles
$placeholderCount = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object {
    $_.FullName -notmatch '\\\.git\\' -and
    $_.FullName -notmatch '\\txt\\' -and
    $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and
    $_.FullName -notmatch '\\tools\\' -and
    ($_.FullName -match '\\APPLICATIONS\\' -or $_.FullName -match '\\INFRASTRUCTURE\\' -or $_.FullName -match '\\ANONYMITY-PRIVACY-OPSEC\\' -or $_.FullName -match '\\AI\\' -or $_.FullName -match '\\NETWORKS\\' -or $_.FullName -match '\\methodology\\' -or $_.Name -in $docRootFiles)
  } |
  ForEach-Object {
    $ct = [System.IO.File]::ReadAllText($_.FullName, $utf8)
    $matches = [regex]::Matches($ct, $specUnreplacedPat)
    if ($matches.Count -gt 0) {
      $rel = if ($_.FullName.StartsWith($repo)) { $_.FullName.Substring($repo.Length).TrimStart('\') } else { $_.FullName }
      $unique = ($matches | ForEach-Object { $_.Value } | Sort-Object -Unique) -join ', '
      Write-Host "  PLACEHOLDER: $rel ($($matches.Count) markers: $unique)" -ForegroundColor Red
      $script:placeholderCount += $matches.Count
    }
  }
if ($placeholderCount -eq 0) { Write-Host "OK: 0 unreplaced placeholders in docs" -ForegroundColor Green }
else { Write-Host "FAIL: $placeholderCount unreplaced placeholders" -ForegroundColor Red; $totalIssues += $placeholderCount }

# ============================================================
# 10. Broken relative links in docs (WARN only, does not block)
# Scans: APPLICATIONS/01 Web/**/*.md, methodology/**/*.md, root *.md. Skips code blocks, anchors, http(s)/mailto.
# ============================================================
Write-Host "`n=== [10/27] Broken relative links in docs (WARN only) ===" -ForegroundColor Cyan
$brokenLinks = @()
$linkExcludeNames = $specDocExcludeNames
$linkFiles = Get-ChildItem -Path $repo -Recurse -Filter *.md -ErrorAction SilentlyContinue |
  Where-Object {
    $_.FullName -notmatch '\\\\\.git\\\\' -and
    $_.FullName -notmatch '\\\\txt\\\\' -and
    $_.FullName -notmatch '\\\\tests\\\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and
    $_.Name -notin $linkExcludeNames
  }
$linkFiles |
  ForEach-Object {
    $f = $_
    $dir = $f.Directory.FullName
    $ln = 0
    $inCode = $false
    Get-Content -Path $f.FullName | ForEach-Object {
      $ln++
      $line = $_
      if ($line -match '^```') { $inCode = -not $inCode; return }
      if ($inCode) { return }
      [regex]::Matches($line, '\]\(([^)]+)\)') | ForEach-Object {
        $link = $_.Groups[1].Value.Trim()
        if ($link -match '^https?:' -or $link -match '^mailto:' -or $link -match '^#') { return }
        $noAnchor = ($link -split '#')[0]
        if ($noAnchor -eq '') { return }
        $decoded = [System.Uri]::UnescapeDataString($noAnchor)
        $combined = Join-Path $dir $decoded
        try { $target = [System.IO.Path]::GetFullPath($combined) } catch { return }
        if (-not (Test-Path $target)) {
          $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
          $script:brokenLinks += "${rel}:${ln}: $link"
        }
      }
    }
  }
if ($brokenLinks.Count -eq 0) { Write-Host "OK: 0 broken relative links across all tracked .md" -ForegroundColor Green }
else {
  Write-Host "WARN: $($brokenLinks.Count) broken relative link(s):" -ForegroundColor Yellow
  $brokenLinks | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
  if ($brokenLinks.Count -gt 10) { Write-Host "  ... and $($brokenLinks.Count - 10) more" -ForegroundColor Gray }
}

# ============================================================
# 11. Counter consistency in root README (WARN only, does not block)
# Compares root README counter with actual file counts.
# ============================================================
Write-Host "`n=== [11/27] Counter consistency in root README (WARN only) ===" -ForegroundColor Cyan
$counterWarn = 0

# Count published (non-stub) and stubs in all 01 Az/ folders
$publishedTotal = 0
$stubsTotal = 0
$categories = Get-ChildItem -Recurse -Directory -Filter "01 Az" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' }
foreach ($cat in $categories) {
    $files = Get-ChildItem -Path $cat.FullName -Filter *.md -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        if (Test-StubFile $f.FullName) { $stubsTotal++ } else { $publishedTotal++ }
    }
}

# Read root README counter
$readmePath = Join-Path $repo "README.md"
if (Test-Path $readmePath) {
    $readmeContent = [System.IO.File]::ReadAllText($readmePath, $utf8)
    $counterMatch = [regex]::Match($readmeContent, $specReadmeCounterPat)
    if ($counterMatch.Success) {
        $readmePub = [int]$counterMatch.Groups[1].Value
        $readmeStub = [int]$counterMatch.Groups[2].Value
        $readmeTotal = [int]$counterMatch.Groups[3].Value
        if ($readmePub -ne $publishedTotal) {
            Write-Host "WARN: README published=$readmePub, actual=$publishedTotal" -ForegroundColor Yellow
            $counterWarn++
        }
        if ($readmeStub -ne $stubsTotal) {
            Write-Host "WARN: README stubs=$readmeStub, actual=$stubsTotal" -ForegroundColor Yellow
            $counterWarn++
        }
        if ($readmeTotal -ne ($readmePub + $readmeStub)) {
            Write-Host "WARN: README total=$readmeTotal, sum=$($readmePub + $readmeStub)" -ForegroundColor Yellow
            $counterWarn++
        }
        if ($counterWarn -eq 0) {
            Write-Host "OK: README counter matches actual ($publishedTotal published + $stubsTotal stubs)" -ForegroundColor Green
        }
    } else {
        Write-Host "WARN: root README counter pattern not found" -ForegroundColor Yellow
    }
} else {
    Write-Host "WARN: root README.md not found" -ForegroundColor Yellow
}

# ============================================================
# 12. CVE version ranges in docs tables (WARN only, does not block)
# Scans APPLICATIONS/01 Web/** for table rows that reference a CVE and an NVD/MITRE
# link but contain no version range (no digit outside the CVE ID).
# References lists (`- CVE-...: url`) are skipped on purpose.
# ============================================================
Write-Host "`n=== [12/27] CVE version ranges in docs tables (WARN only) ===" -ForegroundColor Cyan
$bareCve = @()
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -match '\\APPLICATIONS\\' -or $_.FullName -match '\\INFRASTRUCTURE\\' -or $_.FullName -match '\\ANONYMITY-PRIVACY-OPSEC\\' -or $_.FullName -match '\\AI\\' -or $_.FullName -match '\\NETWORKS\\' } |
  ForEach-Object {
    $lines3 = [System.IO.File]::ReadAllLines($_.FullName, $utf8)
    for ($i = 0; $i -lt $lines3.Count; $i++) {
      $ln = $lines3[$i]
      if ($ln -notmatch '^\|\s*CVE-\d{4}-\d{4,}') { continue }
      if ($ln -notmatch (($specCveLinkHosts | ForEach-Object { [regex]::Escape($_) }) -join '|')) { continue }
      $cells = $ln.Split('|') | ForEach-Object { $_.Trim() }
      $hasVersion = $false
      foreach ($c in $cells) {
        if ($c -eq '') { continue }
        if ($c -match 'CVE-\d{4}') { continue }
        if ($c -match [regex]::Escape($specCveLinkHosts[0])) { continue }
        if ($c -match [regex]::Escape($specCveLinkHosts[1])) { continue }
        if ($c -match '^https?://') { continue }
        if ($c -match '\d') { $hasVersion = $true; break }
      }
      if (-not $hasVersion) {
        $rel = if ($_.FullName.StartsWith($repo)) { $_.FullName.Substring($repo.Length).TrimStart('\') } else { $_.FullName }
        $script:bareCve += "${rel}:$($i+1): $($ln.Trim())"
      }
    }
  }
if ($bareCve.Count -eq 0) {
  Write-Host "OK: all CVE table rows include a version range" -ForegroundColor Green
} else {
  Write-Host "WARN: $($bareCve.Count) CVE table row(s) without version range (manual review):" -ForegroundColor Yellow
  $bareCve | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
  if ($bareCve.Count -gt 10) { Write-Host "  ... and $($bareCve.Count - 10) more" -ForegroundColor Gray }
}

# ============================================================
# ============================================================
# [13/27] Backslash escapes in docs (FAIL)
# ============================================================
Write-Host "`n=== [13/27] Backslash escapes in docs ===" -ForegroundColor Cyan
$bsEscapes = @()
$docsRoots = $specDocsRoots
$docsFiles = @()
foreach ($root in $docsRoots) {
    $p = Join-Path $repo $root
    if (Test-Path $p) {
        $docsFiles += Get-ChildItem -Path $p -Recurse -File -Filter '*.md' -ErrorAction SilentlyContinue
    }
}
$docsFiles += Get-ChildItem -Path $repo -File -Filter '*.md' -ErrorAction SilentlyContinue
$bsPattern = $specBackslashPat
foreach ($f in $docsFiles) {
    if ($f.FullName -match '\\\.git\\' -or $f.FullName -match '\\txt\\' -or $f.FullName -match '\\tests\\') { continue }
    $lines = [System.IO.File]::ReadAllLines($f.FullName, $utf8)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        if ($ln -match $bsPattern) {
            $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
            $bsEscapes += "${rel}:$($i+1): $($ln.Trim())"
        }
    }
}
if ($bsEscapes.Count -eq 0) {
    Write-Host "OK: 0 backslash-escaped markdown headers/links" -ForegroundColor Green
} else {
    Write-Host "FAIL: $($bsEscapes.Count) line(s) with backslash-escaped markdown (unreplaced placeholders):" -ForegroundColor Red
    $bsEscapes | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($bsEscapes.Count -gt 10) { Write-Host "  ... and $($bsEscapes.Count - 10) more" -ForegroundColor Gray }
    $totalIssues += $bsEscapes.Count
}
# ============================================================
# [14/27] Stale references in tracked .md (WARN only)
# Detects old folder names / marketing phrases left after
# restructures. Any occurrence is a signal to update the file.
# ============================================================
Write-Host "`n=== [14/27] Stale references (WARN only) ===" -ForegroundColor Cyan
$stalePhrases = $specStaleRefs
$staleHits = @()
$staleFiles = Get-ChildItem -Path $repo -Recurse -Filter *.md -ErrorAction SilentlyContinue |
  Where-Object {
    $_.FullName -notmatch '\\\\\.git\\\\' -and
    $_.FullName -notmatch '\\\\txt\\\\' -and
    $_.FullName -notmatch '\\\\tests\\\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and
    $_.Name -notin $specDocExcludeNames
  }
foreach ($f in $staleFiles) {
  $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
  $ln = 0
  foreach ($line in ($ct -split "`n")) {
    $ln++
    foreach ($ph in $stalePhrases) {
      if ($line.Contains($ph)) {
        $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
        $staleHits += "${rel}:${ln}: [$ph] $($line.Trim())"
      }
    }
  }
}
if ($staleHits.Count -eq 0) {
  Write-Host "OK: 0 stale references (02 Web / 01 HTB / OSCP-grade)" -ForegroundColor Green
} else {
  Write-Host "WARN: $($staleHits.Count) stale reference(s) - review:" -ForegroundColor Yellow
  $staleHits | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
  if ($staleHits.Count -gt 10) { Write-Host "  ... and $($staleHits.Count - 10) more" -ForegroundColor Gray }
}

# ============================================================
# [15/27] Language counter marker consistency (WARN only)
# Every "(N <marker> 3 languages)" line in WRITEUPS/**/README.md
# must use the multiplication sign U+00D7 between the number and
# "3 languages". Latin "x", "X", "*", "-", or mojibake "G-" are
# cosmetic drift (pass 71) and must be fixed.
# ============================================================
Write-Host "`n=== [15/27] Language counter marker (WARN only) ===" -ForegroundColor Cyan
$timesSign = [string]$specTimesSign
$counterWarns = @()
$counterFiles = Get-ChildItem -Path (Join-Path $repo "WRITEUPS") -Recurse -Filter "README.md" -ErrorAction SilentlyContinue
foreach ($f in $counterFiles) {
    $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
    $ln = 0
    foreach ($line in ($ct -split "`n")) {
        $ln++
        $ms = [regex]::Matches($line, '\((\S+)\s+3 languages\)')
        foreach ($m in $ms) {
            $marker = $m.Groups[1].Value
            if ($marker -ne $timesSign) {
                $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
                $counterWarns += "${rel}:${ln}: marker='$marker' (expected U+00D7)"
            }
        }
    }
}
if ($counterWarns.Count -eq 0) {
    Write-Host "OK: all language counters use U+00D7" -ForegroundColor Green
} else {
    Write-Host "WARN: $($counterWarns.Count) language counter(s) with wrong marker - review:" -ForegroundColor Yellow
    $counterWarns | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($counterWarns.Count -gt 10) { Write-Host "  ... and $($counterWarns.Count - 10) more" -ForegroundColor Gray }
}
# ============================================================
Write-Host "`n=== [16/27] Chat citation markers (FAIL) ===" -ForegroundColor Cyan
$citationFiles = Get-ChildItem -Path $repo -Recurse -Filter "*.md" -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch '\\txt\\' -and
        $_.FullName -notmatch '\\\.git\\' -and
        $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and
        $_.FullName -notmatch '_WORKFLOW'
    }
$citationHits = @()
foreach ($f in $citationFiles) {
    $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
    $m = [regex]::Matches($ct, $specCitationPat)
    if ($m.Count -gt 0) {
        $rel = $f.FullName.Replace($repo + '\', '')
        $citationHits += "$rel ($($m.Count))"
    }
}
if ($citationHits.Count -eq 0) {
    Write-Host "OK: 0 citation markers" -ForegroundColor Green
} else {
    Write-Host "FAIL: $($citationHits.Count) files contain chat citation markers:" -ForegroundColor Red
    $citationHits | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    $totalIssues++
}
# ============================================================
Write-Host "`n=== [17/27] References format (WARN only) ===" -ForegroundColor Cyan
$refFiles = Get-ChildItem -Path $repo -Recurse -Filter "*.md" -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch '\\txt\\' -and
        $_.FullName -notmatch '\\\.git\\' -and
        $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and
        $_.FullName -notmatch '_WORKFLOW' -and
        $_.FullName -notmatch '\\WRITEUPS\\'
    }
$refWarns = @()
foreach ($f in $refFiles) {
    $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
    $ct = $ct -replace "`r`n", "`n"
    $lines = $ct -split "`n"
    $rs = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^##\s+(\d+\.\s+)?References\s*$') { $rs = $i; break }
    }
    if ($rs -lt 0) { continue }
    $rel = $f.FullName.Replace($repo + '\', '')
    for ($i = $rs + 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^##\s+') { break }
        $line = $lines[$i].Trim()
        if ($line -eq '' -or $line -notmatch '^[-*]\s+') { continue }
        $item = $line -replace '^[-*]\s+', ''
        if ($item -match '^\[[^\]]+\]\(\.\.?/') { continue }
        $bPat = if ($null -ne $specRefEtalon) { $specRefEtalon.BPattern } else { '^\[[^\]]+\]\(https?://' }
        if ($item -match $bPat) {
            $refWarns += "$rel : B-format markdown link: $item"
            continue
        }
        $cPat = if ($null -ne $specRefEtalon) { $specRefEtalon.CPattern } else { ':\s+https?://' }
        if ($item -match $cPat) {
            $refWarns += "$rel : C-format colon URL: $item"
            continue
        }
    }
}
if ($refWarns.Count -eq 0) {
    Write-Host "OK: all References use etalon format" -ForegroundColor Green
} else {
    Write-Host "WARN: $($refWarns.Count) References item(s) not in etalon format 'description - url':" -ForegroundColor Yellow
    $refWarns | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($refWarns.Count -gt 10) { Write-Host "  ... and $($refWarns.Count - 10) more" -ForegroundColor Gray }
}

# Summary
# ============================================================
Write-Host "`n============================================" -ForegroundColor Cyan

# --- [18/27] Flags table placeholders ---
Write-Host "`n=== [18/27] Flags table placeholders (FAIL) ===" -ForegroundColor Cyan
$flagsIssues = @()
$flagFiles = Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -notmatch '\\methodology\\' -and $_.FullName -notmatch '\\tools\\' -and $_.FullName -notmatch '\\03 Pro Labs' -and $_.FullName -notmatch '\\APPLICATIONS\\' -and $_.FullName -notmatch '\\INFRASTRUCTURE\\' -and $_.FullName -notmatch '\\ANONYMITY-PRIVACY-OPSEC\\' -and $_.FullName -notmatch '\\AI\\' -and $_.FullName -notmatch '\\NETWORKS\\' -and $_.FullName -notmatch '\\CLOUD\\' -and $_.FullName -notmatch '\\VIRTUALIZATION\\' -and $_.FullName -notmatch '\\INFORMATION_SECURITY\\' -and $_.FullName -notmatch '\\OSINT\\' -and $_.Name -notin $notWalkthrough }

foreach ($f in $flagFiles) {
    if (Test-StubFile $f.FullName) { continue }
    $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
    $lines = $ct -split "`n"
    $inFlags = $false
    $flagsText = ""
    foreach ($ln in $lines) {
        if ($ln -match ('^## (' + [regex]::Escape('Flags') + '|' + [regex]::Escape('Флаги') + '|' + [regex]::Escape('Bayraqlar') + ')')) { $inFlags = $true; continue }
        if ($inFlags -and $ln -match '^## ') { $inFlags = $false }
        if ($inFlags) { $flagsText += $ln + "`n" }
    }
    if ($flagsText -ne "") {
        if (-not ($flagsText -match ([regex]::Escape($specUserFlag))) -or -not ($flagsText -match ([regex]::Escape($specRootFlag)))) {
            $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
            $flagsIssues += "$rel (missing placeholder)"
        }
        if ($f.FullName -notmatch '\\02 Windows\\' -and $flagsText -match 'root\.txt|СЃРј\.|see |bax ') {
            $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
            $flagsIssues += "$rel (contains file reference)"
        }
    }
}
if ($flagsIssues.Count -eq 0) {
    Write-Host "OK: all flags tables use placeholders" -ForegroundColor Green
} else {
    Write-Host "FAIL: $($flagsIssues.Count) issue(s) in flags tables:" -ForegroundColor Red
    $flagsIssues | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    $totalIssues += $flagsIssues.Count
}

# --- [19/27] Language terminology ---
Write-Host "`n=== [19/27] Language terminology (WARN) ===" -ForegroundColor Cyan
$termIssues = @()
foreach ($f in $flagFiles) {
    if (Test-StubFile $f.FullName) { continue }
    if ($f.FullName -notmatch '\\01 Az\\') { continue }
    $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
    if ($ct -match [regex]::Escape($specTermOldAz)) {
        $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
        $termIssues += "$rel (uses 'Defolt Kredensiallar' instead of 'Standart GiriЕџ MЙ™lumatlarД±')"
    }
}
if ($termIssues.Count -eq 0) {
    Write-Host "OK: language terminology correct" -ForegroundColor Green
} else {
    Write-Host "WARN: $($termIssues.Count) terminology warning(s):" -ForegroundColor Yellow
    $termIssues | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}

# --- Shared helpers for [20/27]..[23/27] ---
$cyrClass = $specCyrClass
$azeClass = $specAzeClass
$fence = [string][char]96 * 3
$crChar = [char]13
# --- [20/27] H3 parity across Az/En/Ru (FAIL) ---
Write-Host "`n=== [20/27] H3 parity across Az/En/Ru (FAIL) ===" -ForegroundColor Cyan
$h3Issues = @()
$h3Groups = @{}
foreach ($f in $flagFiles) {
    if (Test-StubFile $f.FullName) { continue }
    $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart("\") } else { $f.FullName }
    if ($rel -notmatch "\\0[123] (Az|En|Ru)\\") { continue }
    $dir = Split-Path (Split-Path $f.FullName -Parent) -Parent
    $nm = [System.IO.Path]::GetFileName($f.FullName)
    $key = Join-Path $dir $nm
    if (-not $h3Groups.ContainsKey($key)) { $h3Groups[$key] = @{} }
    $lang = if ($f.FullName -match "\\01 Az\\") { "Az" } elseif ($f.FullName -match "\\02 En\\") { "En" } else { "Ru" }
    $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
    $lns = $ct -split "`n"
    $inFence = $false
    $h3c = 0
    foreach ($ln in $lns) {
        $t = $ln.TrimStart()
        if ($t.StartsWith($fence)) { $inFence = -not $inFence; continue }
        if ($inFence) { continue }
        if ($ln -match "^### ") { $h3c++ }
    }
    $h3Groups[$key][$lang] = $h3c
}
foreach ($key in $h3Groups.Keys) {
    $g = $h3Groups[$key]
    if ($g.Count -lt 3) { continue }
    $va = $g["Az"]; $ve = $g["En"]; $vr = $g["Ru"]
    if ($null -eq $va -or $null -eq $ve -or $null -eq $vr) { continue }
    if ($va -ne $ve -or $ve -ne $vr) {
        $rel = if ($key.StartsWith($repo)) { $key.Substring($repo.Length).TrimStart("\") } else { $key }
        $h3Issues += "$rel (Az=$va En=$ve Ru=$vr)"
    }
}
if ($h3Issues.Count -eq 0) {
    Write-Host "OK: H3 count matches across Az/En/Ru" -ForegroundColor Green
} else {
    Write-Host "FAIL: $($h3Issues.Count) walkthrough(s) with H3 mismatch:" -ForegroundColor Red
    $h3Issues | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    $totalIssues += $h3Issues.Count
}

# --- [21/27] OSCP marker parity (FAIL) ---
Write-Host "`n=== [21/27] OSCP marker parity (FAIL) ===" -ForegroundColor Cyan
$oscpIssues = @()
$oscpGroups = @{}
$oscpMarker = $specOscpMarker
foreach ($f in $flagFiles) {
    if (Test-StubFile $f.FullName) { continue }
    $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart("\") } else { $f.FullName }
    if ($rel -notmatch "\\0[123] (Az|En|Ru)\\") { continue }
    if ($rel -notmatch "\\02 OSCP\\") { continue }
    $dir = Split-Path (Split-Path $f.FullName -Parent) -Parent
    $nm = [System.IO.Path]::GetFileName($f.FullName)
    $key = Join-Path $dir $nm
    if (-not $oscpGroups.ContainsKey($key)) { $oscpGroups[$key] = @{} }
    $lang = if ($f.FullName -match "\\01 Az\\") { "Az" } elseif ($f.FullName -match "\\02 En\\") { "En" } else { "Ru" }
    $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
    $cnt = ([regex]::Matches($ct, [regex]::Escape($oscpMarker))).Count
    $oscpGroups[$key][$lang] = $cnt
}
foreach ($key in $oscpGroups.Keys) {
    $g = $oscpGroups[$key]
    if ($g.Count -lt 3) { continue }
    $va = $g["Az"]; $ve = $g["En"]; $vr = $g["Ru"]
    if ($null -eq $va -or $null -eq $ve -or $null -eq $vr) { continue }
    if ($va -ne $ve -or $ve -ne $vr) {
        $rel = if ($key.StartsWith($repo)) { $key.Substring($repo.Length).TrimStart("\") } else { $key }
        $oscpIssues += "$rel (Az=$va En=$ve Ru=$vr)"
    }
}
if ($oscpIssues.Count -eq 0) {
    Write-Host "OK: OSCP marker count matches across Az/En/Ru" -ForegroundColor Green
} else {
    Write-Host "FAIL: $($oscpIssues.Count) walkthrough(s) with OSCP marker mismatch:" -ForegroundColor Red
    $oscpIssues | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    $totalIssues += $oscpIssues.Count
}

# --- [22/27] English fragment scan in Az/Ru (FAIL) ---
Write-Host "`n=== [22/27] English fragment scan in Az/Ru (FAIL) ===" -ForegroundColor Cyan
$engIssues = @()
$engWhitelist = $specEngWhitelist
foreach ($f in $flagFiles) {
    if (Test-StubFile $f.FullName) { continue }
    $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart("\") } else { $f.FullName }
    if ($rel -match "\\02 En\\") { continue }
    if ($rel -notmatch "\\0[123] (Az|Ru)\\") { continue }
    $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
    $lns = $ct -split "`n"
    $inFence = $false
    $lnNum = 0
    foreach ($ln in $lns) {
        $lnNum++
        $t = $ln.TrimStart()
        if ($t.StartsWith($fence)) { $inFence = -not $inFence; continue }
        if ($inFence) { continue }
        if ($ln -match "^\s*#") { continue }
        if ($ln -match "^\s*\|") { continue }
        if ($ln -match "^\s*>") { continue }
        if ($ln -match "^\s*-\s+\x60") { continue }
        if ($ln.Length -lt 40) { continue }
        if ($ln -match 'CVE-\d{4}-\d{4,}') { continue }
        if ($ln -match 'nvd\.nist\.gov|cve\.mitre\.org') { continue }
        if ($ln -match '\b[a-fA-F0-9]{16,}\b') { continue }
        if ($ln -match '<\?php|\$_GET|\$_POST|system\(') { continue }
        if ($ln -match 'hashcat mode|SHA-256 crypt|\$[0-9][a-z]?\$') { continue }
        if ($ln -match '^\s*(Komponent|Component|Компонент):') { continue }
        $hasCyr = $ln -match $cyrClass
        $hasAze = $ln -match $azeClass
        if ($hasCyr -or $hasAze) { continue }
        $lnCheck = $ln
        foreach ($w in $engWhitelist) { $lnCheck = $lnCheck -replace ("\b" + [regex]::Escape($w) + "\b"), '' }
        if ($lnCheck.Trim().Length -lt 20) { continue }
        $azWords = @("sinxron","makros","bloku","fayl","icra","olunan","kimi","ucun","haqqinda","melumat","giris","cixis","daxil","istifade","netice","hucum","zencir","komanda","fayli","faylin","yoxlamaq","tesdiq","meselen","olan","hem","cox","yox","var","ile","bu","bir","ve","az")
        $azHits = 0
        foreach ($aw in $azWords) { if ($ln -match ("\b" + [regex]::Escape($aw) + "\b")) { $azHits++ } }
        if ($azHits -ge 2) { continue }
        $engIssues += "$rel`:$lnNum (possible untranslated)"
    }
}
if ($engIssues.Count -eq 0) {
    Write-Host "OK: no English fragments in Az/Ru prose" -ForegroundColor Green
} elseif ($engIssues.Count -le 20) {
    Write-Host "FAIL: $($engIssues.Count) possible untranslated line(s):" -ForegroundColor Red
    $engIssues | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
} else {
    Write-Host "FAIL: $($engIssues.Count) possible untranslated line(s) (showing first 20):" -ForegroundColor Red
    $engIssues | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}
if ($engIssues.Count -gt 0) { $totalIssues += $engIssues.Count }

# --- [23/27] Draft-mode scan for txt/active-drafts (WARN only) ---
Write-Host "`n=== [23/27] Draft-mode scan for txt/active-drafts (WARN only) ===" -ForegroundColor Cyan
$draftRoot = Join-Path $repo $specDraftPath
$draftIssues = @()
if (Test-Path $draftRoot) {
    $drafts = Get-ChildItem -Path $draftRoot -Filter "*.md" -Recurse -File
    foreach ($d in $drafts) {
        $ct = [System.IO.File]::ReadAllText($d.FullName, $utf8)
        $rel = $d.FullName.Substring($repo.Length).TrimStart("\")
        if ($ct -match $specDraftCitationPat) { $draftIssues += "$rel (citation marker)" }
        if ($ct.IndexOf($crChar) -ge 0) { $draftIssues += "$rel (CRLF in draft)" }
    }
}
if ($draftIssues.Count -eq 0) {
    Write-Host "OK: drafts clean (or none present)" -ForegroundColor Green
} else {
    Write-Host "WARN: $($draftIssues.Count) issue(s) in drafts:" -ForegroundColor Yellow
    $draftIssues | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}


# ============================================================
# [24/27] Meta difficulty values (FAIL)
# ============================================================
Write-Host "`n=== [24/27] Meta difficulty values (FAIL) ===" -ForegroundColor Cyan
$diffIssues = @()
$diffFiles = Get-ChildItem -Path $repo -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\txt\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\terraform\\' -and $_.FullName -notmatch '\\site\\' -and $_.FullName -notmatch '\\node_modules\\' -and $_.FullName -match '\\03 Ru\\' }
foreach ($f in $diffFiles) {
    $ct = [System.IO.File]::ReadAllText($f.FullName, $utf8)
    foreach ($bad in $specWrongDifficultyRu) {
        if ($ct.Contains($bad)) {
            $rel = if ($f.FullName.StartsWith($repo)) { $f.FullName.Substring($repo.Length).TrimStart('\') } else { $f.FullName }
            $diffIssues += "$rel (wrong difficulty word)"
        }
    }
}
if ($diffIssues.Count -eq 0) { Write-Host "OK: meta difficulty values correct" -ForegroundColor Green }
else { Write-Host "FAIL: $($diffIssues.Count) file(s) with wrong difficulty value:" -ForegroundColor Red; $diffIssues | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }; $totalIssues += $diffIssues.Count }
# ============================================================
# [25/27] Stub marker per PSD1 (FAIL)
# ============================================================
Write-Host ('`n=== [25/27] Stub marker per PSD1 (FAIL) ===') -ForegroundColor Cyan
$stubIssueList = @()
if ($spec -and $spec.Overlays -and $spec.Overlays.SeasonStub -and $spec.Overlays.SeasonStub.StubMarker) {
    $sm2 = $spec.Overlays.SeasonStub.StubMarker
    foreach ($sf in $flagFiles) {
        if (-not (Test-StubFile $sf.FullName)) { continue }
        $relS = if ($sf.FullName.StartsWith($repo)) { $sf.FullName.Substring($repo.Length).TrimStart('\') } else { $sf.FullName }
        $langS = if ($sf.FullName -match '\\01 Az\\') { 'Az' } elseif ($sf.FullName -match '\\02 En\\') { 'En' } elseif ($sf.FullName -match '\\03 Ru\\') { 'Ru' } else { $null }
        if (-not $langS) { continue }
        $expected = $sm2[$langS]
        if (-not $expected) { continue }
        $headS = [System.IO.File]::ReadAllText($sf.FullName, $utf8)
        $linesS = $headS -split "`n" | Select-Object -First 15
        $found = $false
        foreach ($lnS in $linesS) { if ($lnS.Contains($expected)) { $found = $true; break } }
        if (-not $found) { $stubIssueList += ($relS + ' (missing marker: ' + $expected + ')') }
    }
}
if ($stubIssueList.Count -eq 0) { Write-Host 'OK: stub markers match PSD1' -ForegroundColor Green }
else { Write-Host ('FAIL: ' + $stubIssueList.Count + ' stub(s) with old marker:') -ForegroundColor Red; $stubIssueList | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Red }; $totalIssues += $stubIssueList.Count }

# ============================================================
# [26/27] RequiredH2 presence with localized names (FAIL)
# ============================================================
Write-Host ('`n=== [26/27] RequiredH2 presence with localized names (FAIL) ===') -ForegroundColor Cyan
$h2IssueList = @()
$fence26 = [string][char]96 * 3
$h2Map = @{
    En = @{ 'Attack Chain'='Attack Chain'; 'Machine Briefing'='Machine Briefing'; 'Reconnaissance'='Reconnaissance'; 'Foothold'='Foothold'; 'Privilege Escalation'='Privilege Escalation'; 'Flags'='Flags'; 'Key Takeaways'='Key Takeaways' }
    Az = @{ 'Attack Chain'='Hücum Zənciri'; 'Machine Briefing'='Maşın Brifinqi'; 'Reconnaissance'='Kəşfiyyat'; 'Foothold'='İlkin Giriş'; 'Privilege Escalation'='Səlahiyyətlərin Artırılması'; 'Flags'='Bayraqlar'; 'Key Takeaways'='Əsas Nəticələr' }
    Ru = @{ 'Attack Chain'='Цепочка Атаки'; 'Machine Briefing'='Брифинг Машины'; 'Reconnaissance'='Разведка'; 'Foothold'='Первичный Доступ'; 'Privilege Escalation'='Повышение Привилегий'; 'Flags'='Флаги'; 'Key Takeaways'='Ключевые Выводы' }
}
$requiredBase = @('Attack Chain', 'Machine Briefing', 'Reconnaissance', 'Foothold', 'Privilege Escalation', 'Flags', 'Key Takeaways')
if ($spec -and $spec.Base -and $spec.Base.RequiredH2) {
    foreach ($hf in $flagFiles) {
        if (Test-StubFile $hf.FullName) { continue }
        $relH = if ($hf.FullName.StartsWith($repo)) { $hf.FullName.Substring($repo.Length).TrimStart('\') } else { $hf.FullName }
        if ($relH -notmatch '\\0[123] (Az|En|Ru)\\') { continue }
        $langH = if ($relH -match '\\01 Az\\') { 'Az' } elseif ($relH -match '\\02 En\\') { 'En' } else { 'Ru' }
        $map = $h2Map[$langH]
        if (-not $map) { continue }
        $txtH = [System.IO.File]::ReadAllText($hf.FullName, $utf8)
        $lnsH = $txtH -split "`n"
        $inF = $false
        $h2Actual = @()
        foreach ($lH in $lnsH) {
            $tH = $lH.TrimStart()
            if ($tH.StartsWith($fence26)) { $inF = -not $inF; continue }
            if ($inF) { continue }
            if ($lH -match '^## ') { $h2Actual += ($lH -replace '^## ','').Trim() }
        }
        foreach ($r in $requiredBase) {
            if ($r -eq 'Privilege Escalation') { continue }
            $localized = $map[$r]
            $foundR = $false
            foreach ($a in $h2Actual) { if ($a -eq $localized -or $a.StartsWith($localized + ' (')) { $foundR = $true; break } }
            if (-not $foundR) { $h2IssueList += ($relH + ' (missing H2: ' + $localized + ')') }
        }
        $mtype = if ($relH -match '\\01 Linux\\') { 'Linux' } elseif ($relH -match '\\02 Windows\\') { 'Windows' } elseif ($relH -match '03 Active Directory') { 'AD' } else { $null }
        if ($mtype -eq 'AD') {
            $locAE = if ($langH -eq 'Az') { 'Autentifikasiyalı Sadalanma' } elseif ($langH -eq 'Ru') { 'Аутентифицированное Перечисление' } else { 'Authenticated Enumeration' }
            $foundAE = $false
            foreach ($a in $h2Actual) { if ($a -eq $locAE) { $foundAE = $true; break } }
            if (-not $foundAE) { $h2IssueList += ($relH + ' (missing H2: ' + $locAE + ')') }
        }
    }
}
if ($h2IssueList.Count -eq 0) { Write-Host 'OK: RequiredH2 present (localized)' -ForegroundColor Green }
else { Write-Host ('FAIL: ' + $h2IssueList.Count + ' H2 issue(s):') -ForegroundColor Red; $h2IssueList | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Red }; $totalIssues += $h2IssueList.Count }

# ============================================================
# [27/27] Meta labels per PSD1 (FAIL)
# ============================================================
Write-Host ('`n=== [27/27] Meta labels per PSD1 (FAIL) ===') -ForegroundColor Cyan
$metaIssueList = @()
if ($spec -and $spec.Base -and $spec.Base.MetaLabels) {
    foreach ($mf in $flagFiles) {
        $relM = if ($mf.FullName.StartsWith($repo)) { $mf.FullName.Substring($repo.Length).TrimStart('\') } else { $mf.FullName }
        if ($relM -notmatch '\\0[123] (Az|En|Ru)\\') { continue }
        $langM = if ($mf.FullName -match '\\01 Az\\') { 'Az' } elseif ($mf.FullName -match '\\02 En\\') { 'En' } else { 'Ru' }
        $labels = $spec.Base.MetaLabels[$langM]
        if (-not $labels) { continue }
        $txtM = [System.IO.File]::ReadAllText($mf.FullName, $utf8)
        $lnsM = $txtM -split "`n"
        $metaBlock = @()
        $started = $false
        foreach ($lM in $lnsM) {
            if ($lM -match '^# ') { continue }
            if ($lM -match '^> ') { $metaBlock += $lM; $started = $true; continue }
            if ($started -and $lM -eq '') { break }
        }
        $pos = 0
        foreach ($lab in $labels) {
            $foundLab = $false
            for ($k = $pos; $k -lt $metaBlock.Count; $k++) {
                $pattern = '^> ' + [regex]::Escape($lab) + ':'
                if ($metaBlock[$k] -match $pattern) { $foundLab = $true; $pos = $k + 1; break }
            }
            if (-not $foundLab) { $metaIssueList += ($relM + ' (missing meta label: ' + $lab + ')') }
        }
    }
}
if ($metaIssueList.Count -eq 0) { Write-Host 'OK: meta labels present' -ForegroundColor Green }
else { Write-Host ('FAIL: ' + $metaIssueList.Count + ' meta label issue(s):') -ForegroundColor Red; $metaIssueList | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Red }; $totalIssues += $metaIssueList.Count }


if ($totalIssues -eq 0) {
    Write-Host "ALL CHECKS PASSED - ready to commit + push" -ForegroundColor Green
    Write-Host ""
    Write-Host "  REMINDER before committing a NEW walkthrough:" -ForegroundColor Magenta
    Write-Host "    1. Add new real secrets to masking-dict.ps1 (passwords, flags, hashes)." -ForegroundColor Magenta
    Write-Host "    2. Run .\update-readmes.ps1 to refresh README tables and counters." -ForegroundColor Magenta
    exit 0
} else {
    Write-Host "TOTAL ISSUES: $totalIssues - fix before push" -ForegroundColor Red
    exit 1
}
Write-Host "============================================" -ForegroundColor Cyan
