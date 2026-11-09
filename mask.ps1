param(
    [switch]$IncludeDrafts,
    [string]$DictPath = 'masking-dict.ps1'
)

# mask.ps1
# Mask sensitive data in .md files.
# Requires masking-dict.ps1 in the same directory.
# Usage: .\mask.ps1

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
Set-Location $repo

$dictPath = Join-Path $repo $DictPath
if (-not (Test-Path $dictPath)) {
    Write-Host "ERROR: masking-dict.ps1 not found at $dictPath" -ForegroundColor Red
    exit 1
}
. $dictPath

$utf8WithBom = New-Object System.Text.UTF8Encoding($true)

Write-Host "`n=== Masking sensitive values ===" -ForegroundColor Cyan
$filesMasked = 0
foreach ($ext in @("*.md")) {
    Get-ChildItem -Recurse -Filter $ext |
      Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\01 Web\\' -and ($IncludeDrafts -or $_.FullName -notmatch '\\txt\\') -and $_.Name -notin @('MASTER_WORKFLOW.md', 'README.md', 'CHEATSHEET.md', 'METHODOLOGY.md', 'OSCP-Reporting.md', 'SECURITY.md') } |
      ForEach-Object {
        $content = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::UTF8)
        $new = $content
        $sortedKeys = $replacements.Keys | Sort-Object { $_.Length } -Descending
        foreach ($key in $sortedKeys) {
            $new = $new.Replace($key, $replacements[$key])
        }
        if ($content -ne $new) {
            [System.IO.File]::WriteAllText($_.FullName, $new, $utf8WithBom)
            Write-Host "[MASK] $($_.Name)"
            $filesMasked++
        }
      }
}
Write-Host "Files masked: $filesMasked" -ForegroundColor Green

function Get-NoteForFile($filePath) {
    if ($filePath -match '\\01 Az\\') {
        return "> [!NOTE]`n> Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir."
    } elseif ($filePath -match '\\03 Ru\\') {
        return "> [!NOTE]`n> Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям."
    } else {
        return "> [!NOTE]`n> All flags, passwords, hashes, and session tokens have been masked for ethical reasons."
    }
}
Write-Host "`n=== Adding note after Attack Chain ===" -ForegroundColor Cyan
$filesWithNote = 0
Get-ChildItem -Recurse -Filter *.md |
  Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\01 Web\\' -and ($IncludeDrafts -or $_.FullName -notmatch '\\txt\\') -and $_.Name -notin @('README.md', 'CHEATSHEET.md', 'METHODOLOGY.md', 'OSCP-Reporting.md', 'MASTER_WORKFLOW.md') } |
  ForEach-Object {
    $content = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::UTF8)
    $note = Get-NoteForFile $_.FullName
    $noteTexts = @(
        'All flags, passwords, hashes, and session tokens have been masked for ethical reasons',
        'Все флаги, пароли, хеши и токены сессий были замаскированы по этическим соображениям',
        'Bütün bayraqlar, şifrələr, heşlər və sessiya tokenləri etik səbəblərə görə gizlədilmişdir'
    )
    $hasNote = $false
    foreach ($nt in $noteTexts) { if ($content.Contains($nt)) { $hasNote = $true; break } }
    if ($hasNote) {
        Write-Host "[SKIP] Note exists: $($_.Name)" -ForegroundColor DarkGray
        return
    }
    $pattern = '(?ms)(^## Attack Chain\s*\r?\n\s*\r?\n```text\b.*?```)\r?\n'
    if ($content -match $pattern) {
        $new = $content -replace $pattern, "`$1`n`n$note`n"
        [System.IO.File]::WriteAllText($_.FullName, $new, $utf8WithBom)
        Write-Host "[NOTE] $($_.Name)" -ForegroundColor Cyan
        $filesWithNote++
    } else {
        Write-Host "[SKIP] No Attack Chain: $($_.Name)" -ForegroundColor DarkGray
    }
  }
Write-Host "Notes added: $filesWithNote" -ForegroundColor Green
exit 0
