# check-anchors.ps1 - Validate markdown anchor links in tracked .md files.
# GitHub-style anchor generation: lowercase, spaces -> hyphens, strip punctuation, keep letters/digits/cyrillic/hyphens.
# WARN-only by default. Exit code 1 if broken anchors found (for CI).
#
# Usage:
#   .\check-anchors.ps1
#   .\check-anchors.ps1 -Quiet

param(
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
$utf8 = New-Object System.Text.UTF8Encoding($false)
$LF = [char]10
$BT3 = [string][char]96 * 3

# Files excluded from anchor check (same as check.ps1 [10/14])
$excludeNames = @("MASTER_WORKFLOW.md", "_SITE_PLAN.md", "PROMPT_NEXT_SESSION.txt")

# Collect all .md files
$files = Get-ChildItem -Path $repo -Recurse -Filter *.md -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch "\\\.git\\" -and
        $_.FullName -notmatch "\\txt\\" -and
        $_.FullName -notmatch "\\tests\\" -and $_.FullName -notmatch "\\terraform\\" -and $_.FullName -notmatch "\\site\\" -and $_.FullName -notmatch "\\node_modules\\" -and
        $_.Name -notin $excludeNames
    }

# Build anchor map per file
$anchorMap = @{}
foreach ($f in $files) {
    $content = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    $headers = [regex]::Matches($content, "(?m)^#{1,6}\s+(.+?)\s*$")
    $anchors = @()
    foreach ($h in $headers) {
        $text = $h.Groups[1].Value.Trim()
        # GitHub-style anchor: lowercase, remove chars except letters/digits/spaces/hyphens/cyrillic, EACH space -> hyphen
        $anchor = $text.ToLower()
        $anchor = $anchor -replace "[^\w\s\u0400-\u04FF-]", ""
        $anchor = $anchor -replace "\s", "-"
        $anchors += $anchor
    }
    $anchorMap[$f.FullName] = $anchors
}

# Collect all anchor links
$broken = @()
foreach ($f in $files) {
    $content = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    $lines = $content -split $LF
    $inCode = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        if ($ln -match ("^\s*" + [regex]::Escape($BT3))) { $inCode = -not $inCode; continue }
        if ($inCode) { continue }
        $matches = [regex]::Matches($ln, "\[[^\]]*\]\(([^)]*#[^)]+)\)")
        foreach ($m in $matches) {
            $link = $m.Groups[1].Value.Trim()
            if ($link -match "^https?:" -or $link -match "^mailto:") { continue }
            $parts = $link -split "#", 2
            $path = $parts[0]
            $anchor = $parts[1]
            if ($anchor -eq "") { continue }
            $decoded = [System.Uri]::UnescapeDataString($path)
            if ($decoded -eq "") {
                $targetFile = $f.FullName
            } else {
                $dir = $f.Directory.FullName
                $combined = Join-Path $dir $decoded
                try { $targetFile = [System.IO.Path]::GetFullPath($combined) } catch { continue }
            }
            if (-not (Test-Path $targetFile)) { continue }
            if (-not $anchorMap.ContainsKey($targetFile)) { continue }
            $anchorLower = $anchor.ToLower()
            if ($anchorMap[$targetFile] -notcontains $anchorLower) {
                $rel = $f.FullName.Replace($repo + "\", "")
                $broken += "${rel}:$($i+1): $link"
            }
        }
    }
}

if ($broken.Count -eq 0) {
    if (-not $Quiet) { Write-Host "OK: 0 broken anchor links" -ForegroundColor Green }
    exit 0
} else {
    Write-Host "WARN: $($broken.Count) broken anchor link(s):" -ForegroundColor Yellow
    $broken | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    exit 1
}