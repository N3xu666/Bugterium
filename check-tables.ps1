# check-tables.ps1 - Validate markdown tables for inconsistent link usage.
# Finds tables where SOME rows have markdown links and OTHERS do not.
# This catches the "added a subcategory but forgot the link" class of bugs.
#
# WARN-only by default. Exit code 1 if inconsistent tables found (for CI).
#
# Usage:
#   .\check-tables.ps1
#   .\check-tables.ps1 -Quiet

param(
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
$utf8 = New-Object System.Text.UTF8Encoding($false)
$LF = [char]10

# Files excluded (same as check-anchors.ps1)
$excludeNames = @("MASTER_WORKFLOW.md", "_SITE_PLAN.md", "PROMPT_NEXT_SESSION.txt")

# Collect all .md files
$files = Get-ChildItem -Path $repo -Recurse -Filter *.md -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch "\\\.git\\" -and
        $_.FullName -notmatch "\\txt\\" -and
        $_.FullName -notmatch "\\tests\\" -and $_.FullName -notmatch "\\terraform\\" -and $_.FullName -notmatch "\\site\\" -and $_.FullName -notmatch "\\node_modules\\" -and
        $_.Name -notin $excludeNames
    }

$issues = @()

foreach ($f in $files) {
    $content = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    $lines = $content -split $LF

    $i = 0
    while ($i -lt $lines.Count) {
        $ln = $lines[$i]

        # Detect table start: a line starting with "|" followed by a separator line "|---|"
        if ($ln -match '^\|' -and ($i + 1) -lt $lines.Count -and $lines[$i + 1] -match '^\|[\s\-:|]+\|$') {
            # Collect the table
            $tableStart = $i
            $tableLines = @()
            $j = $i
            while ($j -lt $lines.Count -and $lines[$j] -match '^\|') {
                $tableLines += $lines[$j]
                $j++
            }
            $i = $j

            # Skip header (line 0) and separator (line 1); process data rows (2+)
            $dataRows = @()
            if ($tableLines.Count -gt 2) {
                $dataRows = $tableLines[2..($tableLines.Count - 1)]
            }

            # Filter out placeholder rows and rows that legitimately have no link.
            # A row is "legitimate non-link" if:
            #   - all cells are empty/dashes (placeholder)
            #   - the row starts with "none"/"pending"
            #   - the row's non-link text references a FOLDER (ends with "/") - not a file
            #   - the row contains "no dedicated file", "planned", "n/a", "tbd", "todo"
            $realRows = @()
            foreach ($row in $dataRows) {
                $cells = $row -split '\|' | ForEach-Object { $_.Trim() }
                $cells = $cells | Where-Object { $_ -ne '' }
                $joined = ($cells -join ' ').ToLower()

                # Pure placeholder
                if ($joined -match '^(none|pending|-|n/a|tbd|todo)') { continue }
                if (($cells | Where-Object { $_ -notmatch '^-+$' -and $_ -ne '' }).Count -eq 0) { continue }

                # Legitimate non-link: folder reference (ends with /) or explicit "no dedicated file"
                if ($row -notmatch '\]\(') {
                    $hasFolderRef = $false
                    foreach ($c in $cells) {
                        if ($c -match '/$') { $hasFolderRef = $true; break }
                    }
                    if ($hasFolderRef) { continue }
                    if ($joined -match 'no dedicated file|no file yet|not yet|planned') { continue }
                }

                $realRows += $row
            }

            if ($realRows.Count -lt 2) { continue }

            $rowsWithLink = 0
            $rowsWithoutLink = @()
            foreach ($row in $realRows) {
                if ($row -match '\]\(') {
                    $rowsWithLink++
                } else {
                    $rowsWithoutLink += $row
                }
            }

            # Issue: SOME rows have links, SOME don't
            if ($rowsWithLink -gt 0 -and $rowsWithoutLink.Count -gt 0) {
                $rel = $f.FullName.Replace($repo + "\", "")
                $issues += "${rel}:$($tableStart + 1): table has $rowsWithLink row(s) with links and $($rowsWithoutLink.Count) row(s) without"
            }
        } else {
            $i++
        }
    }
}

if ($issues.Count -eq 0) {
    if (-not $Quiet) { Write-Host "OK: 0 inconsistent tables" -ForegroundColor Green }
    exit 0
} else {
    Write-Host "WARN: $($issues.Count) inconsistent table(s):" -ForegroundColor Yellow
    $issues | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    exit 1
}