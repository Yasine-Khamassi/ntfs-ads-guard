param(
    [Parameter(Mandatory=$true)][string]$Exe,
    [Parameter(Mandatory=$true)][string]$Config
)
# End-to-end test of the user-mode pipeline without the driver: create the
# benign harness streams, run --scan, and check the JSONL records.
$ErrorActionPreference = 'Stop'
$exePath = (Resolve-Path -LiteralPath $Exe).Path
$configPath = (Resolve-Path -LiteralPath $Config).Path
$harness = Join-Path $PSScriptRoot '..\..\harness\create_benign_ads.ps1'
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("ads-guard-scan-" + [guid]::NewGuid().ToString('N'))
$out = Join-Path $temp 'scan.jsonl'

function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw "Assertion failed: $Message" } }

try {
    & $harness -Directory $temp | Out-Null
    & $exePath --scan $temp --config $configPath --output $out
    if ($LASTEXITCODE -ne 0) { throw "Scan returned exit code $LASTEXITCODE" }

    $records = @(Get-Content -LiteralPath $out | ForEach-Object { $_ | ConvertFrom-Json })
    $errors = @($records | Where-Object record_type -ne 'ads_event')
    Assert ($errors.Count -eq 0) "unexpected non-event records: $($errors | ConvertTo-Json -Compress)"
    $byName = @{}
    foreach ($r in $records) { $byName[$r.stream_name] = $r }
    Assert ($byName.Count -eq 3) "expected 3 streams, got: $($byName.Keys -join ', ')"

    $file = Join-Path $temp 'notes.txt'
    $review = $byName['review.txt']
    Assert ($review.operation -eq 'scan') 'operation is scan'
    Assert ($review.inspection_status -eq 'complete') 'review.txt fully inspected'
    Assert (-not $review.allowlisted) 'review.txt not allow-listed'
    Assert ($review.score -eq 10) "review.txt score 10, got $($review.score)"
    Assert ($review.pe_header -eq $false) 'review.txt is not PE'
    Assert ($null -eq $review.entropy) 'entropy withheld below entropy_min_bytes'
    Assert ($review.process_source -eq 'not_applicable') 'no process in scan mode'
    $expected = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.IO.File]::ReadAllBytes("${file}:review.txt"))) -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert ($review.sha256 -eq $expected) "sha256 matches ($($review.sha256) vs $expected)"
    Assert ($review.size -eq $review.inspection_bytes) 'size equals bytes read'

    $zone = $byName['Zone.Identifier']
    Assert ($zone.allowlisted) 'Zone.Identifier allow-listed'
    Assert ($zone.score -eq 0) 'Zone.Identifier score 0'
    Assert ($zone.severity -eq 'informational') 'Zone.Identifier informational'

    $pe = $byName['synthetic.exe']
    Assert ($pe.pe_header -eq $true) 'synthetic.exe has a PE header'
    Assert ($pe.reasons -contains 'pe_header') 'pe_header reason'
    Assert ($pe.reasons -contains 'executable_extension') 'executable_extension reason'
    Assert ($pe.reasons -contains 'high_entropy') 'high_entropy reason'
    Assert ($pe.severity -eq 'high') "synthetic.exe severity high, got $($pe.severity)"

    Write-Host "Scan test passed ($($records.Count) records)."
}
finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
