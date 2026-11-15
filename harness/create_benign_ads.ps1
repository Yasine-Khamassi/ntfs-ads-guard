param([string]$Directory = "$env:TEMP\ads-guard-validation")
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Directory | Out-Null
$file = Join-Path $Directory 'notes.txt'
Set-Content -LiteralPath $file -Value 'Benign ADS validation fixture.' -Encoding utf8
Set-Content -LiteralPath "${file}:review.txt" -Value 'Review notes for a test file.' -Encoding utf8
Set-Content -LiteralPath "${file}:Zone.Identifier" -Value "[ZoneTransfer]`nZoneId=3" -Encoding ascii
$header = [byte[]]::new(1024)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($header)
$header[0] = 0x4D; $header[1] = 0x5A
[BitConverter]::GetBytes([int]64).CopyTo($header, 0x3C)
$header[64] = 0x50; $header[65] = 0x45; $header[66] = 0; $header[67] = 0
[System.IO.File]::WriteAllBytes("${file}:synthetic.exe", $header)
Write-Host "Created benign streams on $file"
Get-Item -LiteralPath $file -Stream * | Format-Table Stream,Length
Write-Host 'Run the collector and inspect its JSONL output for review.txt and Zone.Identifier.'
