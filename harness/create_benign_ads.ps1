#Requires -Version 7
# Creates a test file with three benign named streams:
#   review.txt       short text, scored as an ordinary named stream
#   Zone.Identifier  allow-listed by the default rules
#   synthetic.exe    random bytes behind an MZ/PE signature; not runnable
# Use a disposable directory. Nothing outside -Directory is touched.
param([string]$Directory = (Join-Path ([System.IO.Path]::GetTempPath()) 'ads-guard-validation'))
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Directory | Out-Null
$file = Join-Path $Directory 'notes.txt'
Set-Content -LiteralPath $file -Value 'Benign ADS validation fixture.' -Encoding utf8
Set-Content -LiteralPath $file -Stream 'review.txt' -Value 'Review notes for a test file.' -Encoding utf8
Set-Content -LiteralPath $file -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`nZoneId=3" -Encoding ascii
$header = [byte[]]::new(1024)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($header)
$header[0] = 0x4D; $header[1] = 0x5A
[BitConverter]::GetBytes([int]64).CopyTo($header, 0x3C)
$header[64] = 0x50; $header[65] = 0x45; $header[66] = 0; $header[67] = 0
Set-Content -LiteralPath $file -Stream 'synthetic.exe' -Value $header -AsByteStream
Write-Host "Created benign streams on $file"
Get-Item -LiteralPath $file -Stream * | Format-Table Stream, Length
Write-Host "Inspect them without the driver: ads-guard-collector.exe --scan `"$Directory`" --output -"
