param(
    [Parameter(Mandatory=$true)][string]$Exe,
    [Parameter(Mandatory=$true)][string]$ValidConfig
)
$ErrorActionPreference = 'Stop'
$exePath = (Resolve-Path -LiteralPath $Exe).Path
$validPath = (Resolve-Path -LiteralPath $ValidConfig).Path
& $exePath --check-config --config $validPath
if ($LASTEXITCODE -ne 0) { throw "Valid configuration returned exit code $LASTEXITCODE" }

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("ads-guard-config-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $badConfigs = @(
        '{"allow_stream_suffixes": [}',
        '{"allow_stream_suffixes": [], "allow_stream_suffixes": [], "allow_process_paths": [], "entropy_threshold": 7, "stream_size_limit_bytes": 100, "thresholds": {"low": 1, "medium": 2, "high": 3}, "weights": {"named_stream": 1, "pe_header": 1, "high_entropy": 1, "executable_extension": 1, "system_binary_host": 1}}',
        '{"allow_stream_suffixes": [], "allow_process_paths": [], "entropy_threshold": 7, "stream_size_limit_bytes": 100, "thresholds": {"low": 9, "medium": 2, "high": 3}, "weights": {"named_stream": 1, "pe_header": 1, "high_entropy": 1, "executable_extension": 1, "system_binary_host": 1}}',
        '{"allow_stream_suffixes": [], "allow_process_paths": [], "entropy_threshold": 7, "stream_size_limit_bytes": 100, "thresholds": {"low": 1, "medium": 2, "high": 3}, "weights": {"named_stream": 1, "pe_header": 1, "high_entropy": 1, "executable_extension": 1, "system_binary_host": 1}, "unexpected": true}'
    )
    $index = 0
    foreach ($text in $badConfigs) {
        $index++
        $path = Join-Path $temp "invalid-$index.json"
        [System.IO.File]::WriteAllText($path, $text, [System.Text.UTF8Encoding]::new($false))
        & $exePath --check-config --config $path 2>$null
        if ($LASTEXITCODE -eq 0) { throw "Invalid configuration $index was accepted" }
    }
    Write-Host 'Config validation checks passed.'
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}
