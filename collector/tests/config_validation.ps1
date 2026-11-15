param(
    [Parameter(Mandatory=$true)][string]$Exe,
    [Parameter(Mandatory=$true)][string]$ValidConfig
)
# Checks that the shipped configuration loads and that each kind of invalid
# configuration is rejected with a non-zero exit code.
$ErrorActionPreference = 'Stop'
$exePath = (Resolve-Path -LiteralPath $Exe).Path
$validPath = (Resolve-Path -LiteralPath $ValidConfig).Path
& $exePath --check-config --config $validPath
if ($LASTEXITCODE -ne 0) { throw "Valid configuration returned exit code $LASTEXITCODE" }

$base = Get-Content -LiteralPath $validPath -Raw
function Mutate([scriptblock]$Change) {
    $o = $base | ConvertFrom-Json
    & $Change $o
    return ($o | ConvertTo-Json -Depth 5)
}

$cases = [ordered]@{
    'malformed JSON'            = '{"allow_stream_names": [}'
    'duplicate key'             = $base -replace '^\{', '{"queue_capacity": 5,'
    'unordered thresholds'      = Mutate { param($o) $o.thresholds.low = 90 }
    'unknown root property'     = Mutate { param($o) $o | Add-Member -NotePropertyName unexpected -NotePropertyValue $true }
    'unknown weight'            = Mutate { param($o) $o.weights | Add-Member -NotePropertyName other -NotePropertyValue 1 }
    'missing property'          = Mutate { param($o) $o.PSObject.Properties.Remove('entropy_min_bytes') }
    'old suffix key'            = Mutate { param($o) $o | Add-Member -NotePropertyName allow_stream_suffixes -NotePropertyValue @(':Zone.Identifier') }
    'stream name with colon'    = Mutate { param($o) $o.allow_stream_names = @(':Zone.Identifier') }
    'extension without dot'     = Mutate { param($o) $o.executable_extensions = @('exe') }
    'empty string'              = Mutate { param($o) $o.allow_process_paths = @('') }
    'entropy out of range'      = Mutate { param($o) $o.entropy_threshold = 9 }
    'fractional size limit'     = Mutate { param($o) $o.stream_size_limit_bytes = 10.5 }
    'zero queue capacity'       = Mutate { param($o) $o.queue_capacity = 0 }
    'string where number'       = Mutate { param($o) $o.weights.pe_header = '50' }
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("ads-guard-config-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $index = 0
    foreach ($name in $cases.Keys) {
        $index++
        $path = Join-Path $temp "invalid-$index.json"
        [System.IO.File]::WriteAllText($path, $cases[$name], [System.Text.UTF8Encoding]::new($false))
        & $exePath --check-config --config $path 2>$null
        if ($LASTEXITCODE -eq 0) { throw "Invalid configuration was accepted: $name" }
    }
    Write-Host "Config validation checks passed ($index invalid cases rejected)."
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}
