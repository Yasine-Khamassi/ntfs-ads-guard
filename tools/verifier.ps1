#Requires -Version 5.1
<#
.SYNOPSIS
Turns Driver Verifier on or off for AdsGuard.sys inside a disposable test VM.

.DESCRIPTION
Run this inside the VM from an elevated prompt, never on a workstation. It
refuses to run on a machine that does not look like a virtual machine unless
-Force is given.

Default flags are 0x209BB, the "standard settings" set:
  0x00001  Special Pool
  0x00002  Force IRQL Checking
  0x00008  Pool Tracking
  0x00010  I/O Verification
  0x00020  Deadlock Detection
  0x00080  DMA Checking
  0x00100  Security Checks
  0x00800  Miscellaneous Checks
  0x20000  DDI Compliance Checking
-LowResources adds 0x00004 (Randomized Low Resources Simulation), which
makes pool allocations and other requests fail at random. Use it in a
separate run: failures it injects show up as events_lost records and
missing contexts, which is the behavior under test.

Settings take effect after a reboot. Undo with -Undo, then reboot.

.EXAMPLE
pwsh -File tools\verifier.ps1                 # enable standard flags, then reboot
pwsh -File tools\verifier.ps1 -LowResources   # standard flags plus low resources simulation
pwsh -File tools\verifier.ps1 -Query          # show what is active now
pwsh -File tools\verifier.ps1 -Undo           # remove all verifier settings, then reboot
#>
[CmdletBinding(DefaultParameterSetName = 'Enable')]
param(
    [Parameter(ParameterSetName = 'Enable')][switch]$LowResources,
    [Parameter(ParameterSetName = 'Undo', Mandatory = $true)][switch]$Undo,
    [Parameter(ParameterSetName = 'Query', Mandatory = $true)][switch]$Query,
    [string]$Driver = 'AdsGuard.sys',
    [switch]$Force
)
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated prompt.'
}

$verifier = Join-Path $env:SystemRoot 'System32\verifier.exe'

if ($Query) {
    & $verifier /querysettings
    & $verifier /query
    return
}

if ($Undo) {
    # /reset clears every Driver Verifier setting on the machine, not only
    # this driver's. That is the intended state for a lab VM.
    & $verifier /reset
    Assert-Verifier '/reset'
    Write-Host 'Driver Verifier settings removed. Reboot to finish.'
    return
}

$system = Get-CimInstance Win32_ComputerSystem
$looksVirtual = $system.Model -match 'Virtual|VMware|KVM|QEMU|HVM' -or $system.Manufacturer -match 'VMware|QEMU|Xen|innotek|Parallels'
if (-not $looksVirtual -and -not $Force) {
    throw "This does not look like a VM (model '$($system.Model)'). Driver Verifier bugchecks on the first violation. Use -Force only if you are sure."
}

$flags = 0x209BB
if ($LowResources) { $flags = $flags -bor 0x4 }
$hex = '0x{0:X}' -f $flags

& $verifier /flags $hex /driver $Driver
Assert-Verifier '/flags'
Write-Host "Driver Verifier set to $hex for $Driver. Reboot, load the driver, then run the workload."
Write-Host "Undo: pwsh -File tools\verifier.ps1 -Undo  (or: verifier /reset), then reboot."
