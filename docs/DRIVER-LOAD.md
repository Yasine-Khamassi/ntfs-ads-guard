# Loading AdsGuard.sys in a Windows 11 test VM

AdsGuard.sys is test-signed and uses a development altitude. Load it only in a disposable VM with a checkpoint you can revert to. Never on a workstation or a host.

Commands marked **host** run on the machine that owns the VM. Everything else runs **inside the VM** in an elevated PowerShell 7 prompt.

## 1. Create the VM

### Hyper-V (host, elevated)

```powershell
$name = 'AdsGuardLab'
New-VM -Name $name -Generation 2 -MemoryStartupBytes 4GB `
       -NewVHDPath "C:\VMs\$name.vhdx" -NewVHDSizeBytes 64GB -SwitchName 'Default Switch'
Set-VMProcessor -VMName $name -Count 2
Set-VMKeyProtector -VMName $name -NewLocalKeyProtector     # Windows 11 needs a TPM
Enable-VMTPM -VMName $name
Set-VMFirmware -VMName $name -EnableSecureBoot Off          # test signing does not work with Secure Boot on
Add-VMDvdDrive -VMName $name -Path 'C:\ISO\Win11_x64.iso'
Set-VMFirmware -VMName $name -FirstBootDevice (Get-VMDvdDrive -VMName $name)
Start-VM -Name $name
```

Install Windows 11, sign in with a local administrator account, install PowerShell 7, then:

```powershell
Checkpoint-VM -Name AdsGuardLab -SnapshotName 'clean'      # host
```

### VMware Workstation

Create a Windows 11 x64 VM with 4 GB RAM, 2 vCPUs, 64 GB disk, and an encrypted VM with a virtual TPM. Under **VM Settings > Options > Advanced**, select UEFI and clear **Enable secure boot**. Install Windows 11 and PowerShell 7, then take a snapshot named `clean`.

## 2. Turn on test signing

```powershell
bcdedit /enum '{current}' | Select-String testsigning   # note the current value
bcdedit /set testsigning on
Restart-Computer
```

If `bcdedit` answers "The value is protected by Secure Boot policy", Secure Boot is still on. Turn it off in the VM firmware settings (step 1) and try again. After the reboot the desktop shows "Test Mode" in the bottom right corner.

## 3. Get the build

Either build it yourself (README, Build section) or download two artifacts from a green CI run on the Actions page: `adsguard-package` (driver package and `verifier.ps1`) and `ads-guard-collector` (collector and `rules.json`). Copy these into the VM, for example to `C:\lab`:

```text
C:\lab\AdsGuard\AdsGuard.sys
C:\lab\AdsGuard\AdsGuard.inf
C:\lab\AdsGuard\adsguard.cat
C:\lab\ads-guard-collector.exe
C:\lab\rules.json                (config/rules.json)
C:\lab\verifier.ps1              (tools/verifier.ps1)
```

Check that the driver carries the test signature:

```powershell
Get-AuthenticodeSignature C:\lab\AdsGuard\AdsGuard.sys | Format-List Status, SignerCertificate
```

`Status` is `UnknownError` (the test root is not trusted in user mode) and the signer is `WDKTestCert ...`. That is expected; the kernel accepts it because test signing is on.

## 4. Check the altitude is free

```powershell
fltmc filters
```

No filter should be listed at 389992. If one is, pick another free value (docs/ALTITUDE.md) and change it in step 5.

## 5. Install

Pick one of the two ways.

### A. With the INF (preferred)

```powershell
cd C:\lab\AdsGuard
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 .\AdsGuard.inf
```

This copies the driver to `C:\Windows\System32\drivers`, creates the `AdsGuard` service in the `FSFilter Activity Monitor` group, and writes the instance and altitude keys.

### B. With `sc.exe` and the registry

```powershell
Copy-Item C:\lab\AdsGuard\AdsGuard.sys C:\Windows\System32\drivers\AdsGuard.sys
sc.exe create AdsGuard type= filesys start= demand error= normal `
       binPath= System32\drivers\AdsGuard.sys group= "FSFilter Activity Monitor" depend= FltMgr `
       DisplayName= "NTFS ADS Guard Minifilter"
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\AdsGuard\Parameters\Instances'
New-Item -Path "$key\AdsGuard Instance" -Force | Out-Null
Set-ItemProperty -Path $key -Name DefaultInstance -Value 'AdsGuard Instance'
Set-ItemProperty -Path "$key\AdsGuard Instance" -Name Altitude -Value '389992'
Set-ItemProperty -Path "$key\AdsGuard Instance" -Name Flags -Value 0 -Type DWord
```

Without the instance keys the service starts but Filter Manager attaches no instance, so nothing is reported.

## 6. Load and check

```powershell
sc.exe start AdsGuard          # or: fltmc load AdsGuard
sc.exe query AdsGuard          # STATE: 4 RUNNING
fltmc filters                  # AdsGuard, 389992
fltmc instances -f AdsGuard    # one instance per NTFS volume, none on FAT or ReFS
```

| Error from `fltmc load` / `sc start` | Meaning |
| --- | --- |
| `0x80070241` / 577 | Signature rejected. Test signing is off, or Secure Boot is on. |
| `0x801F0011` | Altitude collision. Another filter uses 389992. |
| `0x80070002` / 2 | Service or file missing. Re-run step 5. |
| `0x80070005` / 5 | Prompt is not elevated. |

## 7. Run the collector and generate events

Prompt 1:

```powershell
C:\lab\ads-guard-collector.exe --config C:\lab\rules.json --output C:\lab\events.jsonl
```

It prints `Connected to the AdsGuard port.` Prompt 2:

```powershell
New-Item -ItemType Directory C:\lab\t -Force | Out-Null
Set-Content C:\lab\t\host.txt 'host file'

# create + write (write_source "handle")
Set-Content C:\lab\t\host.txt -Stream payload.bin -Value 'hello'

# set_size, set_size_class "end_of_file", requested_size 65536
$fs = [IO.File]::Open('C:\lab\t\host.txt:payload.bin', 'Open', 'ReadWrite')
$fs.SetLength(65536); $fs.Dispose()

# write through a mapped view (write_source "paging")
$fs  = [IO.File]::Open('C:\lab\t\host.txt:payload.bin', 'Open', 'ReadWrite')
$mmf = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($fs, $null, 0, 'ReadWrite', 'None', $false)
$view = $mmf.CreateViewAccessor()
$view.Write(0, [byte]0x41); $view.Flush()
$view.Dispose(); $mmf.Dispose(); $fs.Dispose()

# a scored event: PE-looking content, so the parent file gets hashed
$b = [byte[]]::new(1024); [Security.Cryptography.RandomNumberGenerator]::Fill($b)
$b[0]=0x4D; $b[1]=0x5A; [BitConverter]::GetBytes([int]64).CopyTo($b,0x3C); $b[64]=0x50; $b[65]=0x45
Set-Content C:\lab\t\host.txt -Stream tool.exe -Value $b -AsByteStream
```

Stop the collector with Ctrl+C and look at the records:

```powershell
Get-Content C:\lab\events.jsonl | ConvertFrom-Json |
  Format-Table operation, write_source, stream_name, bytes_written, requested_size, handle_open_ms, severity, parent_sha256_status
```

Expected: `create` and `write`/`handle` for `payload.bin`, `open` and `set_size` for the `SetLength` call, `open` and `write`/`paging` for the mapped view (`process` is the PowerShell that opened it), and for `tool.exe` a `high` severity with `parent_sha256_status` `complete`. If the paging record is missing, the page may not have been flushed yet; it is sent when the mapped page writer writes the page, which can take a while.

## 8. Driver Verifier (optional, recommended for the first run)

See [VERIFIER.md](VERIFIER.md). In short:

```powershell
pwsh -File C:\lab\verifier.ps1      # tools/verifier.ps1: verifier /flags 0x209BB /driver AdsGuard.sys
Restart-Computer
# steps 6 and 7 again, then:
fltmc unload AdsGuard               # Pool Tracking checks for leaks here
verifier /query
pwsh -File C:\lab\verifier.ps1 -Undo
Restart-Computer
```

## 9. Uninstall

```powershell
# stop the collector first (Ctrl+C)
fltmc unload AdsGuard
```

Then, matching the way you installed:

```powershell
# A. INF
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 C:\lab\AdsGuard\AdsGuard.inf

# B. sc.exe
sc.exe delete AdsGuard
Remove-Item C:\Windows\System32\drivers\AdsGuard.sys
```

Restore the boot setting and reboot:

```powershell
bcdedit /set testsigning off
Restart-Computer
```

Check that it is gone: `fltmc filters` does not list AdsGuard and `sc.exe query AdsGuard` reports error 1060. Reverting to the `clean` checkpoint does all of this in one step and is the safest way to finish.
