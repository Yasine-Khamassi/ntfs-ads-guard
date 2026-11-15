# Driver Verifier and debugger output

AdsGuard.sys has only been compiled and statically analyzed. This page is the checklist for the first real run, in a test VM set up as in [DRIVER-LOAD.md](DRIVER-LOAD.md).

## Static checks in CI

| Check | Where | Status |
| --- | --- | --- |
| `/W4 /WX` compile | `driver` job, Build step | runs on every push |
| InfVerif | same build (WDK `Inf` item) | runs on every push |
| Code Analysis (`/analyze`) | `driver` job, Code Analysis step, `RunCodeAnalysis=true`, warnings fail the build | runs on every push |
| Static Driver Verifier | not run | SDV is not shipped in WDKs after build 26017; the build uses WDK 10.0.28000. It needs an older EWDK and cannot run on the hosted runner image as is. |

The Code Analysis step is the command-line form of **Driver > Code Analysis** in Visual Studio:

```powershell
msbuild driver/AdsGuard.vcxproj -t:Rebuild -p:Configuration=Release -p:Platform=x64 `
  -p:RunCodeAnalysis=true -p:CodeAnalysisTreatWarningsAsErrors=true -p:SignMode=Off
```

## Which Driver Verifier options matter here

`tools/verifier.ps1` turns on `0x209BB` (the standard set) for `AdsGuard.sys`. What each option catches in this driver:

| Option | Flag | What it checks in AdsGuard |
| --- | --- | --- |
| Special Pool | 0x1 | Overruns of the `ADSG_EVENT` buffer (5248 bytes) and the cached stream name in the stream context. `CopyName` truncates at the buffer size; this proves it. |
| Force IRQL Checking | 0x2 | Pages out pageable memory whenever IRQL is raised. `PostWrite` can run at `DISPATCH_LEVEL` and only touches the nonpaged contexts; `SendEvent` uses paged pool and must only run at `PASSIVE_LEVEL`. Any slip bugchecks with 0xA or 0xC4. |
| Pool Tracking | 0x8 | Leaks at unload: event buffers, the stream context name copy, image name strings from `SeLocateProcessImageName`. A leak bugchecks with 0xC4 sub-code 0x62 when the driver unloads. |
| I/O Verification | 0x10 | IRP handling. AdsGuard never completes or builds IRPs, so violations here point at Filter Manager usage, for example a callback returning a wrong status. |
| Deadlock Detection | 0x20 | Lock hierarchy. AdsGuard takes no locks of its own, but the name and size queries in post-create and pre-cleanup take file system locks; this checks they are taken in a consistent order. |
| DDI Compliance Checking | 0x20000 | Rules for the kernel calls: IRQL requirements of `FltGetStreamContext`, `FltQueueGenericWorkItem`, `ObDereferenceObject`, `ExFreePoolWithTag`, and reference counting. |
| Low Resources Simulation | 0x4 (not in 0x209BB) | Randomly fails allocations. Run it separately with `-LowResources`. Expect `events_lost` records and no crash: every allocation failure path must count a drop and keep going. |

When Driver Verifier is on for a minifilter, Filter Manager adds its own checks for that filter: context reference counts, callback return values, and use of `FLT_CALLBACK_DATA` after completion. Leaked context references show up when the filter unloads.

## Enabling and undoing

Inside the VM, elevated:

```powershell
pwsh -File tools\verifier.ps1          # verifier /flags 0x209BB /driver AdsGuard.sys
Restart-Computer
verifier /querysettings                # confirm AdsGuard.sys and 0x209BB are listed
```

Load the driver (DRIVER-LOAD.md, steps 5 and 6), start the collector, and run the workload in step 7 plus anything that stresses it: a large copy with many alternate streams, `robocopy` of a tree with streams, a build that writes thousands of files. Then unload with `fltmc unload AdsGuard`; Pool Tracking checks for leaks at that point.

Undo:

```powershell
pwsh -File tools\verifier.ps1 -Undo    # verifier /reset
Restart-Computer
```

If the VM bugchecks during boot because the driver was set to start early, boot into Safe Mode and run `verifier /reset`, or revert the checkpoint.

## Capturing `!verifier` and `!analyze -v`

There is no separate Driver Verifier log file. The record is the debugger output, so capture it to a text file and keep it with the bug.

### From a crash dump

Configure a kernel memory dump before the run:

```powershell
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name CrashDumpEnabled -Value 2
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name AutoReboot -Value 1
```

After a bugcheck the VM reboots and leaves `C:\Windows\MEMORY.DMP`. Copy it and `AdsGuard.pdb` (from the build output) to the host, then:

```powershell
$cmds = '.symfix; .sympath+ C:\lab\symbols; .reload; ' +
        '.logopen C:\lab\analysis.txt; !analyze -v; !verifier; lm vm AdsGuard; ' +
        '!fltkd.filters; .logclose; q'
& "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\kd.exe" -z C:\lab\MEMORY.DMP -c $cmds
```

Put `AdsGuard.pdb` in `C:\lab\symbols`. `analysis.txt` then holds the bugcheck code and parameters, the faulting stack, the Driver Verifier settings and pool statistics, and the loaded filters with their altitudes.

### Live, over the network (KDNET)

In the VM:

```powershell
bcdedit /debug on
bcdedit /dbgsettings net hostip:<host IP> port:50000   # prints a key
Restart-Computer
```

On the host, start the debugger with that key and log everything:

```powershell
& "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\kd.exe" -k net:port=50000,key=<key> -logo C:\lab\live.txt
```

When it stops on a Driver Verifier violation, run `!analyze -v` and `!verifier`, then `g` only if you want the bugcheck to proceed. Turn debugging off afterwards with `bcdedit /debug off`.

## What to record per run

- Windows build (`winver`), commit SHA of the driver, Driver Verifier flags.
- `verifier /query` output after the workload: it lists pool allocation counts and failed allocations when Low Resources Simulation was on.
- The collector's JSONL, including `events_lost` records.
- For any bugcheck: `analysis.txt` from above.
