# Altitude

AdsGuard.sys loads at altitude **389992** in the **FSFilter Activity Monitor** group. That value is temporary and for development only. It is not assigned to this project.

## Why 389992

- AdsGuard observes and reports file I/O and never changes it, which is the definition of the Activity Monitor group.
- The previous value, 385250, is not free. Microsoft's own `UCPD.sys` (385250.5) and `ahflt.sys` (385250.3) are fractional altitudes under the integer 385250, so that integer belongs to Microsoft.
- Microsoft does not publish a reserved development sub-range. Its guidance for filters that are not shipping is to use any altitude value in development and test environments.
- In the [allocated altitudes list](https://learn.microsoft.com/windows-hardware/drivers/ifs/allocated-altitudes) (last updated October 2026) the highest Activity Monitor entry is 389560.5. Nothing between 389561 and 389999 is listed, so 389992 does not collide with any known filter today.

That list is updated once or twice a year and can lag behind new assignments. Before loading the driver on a VM that runs third-party security or backup software, check for a collision:

```powershell
fltmc filters            # look for anything at 389992
fltmc instances -v C:    # altitudes attached to the system volume
```

To use a different value, change `Altitude` in the `[Strings]` section of `driver/AdsGuard.inf`, rebuild, and reinstall. The value is read from `HKLM\SYSTEM\CurrentControlSet\Services\AdsGuard\Instances\AdsGuard Instance\Altitude` when the filter loads.

## Load order groups and ranges

From [Load order groups and altitudes for minifilter drivers](https://learn.microsoft.com/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers). Higher altitudes sit further from the file system.

| Load order group | Altitude range |
| --- | --- |
| Filter | 420000-429999 |
| FSFilter Top | 400000-409999 |
| **FSFilter Activity Monitor** | **360000-389999** |
| FSFilter Undelete | 340000-349999 |
| FSFilter Anti-Virus | 320000-329999 |
| FSFilter Replication | 300000-309999 |
| FSFilter Continuous Backup | 280000-289999 |
| FSFilter Content Screener | 260000-269999 |
| FSFilter Quota Management | 240000-249999 |
| FSFilter System Recovery | 220000-229999 |
| FSFilter Cluster File System | 200000-209999 |
| FSFilter HSM | 180000-189999 |
| FSFilter Imaging | 170000-175000 |
| FSFilter Compression | 160000-169999 |
| FSFilter Encryption | 140000-149999 |
| FSFilter Virtualization | 130000-139999 |
| FSFilter Physical Quota Management | 120000-129999 |
| FSFilter Open File | 100000-109999 |
| FSFilter Security Enhancer | 80000-89999 |
| FSFilter Copy Protection | 60000-69999 |
| FSFilter Bottom | 40000-49999 |
| FSFilter System | 20000-29999 (internal) |
| FSFilter Infrastructure | below 20000 (internal) |

Sitting high in Activity Monitor means AdsGuard sees requests before anti-virus and encryption filters act on them. That is what it should report: what the process asked for.

## Getting a permanent altitude

Microsoft assigns altitudes only to filters planned for a **publicly shipping product**. Requests for internal, test or other non-public filters are not processed. This repository is a lab project, so as it stands it does not qualify, and 389992 is the right choice for it.

If AdsGuard becomes part of a product that ships publicly:

1. Wait until the feature set and load order group are stable.
2. Send the request below as a plain ASCII email to `fsfcomm@microsoft.com` with the subject `Filter altitude request`. Every field must be filled in.
3. Allow 30 business days. There is no faster path.
4. Put the assigned value in `driver/AdsGuard.inf`, remove the development-only comments there and in the README, and bump `DriverVer`.

Once an integer altitude is assigned, later filters in the same group can use fractional values under it (for example 37xxxx.5). Each new fractional value still has to be reported to the same address.

### Email template

```text
Subject: Filter altitude request

Hi,

Below is the request information to assign an altitude for the NTFS ADS
Guard file system minifilter.

Company name: <company, or your full legal name if you ship as an individual>
Contact e-mail: <long-term alias, not a personal mailbox; the altitude is sent here>
Product name: NTFS ADS Guard
Product URL: <public product page>
Product/Filter description: AdsGuard.sys observes create, write, paging
write and set-information (end of file, allocation) operations on named
NTFS $DATA streams (alternate data streams). For each one it sends the
requesting process, stream name, size and handle timing to a user-mode
service over a Filter Manager communication port. It never blocks, changes
or redirects I/O. The service inspects the stream content and scores it
for detection engineering and incident response.
Filter filename: AdsGuard.sys
Filter type: FileSystem
Filter start-type: Demand
Requested filter load order group: FSFilter Activity Monitor
Requested altitude: <a value from 360000-389999 not in the allocated list>
Additional information: Expected first public release: <month and year>.
Distribution: <how it ships, e.g. signed installer through the product site>.
The filter is currently tested at the development value 389992.

Thanks,
<name>
```

## References

- [Load order groups and altitudes for minifilter drivers](https://learn.microsoft.com/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)
- [Request a filter altitude identifier](https://learn.microsoft.com/windows-hardware/drivers/ifs/minifilter-altitude-request)
- [Allocated filter altitudes](https://learn.microsoft.com/windows-hardware/drivers/ifs/allocated-altitudes)
