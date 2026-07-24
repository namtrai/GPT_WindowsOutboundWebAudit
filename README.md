# GPT_WindowsOutboundWebAudit

PowerShell utility to monitor outbound HTTP/HTTPS traffic on Windows Server and identify the responsible process as much as Windows exposes.

## Purpose

Use this when a server is unexpectedly sending outbound TCP 80/443 traffic and you need readable logs showing:

- destination IP and port
- source IP and port
- PID
- process name
- executable path
- command line
- parent process
- Windows service mapping, especially for `svchost.exe`
- Authenticode signature status/signer when available

## Required files

Required to run:

- `scripts/Monitor-OutboundWeb.ps1`

Reference only:

- `README.md`

Safe to delete after copying the script to the Windows server:

- The whole project folder on this Linux/OpenClaw machine, if no longer needed.

## How to run on Windows Server

Open **PowerShell as Administrator**.

Create script folder:

```powershell
New-Item -ItemType Directory -Force C:\Temp\OutboundWebAudit | Out-Null
```

Copy `scripts/Monitor-OutboundWeb.ps1` to:

```text
C:\Temp\OutboundWebAudit\Monitor-OutboundWeb.ps1
```

Run for 24 hours:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Temp\OutboundWebAudit\Monitor-OutboundWeb.ps1 -DurationHours 24
```

Run for 2 hours:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Temp\OutboundWebAudit\Monitor-OutboundWeb.ps1 -DurationHours 2
```

Run and disable audit automatically when the script exits:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Temp\OutboundWebAudit\Monitor-OutboundWeb.ps1 -DurationHours 24 -DisableAuditOnExit
```

Stop manually:

```text
Ctrl + C
```

## Output files

Default output folder:

```text
C:\Temp\OutboundWebAudit
```

The script writes timestamped files:

```text
outbound-web-YYYYMMDD-HHMMSS.log
outbound-web-live-YYYYMMDD-HHMMSS.csv
outbound-web-security-audit-YYYYMMDD-HHMMSS.csv
```

Windows Firewall text log is also enabled here:

```text
C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

## Quick view after running

List output files:

```powershell
Get-ChildItem C:\Temp\OutboundWebAudit | Sort-Object LastWriteTime -Descending | Select-Object Name,Length,LastWriteTime
```

Open readable log:

```powershell
notepad (Get-ChildItem C:\Temp\OutboundWebAudit\outbound-web-*.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
```

Show compact audit result:

```powershell
Import-Csv (Get-ChildItem C:\Temp\OutboundWebAudit\outbound-web-security-audit-*.csv | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName |
Sort-Object DstIP,DstPort,ProcessName |
Format-Table Time,Source,ProcessName,PID,DstIP,DstPort,Path,Services -Auto
```

## Important limitation

If Windows reports traffic as:

```text
PID=4 / System
```

then the connection is exposed at kernel/System level. The script records it, but Windows may not reveal the original user-mode application through built-in logs. In that case, combine this output with packet capture/SNI, EDR telemetry, or vendor logs.

## Cleanup

If audit was left enabled and you want to disable it:

```cmd
auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
```

Firewall logging can be left enabled during investigation. To disable it:

```cmd
netsh advfirewall set allprofiles logging droppedconnections disable
netsh advfirewall set allprofiles logging allowedconnections disable
```
