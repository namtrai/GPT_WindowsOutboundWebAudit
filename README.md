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

Run for 10 minutes as a quick test:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Temp\OutboundWebAudit\Monitor-OutboundWeb.ps1 -DurationMinutes 10
```

## Optional: Procmon deep capture

Procmon is Microsoft Sysinternals Process Monitor. It can capture deeper process/network activity and preserve stack details in `.pml` format. This is useful when Windows only reports traffic as `PID=4 / System`.

Download Procmon from Microsoft Sysinternals and place it here:

```text
C:\Tools\Procmon64.exe
```

Run with Procmon capture enabled:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Temp\OutboundWebAudit\Monitor-OutboundWeb.ps1 -DurationMinutes 10 -EnableProcmon
```

For long captures, create a Procmon config first with filters and **Filter -> Drop Filtered Events** enabled, then run:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Temp\OutboundWebAudit\Monitor-OutboundWeb.ps1 -DurationMinutes 10 -EnableProcmon -ProcmonConfigPath C:\Temp\procmon-network-filter.pmc
```

If Procmon is somewhere else:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Temp\OutboundWebAudit\Monitor-OutboundWeb.ps1 -DurationMinutes 10 -EnableProcmon -ProcmonPath "D:\Tools\Procmon64.exe"
```

Procmon outputs:

```text
outbound-web-procmon-YYYYMMDD-HHMMSS.pml
outbound-web-procmon-YYYYMMDD-HHMMSS.csv
```

For PID 4/System cases, open the `.pml` in Procmon GUI and inspect the event Stack. Driver names such as `csagent.sys`, backup drivers, VPN drivers, or AV filter drivers are the key clue.

Recommended Procmon filter for small files:

```text
Path contains 35.162.239.174 Include
Path contains 169.254.169.254 Include
```

Then enable:

```text
Filter -> Drop Filtered Events
```

Save config:

```text
File -> Save Configuration... -> C:\Temp\procmon-network-filter.pmc
```

By default, the script writes logs to files only and does not print every event to the console.

If you want console output too:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Temp\OutboundWebAudit\Monitor-OutboundWeb.ps1 -DurationHours 24 -Console
```

Run and disable audit automatically when the script exits:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Temp\OutboundWebAudit\Monitor-OutboundWeb.ps1 -DurationHours 24 -DisableAuditOnExit
```

If the monitor stops early, open the latest `.log` file and look for `[ERROR]` or `[WARN]` lines. Newer versions log the crash reason instead of failing silently.

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
outbound-web-procmon-YYYYMMDD-HHMMSS.pml, only when `-EnableProcmon` is used
outbound-web-procmon-YYYYMMDD-HHMMSS.csv, only when `-EnableProcmon` is used
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
