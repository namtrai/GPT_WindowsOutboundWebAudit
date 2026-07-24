<#
.SYNOPSIS
  Monitor outbound HTTP/HTTPS activity on Windows and identify the process as much as Windows exposes.

.DESCRIPTION
  This script enables Windows Filtering Platform auditing, enables Windows Firewall text logging,
  and polls live TCP connections for outbound TCP 80/443. It writes readable logs and CSV files.

.NOTES
  Run PowerShell as Administrator.
  Some kernel-level traffic may appear as PID 4 / System; Windows may not expose the original user-mode app.
#>

param(
  [int]$DurationHours = 24,
  [int]$DurationMinutes = 0,
  [int]$IntervalSeconds = 1,
  [string]$OutDir = "C:\Temp\OutboundWebAudit",
  [switch]$DisableAuditOnExit,
  [switch]$Console
)

$ErrorActionPreference = "Continue"

New-Item -ItemType Directory -Force $OutDir | Out-Null

$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$ReadableLog = Join-Path $OutDir "outbound-web-$Stamp.log"
$LiveCsv = Join-Path $OutDir "outbound-web-live-$Stamp.csv"
$AuditCsv = Join-Path $OutDir "outbound-web-security-audit-$Stamp.csv"

function Write-Log {
  param([string]$Message)
  $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message"
  Add-Content -Path $ReadableLog -Value $line
  if ($Console) {
    Write-Host $line
  }
}

function Convert-DevicePathToDrivePath {
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return $Path
  }

  if ($Path -notmatch '^\\device\\harddiskvolume') {
    return $Path
  }

  foreach ($drive in Get-PSDrive -PSProvider FileSystem) {
    $root = $drive.Root.TrimEnd('\')
    $device = (cmd /c "mountvol $($drive.Root) /L" 2>$null | Select-Object -First 1).Trim()
    if ($device) {
      # Best effort only. Event log device paths are still kept if conversion fails.
    }
  }

  return $Path
}

function Get-ServicesForPid {
  param([int]$ServiceProcessId)

  return (Get-CimInstance Win32_Service |
    Where-Object { $_.ProcessId -eq $ServiceProcessId } |
    ForEach-Object { "$($_.Name)[$($_.DisplayName)]" }) -join "; "
}

function Get-ProcessInfoSafe {
  param([int]$ProcessId)

  if ($ProcessId -eq 4) {
    return [PSCustomObject]@{
      PID = 4
      ProcessName = "System"
      Path = "System"
      CommandLine = ""
      ParentPID = ""
      ParentName = ""
      Services = "Kernel/System - original app may not be exposed by Windows"
      SignatureStatus = ""
      Signer = ""
    }
  }

  $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId"
  $p2 = Get-Process -Id $ProcessId

  $processName = ""
  $path = ""
  $commandLine = ""
  $parentPid = ""
  $parentName = ""

  if ($proc) {
    $processName = $proc.Name
    $path = $proc.ExecutablePath
    $commandLine = $proc.CommandLine
    $parentPid = $proc.ParentProcessId
  }

  if (-not $processName -and $p2) {
    $processName = $p2.ProcessName
  }

  if ($parentPid) {
    $parent = Get-Process -Id $parentPid
    if ($parent) {
      $parentName = $parent.ProcessName
    }
  }

  $services = Get-ServicesForPid -ServiceProcessId $ProcessId

  $sigStatus = ""
  $signer = ""
  if ($path) {
    $sig = Get-AuthenticodeSignature $path
    if ($sig) {
      $sigStatus = $sig.Status
      if ($sig.SignerCertificate) {
        $signer = $sig.SignerCertificate.Subject
      }
    }
  }

  return [PSCustomObject]@{
    PID = $ProcessId
    ProcessName = $processName
    Path = $path
    CommandLine = $commandLine
    ParentPID = $parentPid
    ParentName = $parentName
    Services = $services
    SignatureStatus = $sigStatus
    Signer = $signer
  }
}

function Get-EventField {
  param(
    [string]$Message,
    [string]$FieldName
  )

  $match = [regex]::Match($Message, [regex]::Escape($FieldName) + ":\s+(.+)")
  if ($match.Success) {
    return $match.Groups[1].Value.Trim()
  }
  return ""
}

function Parse-AuditEvent {
  param($Event)

  $m = $Event.Message
  $pidText = Get-EventField -Message $m -FieldName "Process ID"
  $pidInt = 0

  if ($pidText -match '^0x[0-9a-fA-F]+$') {
    $pidInt = [Convert]::ToInt32($pidText, 16)
  } else {
    [int]::TryParse($pidText, [ref]$pidInt) | Out-Null
  }

  return [PSCustomObject]@{
    Time = $Event.TimeCreated
    RecordId = $Event.RecordId
    EventId = $Event.Id
    Action = if ($Event.Id -eq 5156) { "ALLOW" } elseif ($Event.Id -eq 5157) { "BLOCK" } else { "UNKNOWN" }
    AppFromEvent = Convert-DevicePathToDrivePath (Get-EventField -Message $m -FieldName "Application Name")
    PID = $pidInt
    SrcIP = Get-EventField -Message $m -FieldName "Source Address"
    SrcPort = Get-EventField -Message $m -FieldName "Source Port"
    DstIP = Get-EventField -Message $m -FieldName "Destination Address"
    DstPort = Get-EventField -Message $m -FieldName "Destination Port"
  }
}

function Enable-Auditing {
  Write-Log "Enabling Windows Filtering Platform audit"
  cmd /c 'auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable' | Out-Null
  cmd /c 'auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable' | Out-Null
  cmd /c 'wevtutil sl Security /ms:268435456' | Out-Null
}

function Disable-Auditing {
  Write-Log "Disabling Windows Filtering Platform audit"
  cmd /c 'auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable' | Out-Null
  cmd /c 'auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable' | Out-Null
}

function Enable-FirewallLogging {
  Write-Log "Enabling Windows Firewall text logging"
  New-Item -ItemType Directory -Force "C:\Windows\System32\LogFiles\Firewall" | Out-Null
  cmd /c 'netsh advfirewall set allprofiles logging filename %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' | Out-Null
  cmd /c 'netsh advfirewall set allprofiles logging maxfilesize 32768' | Out-Null
  cmd /c 'netsh advfirewall set allprofiles logging droppedconnections enable' | Out-Null
  cmd /c 'netsh advfirewall set allprofiles logging allowedconnections enable' | Out-Null
}

Write-Log "Starting outbound HTTP/HTTPS monitor"
Write-Log "Output directory: $OutDir"
Write-Log "Readable log: $ReadableLog"
Write-Log "Live CSV: $LiveCsv"
Write-Log "Security audit CSV: $AuditCsv"

Enable-Auditing
Enable-FirewallLogging

$seenLive = @{}
$seenAudit = @{}
$start = Get-Date
if ($DurationMinutes -gt 0) {
  $end = $start.AddMinutes($DurationMinutes)
} else {
  $end = $start.AddHours($DurationHours)
}
$lastAuditCheck = $start.AddMinutes(-10)

Write-Log "Monitoring outbound TCP 80/443 until $end"
Write-Log "Press Ctrl+C to stop. Use -DisableAuditOnExit if you want the script to turn audit off when exiting."

try {
  while ((Get-Date) -lt $end) {
    $now = Get-Date

    try {
      $connections = Get-NetTCPConnection -ErrorAction Stop |
        Where-Object {
          $_.RemotePort -in 80,443 -and
          $_.RemoteAddress -notin @("127.0.0.1", "::1", "0.0.0.0", "::") -and
          $_.State -in @("SynSent", "Established", "CloseWait", "FinWait1", "FinWait2")
        }
    } catch {
      Write-Log "[WARN] Get-NetTCPConnection failed: $($_.Exception.Message)"
      $connections = @()
    }

    foreach ($connection in $connections) {
      $liveKey = "$($connection.OwningProcess)|$($connection.LocalAddress)|$($connection.LocalPort)|$($connection.RemoteAddress)|$($connection.RemotePort)|$($connection.State)"

      if (-not $seenLive.ContainsKey($liveKey)) {
        $seenLive[$liveKey] = $true
        $processInfo = Get-ProcessInfoSafe -ProcessId $connection.OwningProcess

        $row = [PSCustomObject]@{
          Time = $now
          Source = "LIVE_NETTCP"
          LocalAddress = $connection.LocalAddress
          LocalPort = $connection.LocalPort
          RemoteAddress = $connection.RemoteAddress
          RemotePort = $connection.RemotePort
          State = $connection.State
          PID = $processInfo.PID
          ProcessName = $processInfo.ProcessName
          Path = $processInfo.Path
          CommandLine = $processInfo.CommandLine
          ParentPID = $processInfo.ParentPID
          ParentName = $processInfo.ParentName
          Services = $processInfo.Services
          SignatureStatus = $processInfo.SignatureStatus
          Signer = $processInfo.Signer
        }

        $row | Export-Csv $LiveCsv -Append -NoTypeInformation
        Write-Log "[LIVE] Process=$($row.ProcessName) PID=$($row.PID) $($row.LocalAddress):$($row.LocalPort) -> $($row.RemoteAddress):$($row.RemotePort) State=$($row.State) Path=$($row.Path) Services=$($row.Services)"
      }
    }

    try {
      $events = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = 5156,5157
        StartTime = $lastAuditCheck
      } -ErrorAction Stop
    } catch {
      if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound*") {
        $events = @()
      } else {
        Write-Log "[WARN] Get-WinEvent failed: $($_.Exception.Message)"
        $events = @()
      }
    }

    foreach ($event in $events) {
      if ($seenAudit.ContainsKey([string]$event.RecordId)) {
        continue
      }

      $parsed = Parse-AuditEvent -Event $event

      if ($parsed.DstPort -in @("80", "443")) {
        $seenAudit[[string]$event.RecordId] = $true
        $processInfo = Get-ProcessInfoSafe -ProcessId $parsed.PID

        $row = [PSCustomObject]@{
          Time = $parsed.Time
          Source = "SECURITY_$($parsed.EventId)_$($parsed.Action)"
          AppFromEvent = $parsed.AppFromEvent
          PID = $parsed.PID
          ProcessName = $processInfo.ProcessName
          Path = $processInfo.Path
          CommandLine = $processInfo.CommandLine
          ParentPID = $processInfo.ParentPID
          ParentName = $processInfo.ParentName
          Services = $processInfo.Services
          SrcIP = $parsed.SrcIP
          SrcPort = $parsed.SrcPort
          DstIP = $parsed.DstIP
          DstPort = $parsed.DstPort
          SignatureStatus = $processInfo.SignatureStatus
          Signer = $processInfo.Signer
        }

        $row | Export-Csv $AuditCsv -Append -NoTypeInformation
        Write-Log "[AUDIT-$($parsed.Action)] EventApp=$($row.AppFromEvent) Process=$($row.ProcessName) PID=$($row.PID) $($row.SrcIP):$($row.SrcPort) -> $($row.DstIP):$($row.DstPort) Path=$($row.Path) Services=$($row.Services)"
      }
    }

    $lastAuditCheck = $now.AddSeconds(-5)
    Start-Sleep -Seconds $IntervalSeconds
  }
}
catch {
  Write-Log "[ERROR] Monitor crashed: $($_.Exception.Message)"
  Write-Log "[ERROR] At: $($_.InvocationInfo.PositionMessage)"
}
finally {
  if ($DisableAuditOnExit) {
    Disable-Auditing
  }

  Write-Log "Monitor stopped"
  Write-Log "Readable log: $ReadableLog"
  Write-Log "Live CSV: $LiveCsv"
  Write-Log "Security audit CSV: $AuditCsv"
  Write-Log "Firewall log: C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
}
