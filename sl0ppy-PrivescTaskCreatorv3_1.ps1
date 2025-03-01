# Author: phoogeveen aka x0xr00t
# Description: Enhanced script for creating a scheduled task with advanced customization options.
# Version: 4.0

param(
    [string]$FilePath,
    [string]$CustTaskName = "ElevatedTask",  # Default task name if none is provided
    [datetime]$Time,                          # Optional start time
    [string]$RepeatInterval = "",            # Optional repeat interval (e.g., "PT1H" for hourly)
    [switch]$RunOnBattery,                    # Allow the task to run on battery
    [switch]$StartWhenAvailable,              # Start the task when available
    [switch]$Hidden,                          # Hide the task in the task scheduler
    [switch]$WakeToRun,                       # Wake the computer to run the task
    [switch]$NetworkRequired,                 # Run only if a network connection is available
    [string]$RunAsUser = "SYSTEM",           # User account to run the task
    [string]$MultipleInstancePolicy = "IgnoreNew", # Policy for handling multiple instances
    [string]$ExecutionTimeLimit = "PT0S"     # Max execution time (default unlimited)
)

if (-not $FilePath) {
    Write-Host "No -FilePath parameter provided. Please specify the path to the .ps1 script."
    $FilePath = Read-Host -Prompt "Enter the full path to the PowerShell script (.ps1)"
}

if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
    Write-Error "The specified file path '$FilePath' does not exist."
    exit
}

$currentDateTime = Get-Date
if (-not $Time) {
    $Time = $currentDateTime.AddMinutes(2)
    Write-Output "Defaulting start time to 2 minutes from now: $Time"
}

$formattedStartTime = $Time.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")

$disallowStartIfOnBatteries = if ($RunOnBattery) { "false" } else { "true" }
$startWhenAvailable = if ($StartWhenAvailable) { "true" } else { "false" }
$hiddenTask = if ($Hidden) { "true" } else { "false" }
$wakeToRun = if ($WakeToRun) { "true" } else { "false" }
$networkRequired = if ($NetworkRequired) { "true" } else { "false" }

$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$formattedStartTime</Date>
    <Author>$RunAsUser</Author>
    <URI>\$CustTaskName</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>$formattedStartTime</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
"@

if ($RepeatInterval) {
    $taskXml += @"  
    <Repetition>
      <Interval>$RepeatInterval</Interval>
      <StopAtDurationEnd>false</StopAtDurationEnd>
    </Repetition>
"@
}

$taskXml += @"  
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$RunAsUser</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>$MultipleInstancePolicy</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>$disallowStartIfOnBatteries</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>$disallowStartIfOnBatteries</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>$startWhenAvailable</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>$networkRequired</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>$hiddenTask</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>$wakeToRun</WakeToRun>
    <ExecutionTimeLimit>$ExecutionTimeLimit</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c start /min conhost.exe cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$FilePath`"</Arguments>
      <WorkingDirectory>$([System.IO.Path]::GetDirectoryName($FilePath))</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

try {
    Register-ScheduledTask -Xml $taskXml -TaskName $CustTaskName -Force
    Write-Output "Scheduled task '$CustTaskName' registered successfully."
} catch {
    Write-Error "Failed to register scheduled task: $_"
    exit
}

try {
    Start-ScheduledTask -TaskName $CustTaskName
    Write-Output "Scheduled task '$CustTaskName' started successfully."
} catch {
    Write-Error "Failed to start scheduled task: $_"
    exit
}

Start-Sleep -Seconds 5
try {
    $processId = Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -like "*powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$FilePath`""} | Select-Object -ExpandProperty ProcessId
    if ($processId) {
        Write-Output "Process ID: $processId"
    } else {
        Write-Output "Process not detected, might be running hidden or scheduled later."
    }
} catch {
    Write-Error "Failed to retrieve process ID: $_"
}
