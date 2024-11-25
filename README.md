### sl0ppy-privesctaskcreator

* sl0ppy-privesctaskcreator is a PowerShell-based script that automates the creation of a scheduled task with elevated privileges. Designed for flexibility, this tool allows users to specify a custom PowerShell script to execute under the highest available permissions, making it useful for system administration, testing, or other scenarios requiring privilege escalation.

## version V2.0
improvements:
* -CustTaskName Flag added
* -Time Flag added 

## Features
```
   * Dynamic Script Execution: Specify the PowerShell script to run at execution time with the new -File option.
   * Automated Scheduling: Schedules a task to run with elevated privileges, automatically starting at a calculated future time.
   * Hidden and Elevated Task: The task runs hidden from user interfaces and with the highest privileges available.
   * Error Handling: Includes robust checks for task registration, execution, and process validation to ensure smooth operation.
   * Interactive or Scripted Use: Prompts for a file path if none is specified, making it versatile for different usage scenarios.
```
## Prerequisites
```
   * Windows OS: Compatible with Windows-based operating systems.
   * Administrator Privileges: Required to create and execute tasks with elevated permissions.
   * PowerShell: Pre-installed on most modern Windows systems.
   * PowerShell Script: Ensure the target script (.ps1) exists at the specified path.
```
## Installation

   * Clone this repository:

```git clone https://github.com/<your-username>/sl0ppy-privesctaskcreator.git```

* Navigate to the directory:

    ```cd sl0ppy-privesctaskcreator```

* The script is ready to run.

## Usage

   * Provide a PowerShell Script: Use the -File parameter to specify the full path to the .ps1 script you want the scheduled task to execute:

```.\sl0ppy-privesctaskcreator.ps1 -File "C:\Path\To\Your\Script.ps1"```

If -File is not provided, the script will prompt you to input the path interactively.

* Specify a Custom Task Name

```.\TaskEscalation.ps1 -FilePath "C:\path\to\script.ps1" -CustTaskName "CustomTask"```

* Specify a Custom Start Time

```.\TaskEscalation.ps1 -FilePath "C:\path\to\script.ps1" -Time (Get-Date).AddHours(1)```

* Run with Administrator Privileges: Open PowerShell as an administrator to ensure the script has the necessary permissions.

* Verify Task Creation: After execution, the task will:
```
    Register a new scheduled task named ElevatedTask.
    Start the task immediately.
    Provide the process ID (PID) of the running task for verification.
```

## Configuration
* Key Parameters

    * PowerShell Script Path: Specify the script's path via the -File parameter:

    ```.\sl0ppy-privesctaskcreator.ps1 -File "C:\Scripts\MyScript.ps1"```

    * Task Start Time: The task start time is dynamically calculated to begin 2 minutes after the script runs. Modify the $startTime logic for custom timing.

Scheduled Task Settings

The scheduled task is configured with the following defaults:
```
    Run Level: Highest available privileges.
    Visibility: Hidden.
    Triggers: Starts at the specified time.
    Execution Policy: Bypasses restrictions to allow the specified script to run.
```
* You can customize these settings by editing the $taskXml definition in the script.

## Examples
Run a Script Immediately

To execute a PowerShell script at the earliest opportunity:

```.\sl0ppy-privesctaskcreator.ps1 -File "C:\Scripts\TestScript.ps1"```

Custom Script Path Prompt

If no -File parameter is provided, the script will prompt you to enter the full path interactively.
## Troubleshooting
```
    Task Not Created: Ensure PowerShell is running with elevated (Administrator) permissions.

    File Path Issues: Verify that the specified .ps1 file exists and the path is correct.

    Task Not Executing: Check Task Scheduler logs in Event Viewer:
        Applications and Services Logs > Microsoft > Windows > TaskScheduler.

    Process Not Found: Confirm the script you specified runs successfully when executed manually.
```

## License

* This project is licensed under the GNU GENERAL PUBLIC v3 LICENSE. See the LICENSE file for details.

## Disclaimer

* This script is provided "as-is" for educational purposes only. Use responsibly in environments where you have authorization. Misuse may lead to unintended consequences or security risks.

sl0ppy-privesctaskcreator—simplifying scheduled tasks with privilege escalation. Feel free to contribute or modify for your needs!
