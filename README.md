## sl0ppy-privesctaskcreator

```sl0ppy-privesctaskcreator is a PowerShell-based script that automates the creation of a scheduled task with elevated privileges. Designed for flexibility, this tool allows users to specify a custom PowerShell script to execute under the highest available permissions, making it useful for system administration, testing, or other scenarios requiring privilege escalation.```

# Version: V3.0
```
* Improvements in V3.0:

* Added -CustTaskName flag for customizable task naming.

* Added -Time flag to specify the start time.

* Added -RepeatInterval for periodic task execution.

* Introduced -RunOnBattery, -StartWhenAvailable, and -Hidden flags for enhanced control.
```
## Features
```
   * Dynamic Script Execution: Specify the PowerShell script to run at execution time with the new -FilePath option.
   * Automated Scheduling: Schedules a task to run with elevated privileges, automatically starting at a calculated future time.
   * Hidden and Elevated Task: The task runs hidden from user interfaces and with the highest privileges available.
   * Repetition Support: Option to configure the task to repeat at custom intervals.
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

## Navigate to the directory:

```cd sl0ppy-privesctaskcreator```

The script is ready to run.

## Usage

* The script provides multiple flags to customize task creation. Below are the available options:

## Basic Usage

Provide the path to a PowerShell script to execute:

```.‌sl0ppy-privesctaskcreator.ps1 -FilePath "C:\Path\To\Your\Script.ps1"```

* If -FilePath is not provided, the script will prompt you to input the path interactively.

## Flags and Parameters

* -CustTaskName (optional):

* Specify a custom name for the scheduled task (default: ElevatedTask).

```.‌sl0ppy-privesctaskcreator.ps1 -FilePath "C:\Scripts\MyScript.ps1" -CustTaskName "MyCustomTask"```

* -Time (optional):

* Set a custom start time for the task. If not provided, defaults to 2 minutes from the current time.

```.‌sl0ppy-privesctaskcreator.ps1 -FilePath "C:\Scripts\MyScript.ps1" -Time (Get-Date).AddHours(1)```

* -RepeatInterval (optional):

Specify a repetition interval in ISO 8601 format (e.g., PT1H for hourly).

```.‌sl0ppy-privesctaskcreator.ps1 -FilePath "C:\Scripts\MyScript.ps1" -RepeatInterval "PT1H"```

-RunOnBattery (optional):

Allow the task to run even when the system is on battery power.

```.‌sl0ppy-privesctaskcreator.ps1 -FilePath "C:\Scripts\MyScript.ps1" -RunOnBattery```

-StartWhenAvailable (optional):

Start the task as soon as the system is ready (e.g., after startup).

```.‌sl0ppy-privesctaskcreator.ps1 -FilePath "C:\Scripts\MyScript.ps1" -StartWhenAvailable```

* -Hidden (optional):

Hide the task in the Task Scheduler UI.

```.‌sl0ppy-privesctaskcreator.ps1 -FilePath "C:\Scripts\MyScript.ps1" -Hidden```

## Advanced Examples

* Run a Script Immediately

```.‌sl0ppy-privesctaskcreator.ps1 -FilePath "C:\Scripts\TestScript.ps1" -Time (Get-Date)```

## Full Customization Example

```.‌sl0ppy-privesctaskcreator.ps1 -FilePath "C:\Scripts\MyScript.ps1" -CustTaskName "DailyTask" -Time (Get-Date).AddMinutes(10) -RepeatInterval "P1D" -RunOnBattery -StartWhenAvailable -Hidden```

## Configuration
```
The scheduled task is configured with the following default settings:

   * Run Level: Highest available privileges.
   * Visibility: Hidden (if -Hidden flag is set).
   * Triggers: Starts at the specified time.
   * Execution Policy: Bypasses restrictions to allow the specified script to run.

* You can further customize these settings by editing the $taskXml definition in the script.
```

## Troubleshooting
```
Common Issues and Solutions:

* Task Not Created: Ensure PowerShell is running with elevated (Administrator) permissions.

* File Path Issues: Verify that the specified .ps1 file exists and the path is correct.

* Task Not Executing: Check Task Scheduler logs in Event Viewer:

* Applications and Services Logs > Microsoft > Windows > TaskScheduler.

* Process Not Found: Confirm the script you specified runs successfully when executed manually.
```
## License

This project is licensed under the GNU GENERAL PUBLIC v3 LICENSE. See the LICENSE file for details.

## Disclaimer

* This script is provided "as-is" for educational purposes only. Use responsibly in environments where you have authorization. Misuse may lead to unintended consequences or security risks.

# sl0ppy-privesctaskcreator—simplifying scheduled tasks with privilege escalation. Feel free to contribute or modify for your needs!

