# sl0ppy-PrivescTaskCreator
sl0ppy-PrivescTaskCreator.ps1

# sl0ppy-PrivescTaskCreator.ps1

## Author: phoogeveen aka x0xr00t

### Description:
This PowerShell script is designed to create a scheduled task that runs a specified PowerShell script with **elevated (SYSTEM)** privileges. It is intended for educational purposes to demonstrate how privilege escalation can be achieved via scheduled tasks. The script checks for the existence of the specified script, verifies that the current user has the required privileges, and sets up the task to run automatically at a future time.

---

## Features:
- **Privilege Escalation**: The scheduled task runs with **SYSTEM** privileges, allowing the execution of scripts with the highest available privileges on the machine.
- **Script Existence Check**: Validates the existence of the provided PowerShell script path before registering the task.
- **Elevation Check**: Ensures that the user running the script has administrator (elevated) privileges.
- **Task Scheduling**: Automatically schedules the task to run 2 minutes after the script is executed (this delay is adjustable).
- **Error Handling**: Handles various potential errors such as missing scripts, insufficient privileges, or task registration issues.
- **Custom Task Name**: Allows specifying a custom task name for better organization in Task Scheduler.

---

## Requirements:
- **PowerShell** 3.0 or higher.
- **Administrator privileges** to create and register scheduled tasks.
- A valid **PowerShell script** that you wish to execute with elevated privileges.

---

## Parameters:

### `-ScriptPath` (Required):
The full path to the PowerShell script that you want to execute with SYSTEM privileges.

**Example**:
* ```C:\Path\To\Your\Script\your-ps-code.ps1```

-TaskName (Optional):

The name of the scheduled task that will be created. By default, it is set to sl0ppy-PrivescTask, but you can specify a custom name.

Example:

MyCustomPrivescTask

**Script Flow**:

    Check Script Existence: The script checks whether the provided $ScriptPath exists. If the script does not exist, the script halts and outputs an error message.
    Check for Elevated Permissions: The script checks if the user running it has elevated (administrator) privileges. If the user does not have the necessary privileges, the script will terminate with an error.
    Scheduled Task Creation: If the script exists and the user is an administrator, a scheduled task is created with SYSTEM-level privileges.
    Start Scheduled Task: The task is registered and started immediately.
    Retrieve Process ID: The script retrieves the process ID of the newly started task to verify it is running. 

## Usage:
Example Command:

```.\sl0ppy-PrivescTaskCreator.ps1 -ScriptPath "C:\Path\To\Your\Script\your-ps-code.ps1"```

* This command creates and registers a scheduled task with the default name sl0ppy-PrivescTask, which will run the specified PowerShell script with SYSTEM privileges.
* Custom Task Name Example:

```.\sl0ppy-PrivescTaskCreator.ps1 -ScriptPath "C:\Path\To\Your\Script\your-ps-code.ps1" -TaskName "MyCustomPrivescTask"```

This command creates a scheduled task with the name MyCustomPrivescTask instead of the default name sl0ppy-PrivescTask.
## Example Output:

* When the script runs successfully, the output will look something like this:

``` Current system time: 11/22/2024 12:34:56 PM
Scheduled task will start at: 11/22/2024 12:36:56 PM
Formatted start time for XML: 2024-11-22T12:36:56
Scheduled task 'sl0ppy-PrivescTask' registered successfully.
Scheduled task 'sl0ppy-PrivescTask' started successfully.
Process ID of the started process: 1234 
```

* If there are issues, you may see errors like:

The script at 'C:\Path\To\Your\Script\your-ps-code.ps1' does not exist.

Or:

You do not have elevated privileges. This task requires administrator rights.
