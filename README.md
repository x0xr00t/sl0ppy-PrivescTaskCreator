# sl0ppy-privesctaskcreator

**sl0ppy-privesctaskcreator** is a PowerShell-based script that creates a scheduled task with elevated privileges, designed for quick and automated task creation that can be used for system administration, testing, or other use cases where elevated access is required. The script leverages the Windows Task Scheduler to execute a PowerShell script with the highest available privileges at a specified time.

## Features

- **Automated Task Creation**: Automatically creates and registers a scheduled task that runs with elevated privileges.
- **Customizable Script Execution**: Allows you to specify any PowerShell script to run as part of the scheduled task.
- **Flexible Time Triggers**: Set the task to start at a specific time (default is 2 minutes after the script is executed).
- **Hidden Task**: The scheduled task is set to run hidden to ensure it does not show up in user-facing interfaces.
- **Error Handling**: The script checks for errors at critical points (task registration, task start, process retrieval).

## Prerequisites

- **Windows OS**: This script works on Windows-based operating systems.
- **Administrator Privileges**: You need administrative privileges to register and run tasks with elevated permissions.
- **PowerShell**: PowerShell is required to execute the script. This should be available by default on modern Windows operating systems.
- **Script Path**: Ensure the script you want to execute is available at the specified path on the local machine.

## Installation

1. Clone the repository to your local machine:
    ```bash
    git clone https://github.com/<your-username>/sl0ppy-privesctaskcreator.git
    ```

2. Navigate to the directory where the script is located:
    ```bash
    cd sl0ppy-privesctaskcreator
    ```

3. You can now execute the PowerShell script directly or modify the paths and settings as needed.

## Usage

1. **Customize the script path**:
    Before using the tool, make sure you update the path to the PowerShell script that you wish to execute with elevated privileges in the `taskXml` definition.

    ```xml
    <Arguments>/c start /b "" conhost.exe cmd.exe /K powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Path\To\Your\Script.ps1"</Arguments>
    ```

2. **Run the PowerShell Script**:
    Open PowerShell with administrator privileges and run the `sl0ppy-privesctaskcreator.ps1` script:

    ```powershell
    .\sl0ppy-privesctaskcreator.ps1
    ```

    This will:
    - Calculate the start time for the scheduled task (default is 2 minutes from current time).
    - Register the task in Windows Task Scheduler.
    - Start the scheduled task immediately.
    - Wait briefly for the task to execute and retrieve the process ID of the running script.

3. **Adjust Timing**:
    If you'd like the task to run at a different time, adjust the `$startTime` calculation in the script:

    ```powershell
    # Modify this to set the task to run at a different time
    $startTime = $currentDateTime.AddMinutes(2)  # Example: Add 2 minutes from current time
    ```

4. **Check Task Status**:
    After the script runs, you can check the Task Scheduler (or use the following command) to ensure the task has been registered:

    ```powershell
    Get-ScheduledTask -TaskName "ElevatedTask"
    ```

## Configuration

- **Script Path**: Modify the path to the PowerShell script you wish to execute within the scheduled task. This is done in the `$taskXml` variable:
  
    ```xml
    <Arguments>/c start /b "" conhost.exe cmd.exe /K powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Path\To\Your\Script.ps1"</Arguments>
    ```

- **Start Time**: The start time of the task is set to 2 minutes from the current time by default. You can modify this time by adjusting the following line in the script:

    ```powershell
    $startTime = $currentDateTime.AddMinutes(2)
    ```

- **Scheduled Task Settings**: The task is set to run with the highest privileges, on the condition that it is not running on battery power, and it is hidden. You can modify the task settings in the `$taskXml` variable to customize the behavior.

## Troubleshooting

- **Insufficient Permissions**: Ensure that you are running PowerShell with elevated (Administrator) privileges, as creating scheduled tasks with elevated privileges requires admin access.
- **Script Path Issues**: Double-check that the script path you specify in the XML is correct and the script exists in the given location.
- **Task Not Running**: If the task fails to start, check the Task Scheduler logs (`Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> TaskScheduler`).

## License

This project is licensed under the GNU GENERAL PUBLIC v3 LICENSE - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This script is provided "as-is" and is intended for educational purposes. Use it responsibly and only in authorized environments. Misuse may lead to unintended consequences, including security risks.

---

Feel free to contribute or modify this tool for your use cases!
