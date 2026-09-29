![GitHub release](https://img.shields.io/github/v/release/x0xr00t/sl0ppy-PrivescTaskCreator)
![GitHub license](https://img.shields.io/github/license/x0xr00t/sl0ppy-PrivescTaskCreator)
![GitHub stars](https://img.shields.io/github/stars/x0xr00t/sl0ppy-PrivescTaskCreator)
![GitHub issues](https://img.shields.io/github/issues/x0xr00t/sl0ppy-PrivescTaskCreator)

# sl0ppy-privesctaskcreator
## A PowerShell-based tool for creating highly customizable, EDR-evasive scheduled tasks with advanced persistence and execution options.

## 🔥 Key Improvements in v3.2
```
* Core Enhancements
* ✅ EDR Evasion – Direct/indirect syscalls, AMSI/ETW bypass, API unhooking
* ✅ 12+ Execution Methods – cmd, powershell, wscript, mshta, rundll32, etc.
* ✅ 50+ Customization Flags – Fine-grained control over every aspect
* ✅ Advanced Persistence – WMI, registry, services, startup, secondary tasks
* ✅ Process Injection – Hollowing, PPID spoofing, threadless injection
* ✅ Network Evasion – DNS exfil, proxy/Tor support, custom user agents
* ✅ Anti-Forensics – Log clearing, ADS hiding, self-deletion
* ✅ Anti-Debug/Anti-VM – Comprehensive checks to evade analysis
* ✅ Backward Compatibility
* ✅ All original v3.1 features preserved
* ✅ Same core scheduling logic with enhanced reliability
  
  ## new and and upgraded 
  ✅Dynamic Function Resolution  {$asm}
  ✅Memory & Thread Orchestration {$winFunc}
  ✅Analysis & Runtime Integrity  {$debugCheck}
```

# 🛠 Features
## 🔧 Core Functionality
```
* Dynamic Script Execution – Run any .ps1 script with elevated privileges
* Automated Scheduling – Precise timing control with jitter for evasion
* Hidden Execution – Tasks run invisibly with highest privileges
* Repetition Support – Custom intervals (e.g., PT1H for hourly)
* Wake & Network Control – Wake system for execution, enforce network dependency
* User Impersonation – Run as SYSTEM, a custom user, or with token manipulation

* 🛡 EDR Evasion Techniques
* AMSI BypassContext nullification, patching, multiple methodsETW EvasionBypass, patching, provider blockingProcess InjectionHollowing, PPID spoofing, threadless injectionMemory ProtectionDirect/indirect syscalls, reflective loadingAnti-ForensicsLog clearing, ADS hiding, self-deletionAnti-Debug/Anti-VMDebugger checks, VM detection (VBox, VMware, Hyper-V)API UnhookingRestores hooked APIs (NtCreateProcess, etc.)
* 🔄 Persistence Methods
* WMI Event SubscriptionTriggers on system eventsRegistry Run KeysHKCU\...\Run persistenceService InstallationCreates a fake Windows serviceStartup FolderAdds shortcut to startupSecondary TasksCreates backup scheduled tasksAlternate Data StreamsHides payloads in NTFS streams
* 🌐 Network Evasion


* DNS Exfiltration – C2 over DNS (port 53)

* Proxy/Tor Support – Route traffic through proxies or Tor
* Custom User Agents – Mimic legitimate browser traffic
* HTTPS Encryption – Secure C2 communications
```
## 🔐 Process Manipulation
```
* PPID Spoofing – Fake parent process (e.g., explorer.exe)

* Token Impersonation – Steal tokens from other processes

* Privilege Escalation – Enable all privileges (SeDebugPrivilege, etc.)

* Critical Process – Mark process as critical to prevent termination
```

## 📜 Encoding & Obfuscation
```
* Base64Encodes PowerShell commandsXORSimple byte XOR encryptionRC4Stream cipher encryptionAESStrong symmetric encryptionSecureStringHides commands in memory
```

# 📋 Prerequisites
```
* Windows OS (7/10/11, Server 2012+)
* Administrator Privileges (for task creation)
* PowerShell 5.1+ (preinstalled on modern Windows)
* Target Script (.ps1 file must exist at the specified path)
```

# 🚀 Installation
```
* git clone https://github.com/x0xr00t/sl0ppy-PrivescTaskCreator.git
* cd PrivescTaskCreator
* The script is now ready to run.
```
# 📖 Usage
## Basic Invocation

## Run the script from PowerShell:
```
.\sl0ppy-PrivescTaskCreator.ps1
```
## Display PowerShell's parameter information:
``
Get-Help .\sl0ppy-PrivescTaskCreator.ps1 -Full
``
## Display examples embedded in the script, when available:
```
Get-Help .\sl0ppy-PrivescTaskCreator.ps1 -Examples
```
## Inspect the available parameters:
```
(Get-Command .\sl0ppy-PrivescTaskCreator.ps1).Parameters.Keys
```
## The script is implemented as an advanced PowerShell script using [CmdletBinding()] and a parameter block.

# 1. Core Task Parameters

## These parameters control the fundamental Scheduled Task configuration.
```
Parameter	Type	Default	Description
-FilePath	String	—	Path to the file/script being processed
-CustTaskName	String	Randomized Windows Update-style name	Scheduled Task name
-Time	DateTime	—	Start time for time-based execution
-RepeatInterval	String	Empty	Task repetition interval
-RunOnBattery	Switch	Off	Allow execution while running on battery
-StartWhenAvailable	Switch	Off	Start when the scheduled time becomes available
-Hidden	Switch	Off	Configure the task as hidden
-WakeToRun	Switch	Off	Allow the task to wake the computer
-NetworkRequired	Switch	Off	Require network availability
-RunAsUser	String	SYSTEM	Security principal used by the task
-MultipleInstancePolicy	String	IgnoreNew	Multiple-instance behavior
-ExecutionTimeLimit	String	PT0S	Maximum execution duration
```
## The source defines SYSTEM as the default execution principal and supports task-level settings such as hidden state
## battery behavior, network requirements, wake-to-run, and execution limits.
```
-FilePath
```
## Specifies the primary file associated with the experiment.
```
-FilePath <path>
```
## Use a controlled test script or executable when conducting research.
```
-CustTaskName
```
## Controls the name assigned to the Scheduled Task.
```
-CustTaskName <name>
```
## If omitted, the script generates a Windows-style task name containing a random numeric component.
```
-Time
```
## Controls the start boundary for a time-triggered task.
```
-Time <DateTime>
```
## For example, PowerShell can construct a future test time using:
```
$testTime = (Get-Date).AddMinutes(10)
-RepeatInterval
```
## Controls repetition for a time trigger.
```
-RepeatInterval <TaskSchedulerInterval>
```
## The value is inserted into the Scheduled Task repetition configuration.
```
Execution-condition switches
-RunOnBattery
-StartWhenAvailable
-Hidden
-WakeToRun
-NetworkRequired
```
## These correspond to Task Scheduler settings generated by the script.

# 2. Trigger Types

## The script supports:
```
Time
Logon
Boot
Event
Idle
SessionStateChange
```
## Select the trigger with:
```
-TriggerType <type>
```
## The default is:
```
-TriggerType Time
```
## The available trigger types are defined directly in the parameter block.
```
Time
-TriggerType Time
```
## Runs according to the configured -Time value.

## Optional repetition is controlled by:
```
-RepeatInterval
Logon
-TriggerType Logon
```
## Associates execution with a Windows logon event.
```
Boot
-TriggerType Boot
```
## Associates execution with system startup.
```
Event
-TriggerType Event
```
## Event-trigger configuration is controlled by:
```
-EventLog
-EventSource
-EventID
```
## Defaults:
```
EventLog   = System
EventSource = Service Control Manager
EventID    = 7036
```
## These defaults are defined in the source.

## Idle
```
-TriggerType Idle
```
## Used for Task Scheduler idle-state research.

## Session State Change
```
-TriggerType SessionStateChange
```
## The associated session state is controlled with:
```
-SessionState
```
## The default is:
```
ConsoleConnect
```
## 3. Execution Modes

```
Parameter	Purpose
-UseCmdLauncher	Uses cmd.exe as the launcher
-UsePowerShellDirect	Direct PowerShell execution
-UseWScript	Uses Windows Script Host
-UseMshta	Uses mshta.exe
-UseInstallUtil	Uses InstallUtil
-UseRegsvr32	Uses regsvr32.exe
-UseRundll32	Uses rundll32.exe
-UseCMSTP	Uses CMSTP
-UseExcelDDE	Excel DDE research
-UseWMI	WMI-based execution research
-UseBitsTransfer	BITS-related execution/transfer research
```
## These switches are defined in the script's execution-options section.

## These should be regarded as execution research primitives. When testing them, use benign payloads and capture the resulting process tree and telemetry.

## 4. Security / Telemetry Research

## The script contains a separate group of options for studying security controls and endpoint telemetry.
```
-BypassAMSI
-BypassETW
-DisableDefender
-ClearLogs
-AntiDebug
-AntiVM
-UseAlternateDataStream
-Base64Encode
-SecureString
-UseCOM
-PPIDSpoofing
-SpoofedPPID
-ThreadlessInject
-ProcessHollowing
-HollowProcess
-UseDirectSyscalls
-UseIndirectSyscalls
-PatchAMSI
-PatchETW
-UseReflectiveLoading
-SleepObfuscation
-StringEncryption
-APIUnhooking
-BlockETWProviders
-DisableLogging
```

## Important

## Options in this section can interfere with security monitoring or alter system behavior.

## For GitHub research documentation, these should be tested only in an isolated environment with appropriate authorization.

## Recommended workflow:
```
Baseline
   ↓
Enable telemetry
   ↓
Run ONE research feature
   ↓
Collect telemetry
   ↓
Compare results
   ↓
Revert VM
```

# 5. Persistence Research

## The script exposes multiple persistence-research switches:
```
-AddToStartup
-WMIPersistence
-RegistryPersistence
-ServicePersistence
-ServiceName
-SchTaskPersistence
-SecondTaskName
```
## These are implemented in the persistence portion of the source.
```
-AddToStartup
```
## Researches Startup-folder persistence.
```
-WMIPersistence
```
## Researches WMI event-subscription persistence.
```
-RegistryPersistence
```
## Researches Registry-based startup persistence.
```
-ServicePersistence
```
## Researches Windows service persistence.

## The service name can be controlled with:
```
-ServiceName <name>
-SchTaskPersistence
```
## Creates an additional Scheduled Task persistence mechanism.

## The secondary task name is controlled by:
```
-SecondTaskName <name>
```
## The source implements a secondary logon-triggered task as part of this research functionality.

# 6. Network / C2 Research Parameters

## The script also exposes network-research parameters:
```
-UseDNSExfil
-C2Server
-C2Port
-UseHTTPS
-UseProxy
-ProxyAddress
-ProxyPort
-UseTor
-UserAgent
```
## The defaults include:
```
C2Server   = 127.0.0.1
C2Port     = 53
ProxyPort  = 8080
UserAgent  = Mozilla/5.0
```
## These values are defined in the source.

## For safe testing, keep network endpoints pointed at infrastructure you control, preferably localhost or an isolated lab service.

# 7. Self-Destruct / Timing Research

## Available parameters:
```
-SelfDelete
-DelayMinutes
-RandomizeName
-AddJitter
-JitterMinutes
```
## The defaults are:
```
DelayMinutes = 0
JitterMinutes = 5
```
## These options are defined in the script's self-destruct/timing section.

## These features are particularly useful when researching:
```
Detection timing
Scheduled execution behavior
Race conditions
Delayed execution
Telemetry collection windows
8. Process-Injection Research
```
## The script contains several process-injection research switches:
```
-ProcessHollowing
-HollowProcess
-PPIDSpoofing
-SpoofedPPID
-ThreadlessInject
-EarlyBird
-ModuleStomping
-ProcessDoppelganging
-GhostWriting
```
## The source defines these as process-injection techniques and passes the corresponding options into its process-injection function.

## -HollowProcess defaults to:
```
svchost.exe
```

## Use these features only with controlled test processes inside an isolated research VM.

## For defensive research, collect:
```
Parent/child process relationships
Process creation events
Image-load events
Memory protection changes
Thread creation telemetry
EDR alerts
Sysmon events
```
# 9. Encoding / Transformation Options
```
-UseXOR
-XORKey
-UseRC4
-RC4Key
-UseAES
-AESKey
-AESIV
```
## Defaults include:
```
XORKey = 0x25
RC4Key = s3cr3t
AESKey = MySuperSecretKey123
AESIV  = MySuperSecretIV123
```
## These values are source defaults and should not be treated as secure production cryptographic credentials.

## For research, prefer generated test keys and disposable payloads.

# 10. Privilege / Security-Control Options

## The miscellaneous section contains:
```
-RunAsAdmin
-UACBypass
-DisableRealTimeMonitoring
-DisableBehaviorMonitoring
-DisableIOAV
-AddDigitalSignature
-UseDelayedStart
-SetCriticalProcess
-UseTokenManipulation
-ImpersonateUser
-EnableAllPrivileges
-BypassUAC
-UseParentProcess
-ParentProcess
-UsePPLBypass
-UseDriverLoad
-DriverPath
```
## These options can alter privilege, process, or endpoint-security behavior.

## For authorized testing, document the exact Windows security configuration before and after each experiment.

# 11. Detection-Pattern Research

## Additional parameters include:
```
-UseCobaltStrikePattern
-UseMetasploitPattern
-UseCustomPattern
-CustomCommand
```
## The source exposes these specifically as pattern/custom-command controls.

## These are useful when comparing how defensive products respond to different command or behavioral patterns.

# 12. Task Registration

## Internally, the tool generates Scheduled Task XML and registers the resulting task through Windows Task Scheduler.

## The source uses either Register-ScheduledTask or, for one code path, schtasks.exe.

## After registration, the script attempts to start the task when appropriate and performs a basic process verification step.

## This means testing should include both:
```
Task registration
        +
Task execution
        +
Process verification
        +
Telemetry collection
```
# 13. Recommended Safe Test Modes
## Mode A Task Scheduler Baseline

## Use only the basic task configuration.

## Goal:
```
Validate:
    Task creation
    Trigger behavior
    Task XML
    Execution context
    Event logging
```
## Do not combine this test with persistence, injection, or security-control modification.

## Mode B — Trigger Testing

## Test each trigger independently:
```
Time
Logon
Boot
Event
Idle
SessionStateChange
```
## Record:
```
Trigger
Expected execution
Actual execution
Task Scheduler event
Process creation event
EDR response
Mode C — Execution Telemetry
```
## Compare different execution mechanisms one at a time.

 ## Collect:
```
Parent process
Child process
Command line
Image path
Integrity level
Token information
Network activity
EDR telemetry
Mode D — Persistence Detection
```
## For authorized defensive testing, evaluate each persistence mechanism separately.

## Example test matrix:
```
Test	Mechanism	Created	Detected	Removed
P01	Startup	☐	☐	☐
P02	Registry	☐	☐	☐
P03	WMI	☐	☐	☐
P04	Service	☐	☐	☐
P05	Scheduled Task	☐	☐	☐
Mode E — Telemetry Validation
```
## Enable your monitoring stack before testing.

##  Recommended telemetry:
```
Windows Security Events
PowerShell Logging
Task Scheduler Operational
Sysmon
Microsoft Defender
EDR telemetry
```
## Then test one behavior at a time.

# 14. Troubleshooting
## Script execution policy

## If PowerShell refuses to load the script, first inspect the current policy:
```
Get-ExecutionPolicy -List
```
## Do not permanently weaken execution-policy settings merely to run a research script.

## Parameter errors

## Inspect the generated command metadata:
```
Get-Command .\sl0ppy-PrivescTaskCreator.ps1 |
    Select-Object -ExpandProperty Parameters
Scheduled Task problems
```
## Inspect existing tasks:
```
Get-ScheduledTask |
    Sort-Object TaskPath,TaskName
```
## Inspect a specific task:
```
Get-ScheduledTaskInfo -TaskName "<task-name>"
Event investigation
```
## Review Task Scheduler operational events:

## Microsoft-Windows-TaskScheduler/Operational

## For research environments, keep this channel enabled so that task creation and execution behavior can be correlated with process telemetry.

# 15. Cleanup

## Always clean up after an experiment.

## Review the tasks created during testing:
```
 Get-ScheduledTask |
    Where-Object { $_.TaskName -like "*<test-name>*" }
```
##
```
Scheduled Tasks
Services
Registry Run keys
Startup folder
WMI subscriptions
Security configuration
Event logging
Defender configuration
Network configuration
Temporary files
```

# 16. Recommended Experiment Record

```
Experiment ID:
Date:
Windows version:
PowerShell version:
EDR:
Defender configuration:
Tool version:

Feature tested:
Parameters:
Expected behavior:
Observed behavior:

Task created:
Process created:
Parent process:
Child process:
Command line:

Security events:
Sysmon events:
EDR alerts:

Persistence created:
Persistence removed:

False positive:
False negative:

Cleanup completed:
Snapshot restored:

```

# 17. Full Parameter Reference

```
Core
-FilePath
-CustTaskName
-Time
-RepeatInterval
-RunOnBattery
-StartWhenAvailable
-Hidden
-WakeToRun
-NetworkRequired
-RunAsUser
-MultipleInstancePolicy
-ExecutionTimeLimit
Triggers
-TriggerType
-EventLog
-EventSource
-EventID
-SessionState
Execution
-UseCmdLauncher
-UsePowerShellDirect
-UseWScript
-UseMshta
-UseInstallUtil
-UseRegsvr32
-UseRundll32
-UseCMSTP
-UseExcelDDE
-UseWMI
-UseBitsTransfer
Security / Evasion Research
-BypassAMSI
-BypassETW
-DisableDefender
-ClearLogs
-AntiDebug
-AntiVM
-UseAlternateDataStream
-Base64Encode
-SecureString
-UseCOM
-PPIDSpoofing
-SpoofedPPID
-ThreadlessInject
-ProcessHollowing
-HollowProcess
-UseDirectSyscalls
-UseIndirectSyscalls
-PatchAMSI
-PatchETW
-UseReflectiveLoading
-SleepObfuscation
-StringEncryption
-APIUnhooking
-BlockETWProviders
-DisableLogging
Persistence
-AddToStartup
-WMIPersistence
-RegistryPersistence
-ServicePersistence
-ServiceName
-SchTaskPersistence
-SecondTaskName
Network
-UseDNSExfil
-C2Server
-C2Port
-UseHTTPS
-UseProxy
-ProxyAddress
-ProxyPort
-UseTor
-UserAgent
Timing / Cleanup
-SelfDelete
-DelayMinutes
-RandomizeName
-AddJitter
-JitterMinutes
Injection
-EarlyBird
-ModuleStomping
-ProcessDoppelganging
-GhostWriting
Encoding
-UseXOR
-XORKey
-UseRC4
-RC4Key
-UseAES
-AESKey
-AESIV
Privilege / Miscellaneous
-RunAsAdmin
-UACBypass
-DisableRealTimeMonitoring
-DisableBehaviorMonitoring
-DisableIOAV
-AddDigitalSignature
-UseDelayedStart
-SetCriticalProcess
-UseTokenManipulation
-ImpersonateUser
-EnableAllPrivileges
-BypassUAC
-UseParentProcess
-ParentProcess
-UsePPLBypass
-UseDriverLoad
-DriverPath
-UseCobaltStrikePattern
-UseMetasploitPattern
-UseCustomPattern
-CustomCommand
```
# 18. Recommended Usage Philosophy

## The most useful way to operate this project is as a repeatable research harness:
```
              ┌───────────────┐
              │ Windows VM    │
              │ clean snapshot│
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │ Baseline      │
              │ telemetry     │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │ One feature   │
              │ per experiment│
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │ Collect       │
              │ telemetry     │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │ Analyze       │
              │ detection     │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │ Cleanup /     │
              │ rollback      │
              └───────────────┘

```
# ⚙ Configuration
```
* Default Settings

* Run Level: HighestAvailable (SYSTEM privileges)
* Visibility: Hidden (if -Hidden is set)
* Triggers: Time-based (customizable)
* Execution Policy: Bypass mode (-ExecutionPolicy Bypass)

* Customizing the Task XML
* Modify the $taskXml variable in the script to adjust:

* Security descriptors
* Priority levels
* Additional triggers
```

🛠 Troubleshooting
```
Task not createdRun PowerShell as AdministratorFile path errorsVerify the .ps1 file existsTask not executingCheck Event Viewer → Task Scheduler logsProcess not foundTest the script manually firstEDR blocking executionEnable more evasion flags (-BypassAMSI, -UseDirectSyscalls)Anti-VM detectedRun on bare metal or adjust -AntiVM checks
Debugging Tips:
# View Task Scheduler logs
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" | Select-Object -First 20

# Check if task exists
Get-ScheduledTask -TaskName "YourTaskName"
```
## ⚠ Disclaimer

# ⚠️ For Authorized Use Only
```
This tool is designed for legitimate red teaming, penetration testing, and security research.
Unauthorized use against systems you do not own is illegal.
The author is not responsible for misuse.
```

## 📜 License
```
* GNU GPLv3 – See LICENSE for details.
```

## 🤝 Contributing
```
Pull requests are welcome! Feel free to:
* ✅ Add new evasion techniques
* ✅ Improve error handling
* ✅ Optimize performance
```

## 📌 Changelog
```
* v3.2 "Sl0ppy-PrivTaskCreator" (Current)

* Complete rewrite with EDR evasion focus
* 50+ new parameters for customization
* 12 execution methods (up from 1)
* Advanced persistence (WMI, services, etc.)
* Process injection (hollowing, PPID spoofing)
* Network evasion (DNS, proxy, Tor)
```

## v3.1 (Legacy)
```
Basic scheduled task creation
Custom naming & timing
Hidden execution
Network/ wake controls
```

