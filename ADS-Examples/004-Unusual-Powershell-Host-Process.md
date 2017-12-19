# Goal
Detect when powershell (system.management.automation.dll) is loaded into an unusual powershell host process. This may be indicative of an attempt to load powershell functionality without relying on traditional powershell hosts (e.g. powershell.exe). 

# Categorization
These attempts are categorized as [Execution / Powershell](https://attack.mitre.org/wiki/Technique/T1086).

# Strategy Abstract
The strategy will function as follows: 

* Monitor module loads via endpoint tooling on Windows systems.
* Look for any process that loads the powershell DLL (system.management.automation.dll OR system.management.automation.ni.dll)
* Suppress any known-good powershell host processes by path and process name. 
* Alert on any unusual powershell host processes.

# Technical Context
Built on the .NET framework, powershell is a command-line shell and scripting language for performing system management and automation. While normally exposed through the process powershell.exe, powershell is actually a DLL entitled system.management.automation.dll. It may also exist in a native image format as system.management.automation.ni.dll. 

The powershell DLL may be loaded into several processes which are known as powershell hosts. These may range from common hosts like powershell.exe or the powershell integrated scripting environment (powershell_ise.exe) to more esoteric binaries like Exchange and Azure Active Directory Sync processes. Generally, powershell hosts are rather predictable and are usually signed binaries distributed by Microsoft.

Attackers love to leverage powershell as it provides a high-level interface to interact with the operating system without requiring development of functionality in C, C#, or .NET. While many attackers leverage native powershell hosts, more sophisticated adversaries may opt for the more OPSEC-friendly method of injecting powershell into non-native hosts. This is described as [unmanaged powershell](https://github.com/leechristensen/UnmanagedPowerShell) (POC: [powerpick](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)), a method of loading the powershell DLL into an arbitrary process without relying on a powershell host.

An important caveat is how unmanaged powershell interacts with powershell logging. As noted in the powershell knowledge base page, powershell v5 includes substantial improvements to telemetry collection through module, script block, operational, and transcript logs. Older versions, however, do have the same logging hooks available. On systems with powershell v2 installed, the .NET v2 CLR may be loaded, which will provide a logging bypass. Removing powershell v2, and installing powershell >= v5 is essential to maintaining reliable logging pipelines.

Unmanaged powershell is [explained in greater detail on Lee Christensen's blog](https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/), but is summarized as follows: 

* The .NET common language runtime (CLR) is loaded into the current process.
* Attacker tools specify the version of the CLR loaded, but will oftentimes rely on loading v2 if available. 
  * Foreign processes require a method of code injection.
* The injected code loads the CLR.
* The CLR loads a custom C# assembly (effectively a powershell runner) into an AppDomain.
* Commands or script blocks are loaded into the C# assembly and the .NET execution method is called.

Additional information on unmanaged powershell can be found on [Justin Warner's blog](https://www.sixdub.net/?p=367). 

# Blind Spots and Assumptions
This strategy relies on the following assumptions: 

* Endpoint tooling is running and functioning correctly on the system.
* Module loads in Windows are being recorded.
* Logs from endpoint tooling are reported to the server.
* Endpoint tooling is correctly forwarding logs to SIEM.
* SIEM is successfully indexing endpoint tooling logs. 

A blind spot will occur if any of the assumptions are violated. For instance, the following would trip the alert: 
* A legitimate powershell host is abused (e.g. powershell.exe).
* A whitelisted powershell host is abused.
* Endpoint tooling is modified to not collect module load events or report to the server.

# False Positives
There are several instances where false positives will occur: 

* A legitimate powershell host is used and is not suppressed via the whitelist.

Legitimate powershell hosts typically look like the following:

* They are digitally signed by Microsoft, or a valid 3rd party application which may need to make direct powershell calls. 
* The powershell host loads the native powershell library into memory using a standard method (e.g. LoadLibrary). 
* This is a binary which we generally trust. 

# Priority
The priority is set to medium under all conditions.

# Validation
Validation can occur for this ADS by performing the following execution on a MacOS host:

```
Copy-Item C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Destination C:\windows\temp\unusual-powershell-host-process-test.exe -Force 

Start-Process C:\windows\temp\unusual-powershell-host-process-test.exe -ArgumentList '-NoProfile','-NonInteractive','-Windowstyle Hidden','-Command {Get-Date}' 

Remove-Item 'C:\windows\temp\unusual-powershell-host-process-test.exe' -Force -ErrorAction SilentlyContinue
``` 

# Response
In the event that this alert fires, the following response procedures are recommended:

* Compare the suspect powershell host against entries on the whitelist. 
  * Note if there are minor issues due to path or drive letter differences.
* Check the digital signature of the binary.
  * Use either tooling or powershell to identify if the binary is digitally signed.
  * Make a trust determination on the signer and binary.
* Identify if the binary corresponds to an installed application. 
  * Look at osquery to find installed packages that might match the binary.
* Look at the execution behavior of the binary. 
  * Has it made any unusual network connections?
  * Has it spawned any child processes?
  * Has it made any suspicious file modifications?
If the binary is not trustworthy, or cannot be traced to a legitimate installed application, treat it as a potential compromise and escalate to a security incident.

# Additional Resources
* [Unmanaged powershell](https://github.com/leechristensen/UnmanagedPowerShell)
* [Powershell without powershell](https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe)
* [Bypassing AppLocker Policies](https://www.sixdub.net/?p=367)