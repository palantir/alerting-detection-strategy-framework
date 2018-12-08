# Goal
Detect when MSBuild.exe is executed which may indicate attempts to bypass whitelisting or perform lateral movement using trusted developer tools. 

# Categorization
These attempts are categorized as [Defence Evasion / Trusted Developer Utilities](https://attack.mitre.org/wiki/Technique/T1127).

# Strategy Abstract
The strategy will function as follows: 

* Monitor Windows Sysmon logs for process creations.
* Look for any executions of MSBuild.exe
* Suppress any known-good usages of MSBuild.exe. 
* Alert on any unusual MSBuild.exe processes.

# Technical Context
MSBuild is a technique discovered by Casey Smith ([@SubTee](https://twitter.com/subTee)) to execute code and bypass applocker, device guard or other whitelisting solutions. It's great for executing 1st stage payloads then performing more advanced injection techniques for (almost) diskless implants and C2. 

This technique has been proven to be used in the wild so will make a great example for our framework.

Casey's blog is no longer available however you can find the original article on the [Wayback Machine](https://web.archive.org/web/20161212224652/http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html) and a quick google will find many other examples of offensive usage.

>I found a Microsoft signed tool called MSBuild.exe. This is a default .NET utility that ships with Windows. I usually start with the question; ‘HOW could I get MSbuild to execute code for me?’.
>
>Turns out, MSBuild.exe has a built in capability called “Inline Tasks”.  These are snippets of C# code that can be used to enrich the C# build process.  Essentially, what this does, is take an XML file, compile and execute in memory on the target, so it is not a traditional image/module execution event.

# Blind Spots and Assumptions
This strategy relies on the following assumptions: 

* Sysmon is running and functioning correctly on the system.
* Logs from endpoint tooling are reported to the server.
* Endpoint tooling is correctly forwarding logs to SIEM.
* SIEM is successfully indexing endpoint tooling logs. 

A blind spot will occur if any of the assumptions are violated. For instance, the following would trip the alert: 
* MSBuild.exe is renamed
* A whitelisted host is abused, for example a DevOps build server
* Endpoint tooling is modified to not collect module load events or report to the server.

# False Positives
There are several instances where false positives will occur: 

* A user legitimately performs a build during software development
* An automated process during software installations builds a C# component

# Priority
The priority is set to medium under all conditions.

# Validation
Validation can occur for this ADS by performing the following execution using [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

```powershell
#Don't forget to import the module if you didn't do that above
Install-Module -Name powershell-yaml
# Load the T1127 Trusted Developer Utilties test
$T1127 = Get-AtomicTechnique -Path .\atomics\T1127\T1127.yaml
# Set the correct file including full path
$T1127.atomic_tests[0].input_arguments.filename.default = "C:\Coding\atomic-red-team\atomics\T1127\src\T1127.csproj"
# Run the test
Invoke-AtomicTest $T1127
```
Full documentation: https://bleepsec.com/2018/11/26/using-attack-atomic-red-team-part1.html

# Response
In the event that this alert fires, the following response procedures are recommended:

* Compare the suspect MSBuild usage against entries on the whitelist. 
  * Note if there are minor issues due to path or drive letter differences.
* Check the digital signature of the binary.
  * Use either tooling or powershell to identify if the binary is digitally signed.
  * Make a trust determination on the signer and binary.
* Identify if the binary corresponds to an installed application. 
* Look at the execution behavior of the binary. 
  * Has it made any unusual network connections?
  * Has it spawned any child processes?
  * Has it made any suspicious file modifications?
If the binary is not trustworthy, or cannot be traced to a legitimate installed application, treat it as a potential compromise and escalate to a security incident.

# Additional Resources
https://web.archive.org/web/20161212224652/http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html
https://bleepsec.com/2018/11/26/using-attack-atomic-red-team-part1.html