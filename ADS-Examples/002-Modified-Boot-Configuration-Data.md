# Goal
Detect when the boot configuration data (BCD) of a Windows device has been modified in an unusual and potentially malicious way.

# Categorization
These attempts are categorized as [Defense Evasion / Disabling Security Tools](https://attack.mitre.org/wiki/Technique/T1089).

# Strategy Abstract
The strategy will function as follows: 

* Record BCD for all boot events in Windows using Windows Event Logs. 
* Compare reported BCD to a known-good profile.
* Alert on any discrepancies between desired and current states.

# Technical Context
[Boot Configuration Data](https://msdn.microsoft.com/en-us/library/windows/hardware/dn653287(v=vs.85).aspx) is the replacement for legacy file-based boot information. 

BCD provides a firmware-independent mechanism for manipulating boot environment data for any type of Windows system. Windows Vista and later versions of Windows will use it to load the operating system or to run boot applications such as memory diagnostics. Some key characteristics include:

* BCD abstracts the underlying firmware. BCD currently supports both PC/AT BIOS and EFI systems. BCD interfaces perform all necessary interaction with firmware. For example, on EFI systems, BCD creates and maintains EFI NVRAM entries.
* BCD provides clean and intuitive structured storage for boot settings.
* BCD interfaces abstract the underlying data store.
* BCD is available at run time and during the boot process.
* BCD manipulation requires elevated permissions.
* BCD is designed to handle systems with multiple versions and configurations of Windows, including versions earlier than Windows Vista. It can also handle non-Windows operating systems.
* BCD is the only boot data store that is required for Windows Vista and later versions of Windows. BCD can describe NTLDR and the boot process for loading of earlier versions of Windows, but these operating systems are ultimately loaded by Ntldr and must still store their boot options in a boot.ini file.

BCD is relevant for security purposes as it is responsible for: 

* Enforcing driver code signing requirements.
* Enforcing DEP and other anti-exploit requirements.
* Controlling kernel/hypervisor debugging settings.

BCD can be modified using multiple methods, most notably via WMIC or the bcdedit.exe binary. 

At the start of the Windows boot process, a [Windows event ID (4826)](https://docs.microsoft.com/en-us/windows/device-security/auditing/event-4826) is recorded in the event log with the details of the BCD data loaded.

There are several critical BCD entries present in this log that should be inspected for changes: 

|BCD Entries|Description|Default State|Desired State|Security Impact|
|-----------|-----------|-------------|-------------|---------------|
SecurityID|The security ID responsible for the BCD load event.|SYSTEM|SYSTEM|Indicates an anomalous BCD loading event.|
Kernel Debugging|Describes whether or not kernel debugging is enabled.|Disabled|Disabled|Allows subversion of the operating system, security tooling, and controls.|
Hypervisor Debugging|Describes whether or not hypervisor debugging is enabled.|Disabled|Disabled|Allows subversion of the hypervisor and any running guests.|
Test Signing|Describes whether or not test signing is enabled.|Disabled|Disabled|Allows loading of unsigned kernel modules and drivers.|
Flight Signing|Describes whether or not flight signing is enabled.|Disabled|Disabled|Allows loading of flight-signed (Microsoft development code signing certificate) drivers.|
Integrity Checks|Describes whether or not integrity checks are performed.|Enabled|Enabled|Disables all integrity checks on the BCD.|

# Blind Spots and Assumptions
This strategy relies on the following assumptions: 
* BCD reporting is valid and trustworthy. 
* Windows event logs are being successfully generated on Windows hosts.
* Windows event logs are successfully forwarded to WEF servers. 
* SIEM is successfully indexing Windows event logs.

A blind spot will occur if any of the assumptions are violated. For instance, the following would not trip the alert: 
* Windows event forwarding or auditing is disabled on the host.
* BCD is modified without generating a log event (e.g. exploit, implant). 

# False Positives
There are several instances where false positives will occur: 
* Users enrolling in Windows Insider Preview (WIP) builds will enable Flight Signing. 
* Users manually enabling debugging or driver test features for the purposes of development. 

System configuration should prevent enrollment in WIP, but enterprising users may work around these restrictions.

System debugging (e.g. Kernel, Hypervisor) should only take place in a sanctioned development environment, and should not be present on a production host. 

# Priority
The priority is set to high under the following conditions:
* Integrity checks are disabled.
* Kernel debugging is enabled.
* Hypervisor debugging is enabled.
* Test signing is enabled.

The priority is set to medium under the following conditions:
* Flight signing is enabled.

# Validation
Validation can occur for this ADS by performing the following execution on a Windows host, followed by a reboot:
```
BCDEDIT /set nointegritychecks ON
```

# Response
In the event that this alert fires, the following response procedures are recommended:
* Identify the BCD properties that were modified.
* If only Flight Signing were modified, it is likely the user enrolled in WIP.
  * Check the current build of their machine and compare against public WIP builds.
  * If this is a true positive, work with the user to roll back to a stable build.
* If integrity checks or test signing are modified, treat as a high priority alert.
  * Investigation any processes which have executed since the last reboot. 
  * Identify any new loaded kernel modules or drivers.
  * If the user is unaware of this behavior, escalate to a security incident
* If debugging settings are modified, treat as a high priority alert.
  * Identify if any debuggers were used by the user. 
  * If the user is unaware of this behavior, escalate to a security incident.

# Additional Resources
* [Boot Configuration Data Documentation](https://msdn.microsoft.com/en-us/library/windows/hardware/dn653287(v=vs.85).aspx)
* [About Kernel Debugging](https://msdn.microsoft.com/en-us/library/windows/hardware/ff542191(v=vs.85).aspx)
* [About Hypervisor Debugging](https://msdn.microsoft.com/en-us/library/windows/hardware/ff538138(v=vs.85).aspx)
* [About Test Signing](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)
