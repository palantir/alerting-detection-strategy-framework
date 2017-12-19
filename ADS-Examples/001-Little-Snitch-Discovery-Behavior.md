# Goal
Detect attempts by potentially malicious software to discover the presence of Little Snitch on a host by looking for process and command line artifacts.

# Categorization
These attempts are categorized as [Discovery / Security Software Discovery](https://attack.mitre.org/wiki/Technique/T1063).

# Strategy Abstract
The strategy will function as follows: 

* Record process and process command line information for MacOS hosts using endpoint detection tooling.
* Look for any explicit process or command line references to Little Snitch. 
* Suppress known-good processes and command line arguments
  * Little Snitch Updater
  * Little Snitch Installer
  * Health checks for Little Snitch
* Fire alert on any other process or command line activity.

# Technical Context
[Little Snitch](https://www.obdev.at/products/littlesnitch/index.html) is an application firewall for MacOS that allows users to generate rulesets around how applications can communicate on the network. 

In the most paranoid mode, Little Snitch will launch a pop-up notifying the user that an application has deviated from a ruleset. For instance, the following events could trip an interactive alert:

A new process is observed attempting to communicate on the network.
A process is communicating with a new IP address or port which differs from a ruleset.
The following prompt demonstrates the expected behavior of Little Snitch:

Due to the intrusive nature of Little Snitch popups, [several MacOS implants](https://blog.malwarebytes.com/cybercrime/2016/07/new-mac-backdoor-malware-eleanor/) will perform explicit checks for processes, kexts, and other components. This usually manifests through explicit calls to the process (ps) or directory (dir) commands with sub-filtering for Little Snitch.

For instance, an implant could look for the following components: 

* Running Little Snitch processes
* Little Snitch Kexts
* Little Snitch Plists 
* Little Snitch Rules 

The following code is explicitly run by the Powershell Empyre agent as soon as it executes on a MacOS system: 
```
/bin/sh -c ps -ef | grep Little\\ Snitch | grep -v grep
```
The following screenshot shows the same command as part of a endpoint detection tooling process execution chain: 

Looking at the [source code for Powershell Empyre](https://github.com/EmpireProject/Empire/blob/8f3570b390d6f91d940881c8baa11e2b2586081a/lib/listeners/http.py) reveals the explicit check using the ps and grep commands:
```
 try:
     if safeChecks.lower() == 'true':
         launcherBase += "import re, subprocess;"
         launcherBase += "cmd = \"ps -ef | grep Little\ Snitch | grep -v grep\"\n"
         launcherBase += "ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)\n"
         launcherBase += "out = ps.stdout.read()\n"
         launcherBase += "ps.stdout.close()\n"
         launcherBase += "if re.search(\"Little Snitch\", out):\n"
         launcherBase += "   sys.exit()\n"
 except Exception as e:
     p = "[!] Error setting LittleSnitch in stager: " + str(e)
     print helpers.color(p, color='red')
```

# Blind Spots and Assumptions

This strategy relies on the following assumptions: 
* Endpoint detection tooling is running and functioning correctly on the system.
* Process execution events are being recorded.
* Logs from endpoint detection tooling are reported to the server.
* Endpoint detection tooling is correctly forwarding logs to SIEM.
* SIEM is successfully indexing endpoint detection tooling logs. 
* Attacker toolkits will perform searches to identify if Little Snitch is installed or running.

A blind spot will occur if any of the assumptions are violated. For instance, the following would not trip the alert: 
* Endpoint detection tooling is tampered with or disabled.
* The attacker implant does not perform searches for Little Snitch in a manner that generates a child process.
* Obfuscation occurs in the search for Little Snitch which defeats our regex.

# False Positives
There are several instances where false positives for this ADS could occur:

* Users explicitly performing interrogation of the Little Snitch installation
  * Grepping for a process, searching for files.
* Little Snitch performing an update, installation, or uninstallation.
  * We miss whitelisting a known-good process.
* Management tools performing actions on Little Snitch.
  * We miss whitelisting a known-good process.

Known false positives include:
* Little Snitch Software Updater

Most false positives can be attributed to scripts or user behavior looking at the current state of Little Snitch. These are either trusted binaries (e.g. our management tools) or are definitively benign user behavior (e.g. the processes performing interrogation are child processes of a user shell process).

# Priority
The priority is set to medium under all conditions.

# Validation
Validation can occur for this ADS by performing the following execution on a MacOS host: 
```
/bin/sh -c ps -ef | grep Little\\ Snitch | grep -v grep
```

# Response
In the event that this alert fires, the following response procedures are recommended: 

* Look at management tooling to identify if Little Snitch is installed on the host.
  * If Little Snitch is not installed on the Host, this may be more suspicious.
* Look at the process that triggered this alert. Walk the process chain.
  * What process triggered this alert?
  * What was the user the process ran as?
  * What was the parent process?
  * Are there any unusual discrepancies in this chain?
* Look at the process that triggered this alert. Inspect the binary.
  * Is this a shell process?
  * Is the process digitally signed?
  * Is the parent process digitally signed?
  * How prevalent is this binary?
* Does this appear to be user-generated in nature?
  * Is this running in a long-running shell?
  * Are there other indicators this was manually typed by a user?
  * If the activity may have been user-generated, reach out to the user via our chat client and ask them to clarify their behavior.
* If the user is unaware of this behavior, escalate to a security incident.
* If the process behavior seems unusual, or if Little Snitch is not installed, escalate to a security incident. 

# Additional Resources
* [Elanor Mac Malware (Representative Sample)](https://blog.malwarebytes.com/cybercrime/2016/07/new-mac-backdoor-malware-eleanor/)

