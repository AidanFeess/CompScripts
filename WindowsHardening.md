
### Firewall
 - Turn Firewall On
```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
```
 - Create New Rule
 ```powershell
New-NetFirewallRule --DisplayName <Description of rule> --Direction <Inbound|Outbound> --LocalPort <port number> --Action <Allow|Block> 
 ```

 - Change or Edit a Rule
 ```powershell
Set-NetFirewallRule -DisplayName <Description> -Direction <Inbound|Outbound> -LocalPort <LocalPort> -Action <Allow|Block>
 ```

### Password
 - Change Password
Logout is needed to complete the change

```powershell
Get-LocalUser
$Password = Read-Host "Enter the new password" -AsSecureString
$UserAccount = Get-LocalUser -Name [Environment]::UserName
$UserAccount | Set-LocalUser -Password $Password
```

### Windows Defender(AV)
- Turn on Windows Defender
```powershell
Set-MpPreference -DisableRealtimeMonitoring $false

Set-MpPreference -DisableIOAVProtection $false

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force

start-service WinDefend
start-service WdNisSvc	
```

### Winpeas

 - Download and run winPeas
```powershell 
$url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("log")
```

### Group Policies Tricks

 - block users from using cmd(might not work)
```powershell
New-GPO -name "<name>" -domain "<domain-name>"
Set-GPRegistryValue -name "<name>" -key "HKCU\Software\Policies\Microsoft\Windows\System" -ValueName "<name>" -type Dword -value 00000002
New-GPlink -name "<name>" -Target <target> -LinkEnabled Yes
```
 - disable editing of the registry(may not work)
```powershell
New-GPO -name "<name>" -domain "<domain-name>"
Set-GPRegistryValue -name "<name>" -key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "<name>" -type Dword -value 00000002
New-GPLink -name "<name>" -Target $target -LinkEnabled Yes
```

 - disable starting/stopping services(may not work)
```powershell
New-GPO -name "<name>" -domain "<domain-name>"
Set-GPRegistryValue -name "<name>" -key "HKLM\Software\Policies\Microsoft\Windows\Task Scheduler5.0" -ValueName "<name>" -type Dword -value 00000004
New-GPLink -name "<name>" -Target $target -LinkEnabled Yes
```

 - block network shares ie "\\*" in group Policies(figure out how to do this in powershell)

 - disable powershell with GPO

### Active Directory

 - 


### Auditing Important groups

  - Admins

```
net localgroup Administrators
```

  - Remote Desktop Users

```
net localgroup "Remote Desktop Users"
```

  - Remote Management Users

```
net localgroup "Remote Management Users"
```

### Powershell Execution Policiy

  - checking the execution policiy
```powershell
Get-ExecutionPolicy
```

  - changing the execution policiy
```powershell
Set-ExecutionPolicy -ExecutionPolicy <Level> -Scope <Scope>
```

### Disable Guest Accounts 

```
net user guest /active no
```

### Auditing Running Processes

```
tasklist
```

 - Lists all process. Might need to filter on your own

```powershell
Get-Process
```

### SMB

 - Audit SMB shares

```
net view \\127.0.0.1
```

 - List the open sessions that are active with other machines

```
net use
```

 - List open sessions with the current machine

```
net use
```

### Scheduled Tasks

 - Shows the currentlt scheduled tasks

```
schtasks
```

### Services

 - List running services

```powershell
Get-Service | Where-Object {$_.Status -eq "running"}
```

 - Stop a running service
```powershell
Stop-Service -Name <service-name>
```

 - Start a stopped service
```powershell
Start-Service -Name <service-name>
```

 - resume a service
```powershell
Resume-Service
```

 - suspend a service
```powershell
Suspend-Service -Name <service-name>
```

### Autorun

 - Startup apps

```
wmic startup list full
```

```
wmic ntdomain list breif
```

### Networking

 - Get Active TCP connections
```powershell
Get-NetTCPConnection
```

 - View Network statistics
```
netstat
```

 - View Ip and such
```
ipconfig
```

