Import-Module Defender
Import-Module NetSecurity
Import-Module NetTCPIP
Import-Module GroupPolicy
Import-Module Microsoft.PowerShell.LocalAccounts

# install the list of tools
function installtools($toolsPath) {
	Write-Host "[+] installing tools..."

	# create a folder in the user directory
	New-Item -Path "C:\Users\$env::Username\Desktop" -Name Tools -type Directory
	
	# -- Download the specific tools instead of downloading the entire suite --
	
	# TCPView
	$TCPViewUrl = "https://download.sysinternals.com/files/TCPView.zip"	
	Invoke-WebRequest $TCPViewUrl -OutFile "$toolsPath\TCPView.zip"
	$zipPath = "$toolsPath\TCPView.zip"
	Expand-Archive -LiteralPath "$zipPath" -DestinationPath "$toolsPath\TCPView"
	
	# Procmon
	$ProcmonUrl = "https://download.sysinternals.com/files/ProcessMonitor.zip"	
	Invoke-WebRequest "$ProcmonUrl" -OutFile "$toolsPath\ProcessMonitor.zip"
	$zipPath = "$toolsPath\ProcessMonitor.zip"
	Expand-Archive -LiteralPath "$zipPath" -DestinationPath "$toolsPath\Procmon"
	
	# Autoruns/Autorunsc
	$AutorunsUrl = "https://download.sysinternals.com/files/Autoruns.zip"	
	Invoke-WebRequest "$AutorunsUrl" -OutFile "$toolsPath\Autoruns.zip"
	$zipPath = "$toolsPath\Autoruns.zip"
	Expand-Archive -LiteralPath "$zipPath" -DestinationPath "$toolsPath\Autoruns"
	
	Write-Host "[+] finished installing tools"
}

# once tools are run winpeas and parse the output and save it
function toolstart($toolsPath) {
	Write-Host "[+] opening tools..."

	# open autoruns, procmon, TCPView
	Invoke-Expresision "$toolsPath\Procmon\Procmon64.exe"
	Start-Sleep(500)
	Invoke-Expresision "$toolsPath\Autoruns\Autoruns64.exe"
	Start-Sleep(500)
	Invoke-Expresision "$toolsPath\TCPView\tcpview64.exe"
	Start-Sleep(500)

	$runWinpeas = Read-Host -Prompt "Would you like to run Winpeas"
	if ($runWinpeas -eq "y") {
		# run winpeas in the terminal
		$url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
		$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("log")

		# execute the parsers to convert to pdf
		$installPython = Read-Host -Prompt "Would you like to install Python?"
		if ($installPython -eq "y") {
			Write-Host "[+] WARNING this can leave your system vulnerable" 
			Write-Host "[+] Consider removing these items after use if they aren't going to be controlled" 

			Invoke-Webrequest "https://www.python.org/ftp/python/3.11.2/python-3.11.2-amd64.exe" -Outfile '$toolsPath\python3.exe'

			# download the parsers used for the output
		
			$jsonUrl = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/peas2json.py" 
			Invoke-WebRequest $jsonUrl -OutFile "$toolsPath\peas2json.py"

			$pdfUrl = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/json2pdf.py"
			Invoke-WebRequest $pdfUrl -OutFile "$toolsPath\json2pdf.py"

		}
		python3.exe '$toolsPath\peas2json.py'

		python3.exe '$toolsPath\json2pdf.py'
	}

	Write-Host "[+] all tools opened"
}

# edit and configure group policy
function EditGPO {
	param (
	
	)
}

# perform tasks to harden Exchange
function ExchangeHard {
	param (

	)
}

# updates windows
function winUP {
	param (
		
	)

	# TODO check and see if this actually works/if we want it
	Write-Host "[+] Setting up Windows Update..."
	
	# we will have to install this / need to make sure we can
	Install-Module -Name PSWindowsUpdate
	Import-Module PSWindowsUpdate

	Write-Host "[+] This will work in the background and Reboot when finished"
	
	Get-WindowsUpdate -AcceptAll -Install -AutoReboot

}

# winfire only blocks certain ports at the moment
function winFire {
	param (
		$mode
	)

	Write-Host "[+] hardening firewall with $mode..."

	# turn defaults on and set logging
	Set-NetFirewallProfile -Profile Dowmain, Public,Private -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow -NotifyOnListen True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

	# the only ports allowed at this point are
	# - rdp
	# - ssh
	# - http/https
	# - need to add any ftp and or smtp

	# block all ports not in the list of safe ports
	# work needs to be done to make sure that all required services can still run
	if ($mode == "lan") {
		$safeLs = @(21, 53, 80, 443, 587)

		# supposed to block remote connections outside of the local network, but allow any inside ones
		New-NetFirewallRule -DisplayName "allow all incoming connections" -Direction Inbound -LocalPort $safeLs -RemoteAddress Any -Action Allow
		New-NetFirewallRule -DisplayName "block all incoming connections used with safeLs" -Direction Inbound -LocalPort Any -Action Block
	}else{
		$safeLs = @(21, 22, 53, 80, 443, 587, 3389)

		# supposed to block remote connections outside of the local network, but allow any inside ones
		New-NetFirewallRule -DisplayName " allow all incoming connections from inside network" -Direction Inbound -RemoteAddress LocalSubnet  -Action Allow
		New-NetFirewallRule -DisplayName " block all incoming connections from outside network" -Direction Inbound -LocalPort 22, 5900 -RemoteAddress DefaultGateway -Action Block
	}

	# block all the high number ports
	New-NetFirewallRule -DisplayName "Block the high number ports" -Direction Inbound -LocalPort 5000-10000 -Protocol TCP -Action Block
	New-NetFirewallRule -DisplayName "Block the high number ports" -Direction Inbound -LocalPort 5000-10000 -Protocol TCP -Action Block

	Write-Host "[+] finished hardening firewall"
}

# open/close the ports that are requested
function editFirewallRule {
	param (
		$portNum, $action, $direction, $protocol
	)

	Write-Host "[+] editing firewall rule..."
	
	Set-NetFirewallRule -DisplayName "$action $direction $portNum" -Direction $direction -LocalPort $portNum -Protocol $protocol -Action $action
	
	Write-Host "[+] changed firewall rule for $port"
}

# change the password on admin account
function changeCreds {
	param (

	)

	Write-Host "[+] You are about to change the username of the current admin"
	$newUsername = Read-Host -Prompt "What is the new name?"
	Rename-LocalUser -Name "$env::Username" -NewName "$newUsername"
	Write-Host "[+] New username set"

	Write-Host "[+] You are now about to change your password"

	$Password = Read-Host "Enter the new password" -AsSecureString
	Get-LocalUser -Name "$env::Username" | Set-LocalUser -Password $Password
	
	Write-Host "[+] changed password for $env::Username"
	Write-Host "[+] MAKE SURE TO LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT"
}

function  removeTools {
	param (
		$toolsPath
	)

	Write-Host "[+] Removing the tools directory..."

	Remove-Item -LiteralPath "$toolsPath" -Force -Recurse

	Write-Host "[+] Deleted the tools directory"
}

function discovery {
	param (
		
	)

	Write-Host "[+] running discovery dump..."
	Write-Host "[+] YOU SHOULD STILL BE USING THE OTHER TOOLS THAT WERE INSTALLED"

	New-Item -Path "C:\Users\$env::Username\Desktop" -Name Discovery -type Directory

	$discoverypath = "C:\Users\$env::Username\Desktop\Discovery"
	Get-Service -Verbose > "$discoverypath\services.txt"
	Get-Process -Verbose > "$discoverypath\processes.txt"
	Get-NetTCPConnection -Verbose > "$discoverypath\processes.txt"
	schtasks.exe > "$discoverypath\scheduledtasks.txt"

	Write-Host "[+] dump dumped"

}

function setUAC {
	param (
		
	)

	Write-Host "[+] setting UAC values..."

	# set the values
	$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
	New-ItemProperty -Path $path -Name 'ConsentPromptBehaviorAdmin' -Value 2 -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $path -Name 'ConsentPromptBehaviorUser' -Value 3 -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $path -Name 'EnableInstallerDetection' -Value 1 -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $path -Name 'EnableLUA' -Value 1 -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $path -Name 'EnableVirtualization' -Value 1 -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $path -Name 'PromptOnSecureDesktop' -Value 1 -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $path -Name 'ValidateAdminCodeSignatures' -Value 0 -PropertyType DWORD -Force | Out-Null
	New-ItemProperty -Path $path -Name 'FilterAdministratorToken' -Value 0 -PropertyType DWORD -Force | Out-Null

	Write-Host "[+] values set"
}


function DefenderScan {
	param (
		
	)

	# runs a basic windows defender scan	

	# check to make sure windows defender is able to run
	if (Get-MpComputerStatus) {
		Write-Host "[+] setting up for scan..."
		Set-MpPreference -CheckForSignaturesBeforeRunningScan True -CloudBlockLevel

		Write-Host "[+] removing any exclusions..."
		# remove all exclusion if there are any
		$preference = Get-MpPreference
		foreach ($x in $preference.ExclusionPath) {
			Remove-MpPreference -ExclusionPath $x
		}

		Write-Host "[+] running scan in the background..."
		
		# TODO receive output from scan
		Start-MpScan -ScanType FullScan -AsJob -Verbose
	}else {
		Write-Host "[+] error in checking windows defender"
	}
	
}

function main() {
	# TODO add way to revert all changes so that fixes can be made

	$toolsPath = "C:\Users\$env::Username\Desktop\Tools"

	# check if the Tools folder is already created
	if (Test-Path -Path "C:\Users\$env::Username\Desktop\Tools" -eq True) {

		Write-Host "[+] checking to see if the tools are installed..."
		if (Get-ChildItem -Path "C:\Users\$env::Username\Desktop\Tools" -Recurse | Measure-Object -eq 0) {

			installtools ($toolsPath)
		}
	}

	Write-Output "[+] choose a mode to run the script"
	Start-Sleep -Milliseconds 500
	Write-Output "[+] harden will start the hardening process on the current machine"
	Start-Sleep -Milliseconds 500
	Write-Output "[+] control will allow the user to make changes to windows without having to navigate around"
	Start-Sleep -Milliseconds 500
	$usermode = Read-Host -Prompt "(Harden) or (Control)"
	if ($usermode -eq "harden" -or "Harden") {

		# install malwarebytes
		Write-Host "[+] downloading malwarebytes..."
		Invoke-WebRequest "https://downloads.malwarebytes.com/file/mb-windows" -OutFile "$toolsPath\mb.exe"

		# Run Malwarebytes
		Write-Host "[+] click to install the software"
		Invoke-Expression "$toolsPath\mb.exe"

		Start-Sleep -Milliseconds 1000
		
		#Long but disables all guests
		Write-Host "[+] clearing out guest accounts..."

		$user = Get-LocalGroup -Name "guests" | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -Skip 4
		foreach ($x in $user) { 
			Write-Output "disabling guest: $x"
			Disable-LocalUser -Name $x
		}
		Write-Host "[+] guest accounts cleared"

		# remove all the non-required admin accounts
		Write-Host "[+] removing all admin accounts...execpt yours"

		# TODO check to make sure this works
		$user = Get-LocalGroup -Name "Administrators" | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -Skip 4
		foreach ($x in $user) {
			if ($env::Username -notmatch $user) {
				Write-Output "disabling admin: $x"
				Remove-LocalGroupMember -Group "Administrators" "$x"
			}
		}
		Write-Host "[+] pruned Administrator accounts"

		# harden the firewall for remote or lan comps
		$winFirewallOn = Read-Host -Prompt "Do you want to turn on the windows firewall (y)"
		if ($winFirewallOn -eq "y" -or "Y") {
			$mode = Read-Host -Prompt "lan or remote (lan) or (remote)"
			winFire ($mode)
		}

		$hardenExch = Read-Host -Prompt "Do you want to Harden Exchange (y)"
		if ($hardenExch -eq "y" -or "Y") {
			ExchangeHard
		}

		# turn on Windows Defender
		# Windows 8.1 (server 2016+) should already be on
		if (Get-MpComputerStatus | Select-Object "AntivirusEnabled" -eq $false) {
			$turnDefenderOn = Read-Host -Prompt "Do you want to turn on Windows Defender (y)"
			# TODO need to test

			Write-Host "Enabling Windows Defender..."
			if ($turnDefenderOn -eq "y") {
				Set-MpPreference -DisableRealtimeMonitoring $false
				Set-MpPreference -DisableIOAVProtection $false
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force
				New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force
				New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force
				New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force
				New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
				start-service WinDefend
				start-service WdNisSvc	
			}
			Write-Host "Windows Defender Enabled"
		}
		
		# start all the tools to find any possible weird things running
		toolstart($toolsPath)

		# change the execution policy for powershell for admins only (works for the current machine)
		# rest of restrictions happen in group policy and active directory
		Write-Host "[+] changing powershell policy..."
		Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine
		Write-Host "[+] Changed the Powershell policy to Restricted"

		# disable WinRM
		$disableWinRm = Read-Host -Prompt "disable WinRm? (y)"
		if ($disableWinRm -eq "y" -or "Y") {
			Disable-PSRemoting -Force
			Write-Host "[+] disabled WinRm"
		}

		# change the password/username of the current admin
		changeCreds 
		
		# setup UAC
		setUAC

		# disable anonymous logins
		Write-Host "[+] disabling anonymous users..."
		Set-CsAccessEdgeConfiguration -AllowAnonymousUsers $False
		Write-Host "[+] disabled anonymous users"

		# enable/install wdac/applocker/or DeepBlue CLi?


		# disable netbios ??????(might be to good)
		$adapters=(Get-WmiObject win32_networkadapterconfiguration )
		foreach ($adapter in $adapters){
			Write-Host $adapter
			$adapter.settcpipnetbios(0)
		}

		# update windows potentially
		$updates = Read-Host -Prompt "Do you want to update (y)"
		if ($updates -eq "y" -or "Y") {
			winUP
		}

	}else{
		while($true) {
			Write-Host "[+] what would you like to do
			- edit a firewall rule(1)
			- change a group policy(2)
			- Change Password(3)
			- Install Tools(4)
			- Start Tools(5)
			- Remove Tools(6)
			- Discovery(7)
			- DefenderScan(8)
			- quit
			"
			$choice = Read-Host 
			switch ($choice) {

				"1" {
					$portNum = Read-Host -Prompt "which port (num)"
					$action = Read-Host -Prompt "(allow) or (block)"
					$direction = Read-Host -Prompt "which direction (in) or (out)"
					editFirewallRule ($portNum, $action, $direction)
				}

				"2" {

					# TODO populate this with stuff after group policy is added
				}

				"3" {changeCreds}

				"4" {installtools($toolsPath)}

				"5" {toolstart($toolsPath)}

				"6" {removeTools($toolsPath)}

				"7" {discovery}

				"8" {DefenderScan}

				"quit" {break}

				default {continue}
			} 
		}
	}
}

