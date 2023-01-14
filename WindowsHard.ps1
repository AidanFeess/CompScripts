Import-Module ActiveDirectory
Import-Module Defender
Import-Module WindowsUpdate
Import-Module GroupPolicy

# install the list of tools
function installtools($toolsPath, $curUsr) {
	# create a folder in the user directory
	New-Item -Path "C:\Users\$curUsr" Tools -type Directory
	
	# From the README
	$winpeasurl = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
	Invoke-WebRequest "$winpeasurl" -OutFile "$toolsPath" + "winPEASany_ofs.exe"

	# download the parsers used for the output
	$jsonUrl = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/peas2json.py" 
	Invoke-WebRequest "$jsonUrl" -OutFile "$toolsPath" + "peas2json.py"

	$pdfUrl = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/json2pdf.py"
	Invoke-WebRequest "$pdfUrl" -OutFile "$toolsPath" + "json2pdf.py"

	# download the sysinternal suite and unzip into Tools
	$sysUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip"	
	$zipPath = "$toolsPath" + "SysinternalsSuite.zip"
	Invoke-WebRequest "$sysUrl" -OutFile "$zipPath"

	Expand-Archive -LiteralPath '$zipPath' -DestinationPath "$toolsPath" + "SysinternalsSuite"

}

# once tools are run winpeas and parse the output and save it
function toolstart($curUsr, $toolsPath) {
	# open autoruns and procmon
	Invoke-Expresision "& '"$toolsPath\sysinternals\procmon.exe""
	
	# run winpeas in the terminal
	# from the README(github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe)
	$url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
	$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("log")

	# execute the parsers to convert to pdf
	if (!python.exe) {
		winget install Python3
	}
	python3.exe 'C:\Users\$curUsr\Tools\peas2json.py'

	python3.exe 'C:\Users\$curUsr\Tools\json2pdf.py'
}

# perform Group Policy changes
# change privlege
function ADHard() {
}

# edit and configure AD
function EditAD() {
}

# edit and configure group policy
function EditGPO() {
}

# perform tasks to harden Exchange
function ExchangeHard() {
}

# updates windows
function winUP() {
}

# winfire only blocks certain ports at the moment
function winFire($mode){
	# turn the firewall on in all profiles
	Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

	# turn defaults on and set logging
	Set-NetFirewallProfile -DefaultInboundAction Allow -DefaultOutboundAction Allow -NotifyOnListen True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

	# the only ports allowed at this point are
	# - rdp
	# - http/https
	# - need to add any ftp and or smtp

	# block all ports not in the list of safe ports
	if ($mode == "lan") {

		# TODO add previously listed ports here
		$safeLs = @(80, 443)
	}else{

		# TODO same as line 79
		$safeLs = @(80, 443, 3389)
	}

	$port = 0
	ForEach($port in 5000) {
		if ($port == $safeLs) {
			continue;
		}else {
			New-NetFirewallRule -DisplayName "Block Inbound Port $port" -Direction Inbound -LocalPort $port -Protocol TCP -Action Block
			New-NetFirewallRule -DisplayName "Block Outbound Port $port" -Direction Outbound -LocalPort $port -Protocol TCP -Action Block
		}
	}
}

# open the ports that are requested
function editFirewallRule($portNum, $action, $direction) {
	Set-NetFirewallRule -DisplayName "$action $direction $portNum" -Direction $direction -LocalPort $portNum -Action $action
}

# change the password on admin account
function changePass($curUsr) {
	Get-LocalUser
	$Password = Read-Host "Enter the new password" -AsSecureString
	$UserAccount = Get-LocalUser -Name "$curUsr"
	$UserAccount | Set-LocalUser -Password $Password
}

function main() {
	# list of tools to install
	# winpeas, sysinternal suite
	$toolsPath = "C:\Users\$curUsr\Tools\"

	# check if the Tools folder is already created
	if (Test-Path -Path "C:\Users\$curUsr\Tools" == True) {

		if (Get-ChildItem -Path "C:\Users\$curUsr\Tools\" -Recurse | Measure-Object == 0) {

			install-tools ($toolsPath)
		}
	}

	Write-Output "[+] choose a mode to run the script"
	Start-Sleep -Milliseconds 500
	Write-Output "[+] harden will start the hardening process on the current machine"
	Start-Sleep -Milliseconds 500
	Write-Output "[+] control will allow the user to make changes to windows without having to navigate around"
	Start-Sleep -Milliseconds 500
	$usermode = Read-Host -Prompt "(Harden) or (Control)"
	if ($usermode == "harden" or "Harden") {

		# disable the old login accounts
		net user quest /active no
		# harden the firewall for remote or lan comps
		$winFirewallOn = Read-Host -Prompt "Do you want to turn on the windows firewall (y)"
		if ($winFirewallOn == "y") {
			$mode = Read-Host -Prompt "lan or remote (lan) or (remote)"
			winFire ($mode)
		}

		# if ActiveDirectory
		$hardenAD = Read-Host -Prompt "Do you want to Harden AD (y)"
		if ($hardenAD == "y") {
			ADHard
		}

		$hardenExch = Read-Host -Prompt "Do you want to Harden Exchange (y)"
		if ($hardenExch == "y") {
			ExchangeHard
		}

		# turn on Windows Defender
		# if (!Get-MpComputerStatus) {
		# 	$turnDefenderOn = Read-Host -Prompt "Do you want to turn on Windows Defender (y)"
		# 	# Windows 8.1 (server 2016+) should already be on
		# 	# pulled from(https://support.huntress.io/hc/en-us/articles/4402989131283-Enabling-Microsoft-Defender-using-Powershell-)
		# 	# need to test
		# 	if ($turnDefenderOn == "y") {
		# 		Set-MpPreference -DisableRealtimeMonitoring $false
		# 		Set-MpPreference -DisableIOAVProtection $false
		# 		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force
		# 		New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force
		# 		New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force
		# 		New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force
		# 		New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
		# 		start-service WinDefend
		# 		start-service WdNisSvc	
		# 	}
		# }
		
		# start all the tools to find any possible weird things running
		toolstart($curUsr, $toolsPath)

		# remove the tools directory once finished with recon
		$removeTools = Read-Host -Prompt "Do you want to remvove the tools folder (n)"
		if ($removeTools == "y") {
			Remove-Item -LiteralPath "$toolsPath" -Force -Recurse
		}
		
		# maybe perform windows updates?(Rules permitting)
		$updates = Read-Host -Prompt "Do you want to update (y)"
		if ($updates == True) {
			winUP
		}

		# change the password
		Write-Host "[+] you are about to change your password"
		[string]$curUsr = $env::Username
		changePass $curUsr
		Write-Host "[+] MAKE SURE TO LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT"

		# change the execution policy for powershell for admins only (works for the current machine)
		# rest of restrictions happen in group policy and active directory
		Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine

		# disable WinRM
		Disable-PSRemoting -Force

		# enable applocker

	}else{
		while(True) {
			Write-Host "[+] what would you like to do
			- edit a firewall rule(1)
			- change a group policy(2)
			- edit active directory(3)
			- toolstart(4)
			- quit(5)
			"
			$choice = Read-Host 
			switch ($choice) {

				condition1 {$choice == "1"}
				condition1 {
					$portNum = Read-Host -Prompt "which port (num)"
					$action = Read-Host -Prompt "(allow) or (block)"
					$direction = Read-Host -Prompt "which direction (in) or (out)"
					editFirewallRule ($portNum, $action, $direction)
				}

				condition2 {$choice == "2"}
				condition2 {

					# TODO populate this with stuff after group policy is added

				}

				condition3 {$choice == "3"}
				condition3 {

					# TODO populate this with stuff after group policy is added

				}

				condition4 {$choice == "4"}
				condition4 {
					toolstart($curUsr, $toolsPath)
				}

				condition5 {$choice == "5"}
				condition5 {
					break
				}

				default {
					continue
				}
			}
		}
	}
}
