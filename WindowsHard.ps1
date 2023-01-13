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
function toolstart($curUsr) {
	# open autoruns and procmon
	
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

# perform tasks to harden Exchange
function ExchangeHard() {
}

# updates windows
function winUP() {
}

# winfire only blocks certain ports at the moment
function winFire(){
	# turn the firewall on in all profiles
	Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

	# turn defaults on and set logging
	Set-NetFirewallRule -DefaultInboundAction Allow -DefaultOutboundAction Allow –LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

	# # block all remote access on a system
	# New-NetFirewallRule -DisplayName “Block Inbound Telnet” -Direction Inbound -LocalPort 23 -Action Block
	# New-NetFirewallRule -DisplayName “Block Outbound Telnet” -Direction Outbound -LocalPort 23 -Action Block

	# New-NetFirewallRule -DisplayName “Block Inbound msrpc” -Direction Inbound -LocalPort 135  -Action Block
	# New-NetFirewallRule -DisplayName “Block Outbound msrpc” -Direction Outbound -LocalPort 135  -Action Block

	# New-NetFirewallRule -DisplayName “Block Inbound rdp” -Direction Inbound -LocalPort 3389 -Action Block
	# New-NetFirewallRule -DisplayName “Block Outbound rdp” -Direction Outbound -LocalPort 3389 -Action Block

	# New-NetFirewallRule -DisplayName “Block Inbound ssh” -Direction Inbound -LocalPort 22 -Action Block
	# New-NetFirewallRule -DisplayName “Block Outbound ssh” -Direction Outbound -LocalPort 22 -Action Block

	# block all ports not in the list of safe ports
	# TODO add port for ftp and smtp
	$safeLs = @(22, 80, 443, 3389)
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
function openPort($portNum, $action, $direction) {
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
	[string]$curUsr = $env::Username
	changePass $curUsr

	# disable the old login accounts
	net user quest /active:no

	# list of tools to install
	# winpeas, sysinternal suite
	$toolsPath = "C:\Users\$curUsr\Tools\"

	# check if the Tools folder is already created
	if (Test-Path -Path "C:\Users\$curUsr\Tools" == True) {

		if (Get-ChildItem -Path "C:\Users\$curUsr\Tools\" -Recurse | Measure-Object == 0) {

		install-tools ($toolsPath)
		}
	}

	toolstart($curUsr)

	# if ActiveDirectory
	$ActiveDirectoryPresent = 
	if ($ActiveDirectoryPresent == True) {
		$hardenAD = Read-Host -Prompt "Do you want to Harden AD (y)"
		if ($hardenAD == "y") {
			ADHard
		}
	}

	$ExchangePresent = 
	if ($ExchangePresent == True) {
		$hardenExch = Read-Host -Prompt "Do you want to Harden Exchange (y)"
		if ($hardenExch == "y") {
			ExchangeHard
		}
	}

	# remove the tools directory once finished with recon
	$removeTools = Read-Host -Prompt "Do you want to remvove the tools folder (n)"
	if ($removeTools == "y") {
		Remove-Item -LiteralPath "$toolsPath" -Force -Recurse
	}
	
	# turn on Windows Defender
	$turnDefenderOn = Read-Host -Prompt "Do you want to turn on Windows Defender (y)"
	# Windows 8.1 (server 2016+) should already be on
	# pulled from(https://support.huntress.io/hc/en-us/articles/4402989131283-Enabling-Microsoft-Defender-using-Powershell-)
	# need to test
	if ($turnDefenderOn == "y") {
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
	
	# maybe perform windows updates?(Rules permitting)
	$updates = Read-Host -Prompt "Do you want to update (y)"
	if ($updates == True) {
		winUP
	}
}
