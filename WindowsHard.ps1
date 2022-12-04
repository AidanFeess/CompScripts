Import-Module ActiveDirectory
Import-Module Defender
Import-Module WindowsUpdate
Import-Module GroupPolicy

function installtools($toolsPath) {
	# create a folder in the user directory
	[string]$curUsr = $env::Username
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

function ADHard() {
}

function ExchangeHard() {
}

function winUP() {
}

function winFire(){
	# block ssh, rdp and msrcp by default
	Set-NetFirewallRule -
}

function main() {
	# list of tools to install
	# winpeas, sysinternal suite
	$toolsPath = "C:\Users\$curUsr\Tools\"

	# check if the Tools folder is already created
	if (Test-Path -Path "C:\Users\$curUsr\Tools" == True) {

		if (Get-ChildItem -Path "C:\Users\$curUsr\Tools\" -Recurse | Measure-Object == 0) {

		# install the list of tools
		install-tools $toolsPath
		}
	}

	$ExchangePresent = 
	if (ExchangePresent == True) {
		# ask to harden Exchange
		# mostly just secure the server normally
		$hardenExch = Read-Host -Prompt "Do you want to Harden Exchange (y)"
		if ($hardenExch == "y") {
			ExchangeHard
		}
	}

	# once tools are run winpeas and parse the output and save it
	toolstart($curUsr)

	# if ActiveDirectory
	$ActiveDirectoryPresent = 
	if ($ActiveDirectoryPresent == True) {
		$hardenAD = Read-Host -Prompt "Do you want to Harden AD (y)"
		if ($hardenAD == "y") {
			ADHard
		}
	}
	
	# remove the tools directory once finished with recon
	Remove-Item -LiteralPath "$toolsPath" -Force -Recurse

	# maybe perform windows updates?(Rules permitting)
	winUP
}
