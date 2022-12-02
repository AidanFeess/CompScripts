Import-Module ActiveDirectory

function install-tools($toolsPath) {
	$winpeasurl = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
	# create a folder in the user directory
	[string]$curUsr = $env::Username
	New-Item -Path "C:\Users\$curUsr" Tools -type Directory
	

	# download winpeas from repo 
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

function tool-start($toolsPath) {
	[string]$curUsr = $env::Username

	# open autoruns and procmon
	
	# run winpeas in a terminal
	# from the README
	$wp = [System.Reflection.Assembly]::Load([byte[]]([IO.File]::ReadAllBytes("C:\Users\$curUsr\Tools\winPEASany_ofs.exe")));
	$wp.EntryPoint 

	# direct to log to an out File
	[<ReflectedType_from_before>]::Main("")
}

function AD-Hard() {
}

function Exchange-Hard() {
}

function winUP() {
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
	

	# once tools are run winpeas and parse the output and save it
	tool-start($toolsPath)

	# if ActiveDirectory
	$input = Read-Host -Prompt "Do you want to Harden AD (y)"
	if (input == "y") {
		AD-Hard
	}
	# if Exchange
	$input = Read-Host -Prompt "Do you want to Harden Exchange (y)"
	if (input == "y") {
		Exchange-Hard
	}
	
	# remove the tools directory once finished with recon
	Remove-Item -LiteralPath "$toolsPath" -Force -Recurse

	# maybe perform windows updates?(Rules permitting)
	winUP
}
