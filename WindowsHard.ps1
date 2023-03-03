Import-Module Defender
Import-Module NetSecurity
Import-Module NetTCPIP
Import-Module GroupPolicy
Import-Module Microsoft.PowerShell.LocalAccounts
Import-Module Microsoft.PowerShell.Utility
Import-Module ScheduledTasks

# install the list of tools
function installtools {
	param (
		$toolsPath,
		$curUsr
	)

	Write-Host "[+] installing tools..."

	# create a folder in the user directory
	New-Item -Path "C:\Users\$curUsr\Desktop" -Name Tools -type Directory
	
	# -- Download the specific tools instead of downloading the entire suite --
	
	# TCPView
	$TCPViewUrl = "https://download.sysinternals.com/files/TCPView.zip"	
	Invoke-WebRequest $TCPViewUrl -OutFile "$toolsPath\TCPView.zip" -ErrorAction Continue -ErrorVariable $DownTCP

    if ($DownTCP) {
        
        Write-Output "[-] Error in downloading TCPView, make sure you have internet access" | Out-File -FilePath "$toolsPath\ErrLog.txt"

    }
	
    $zipPath = "$toolsPath\TCPView.zip"
	Expand-Archive -LiteralPath "$zipPath" -DestinationPath "$toolsPath\TCPView" -ErrorAction Continue -ErrorVariable $UNZTCP

    if ($UNZTCP) {
        
        Write-Output "[-] Error in unziping TCPView, make sure it was downloaded" | Out-File -FilePath "$toolsPath\ErrLog.txt"

    }
	
	# Procmon
	$ProcmonUrl = "https://download.sysinternals.com/files/ProcessMonitor.zip"	
	Invoke-WebRequest "$ProcmonUrl" -OutFile "$toolsPath\ProcessMonitor.zip" -ErrorAction Continue -ErrorVariable $DownProcmon

    if ($DownProcmon) {
        
        Write-Output "[-] Error in downloading Procmon, make sure you have internet access" | Out-File -FilePath "$toolsPath\ErrLog.txt"

    }
	
    $zipPath = "$toolsPath\ProcessMonitor.zip"
	Expand-Archive -LiteralPath "$zipPath" -DestinationPath "$toolsPath\Procmon" -ErrorAction Continue -ErrorVariable $UNZPROC

    if ($UNZPROC) {
        
        Write-Output "[-] Error in unziping Procmon, make sure it was downloaded" | Out-File -FilePath "$toolsPath\ErrLog.txt"

    }
	
	# Autoruns/Autorunsc
	$AutorunsUrl = "https://download.sysinternals.com/files/Autoruns.zip"	
	Invoke-WebRequest "$AutorunsUrl" -OutFile "$toolsPath\Autoruns.zip" -ErrorAction Continue -ErrorVariable $DownAutoruns

    if ($DownAutoruns) {
        
        Write-Output "[-] Error in downloading Autoruns, make sure you have internet access" | Out-File -FilePath "$toolsPath\ErrLog.txt"

    }
	
    $zipPath = "$toolsPath\Autoruns.zip"
	Expand-Archive -LiteralPath "$zipPath" -DestinationPath "$toolsPath\Autoruns" -ErrorAction Continue -ErrorVariable $UNZAuto

    if ($UNZAuto) {
        
        Write-Output "[-] Error in unziping Autoruns, make sure it was downloaded" | Out-File -FilePath "$toolsPath\ErrLog.txt"

    }
	
	Write-Host "[+] finished installing tools"
}

# once tools are run winpeas and parse the output and save it
function toolstart {
	param (
		$toolsPath
	)

	Write-Host "[+] opening tools..."

	# open autoruns, procmon, TCPView
	Invoke-Expresision -Command "$toolsPath\Procmon\Procmon64.exe"
	Start-Sleep(500)
	
    Invoke-Expresision -Command "$toolsPath\Autoruns\Autoruns64.exe"
	Start-Sleep(500)
	
    Invoke-Expresision -Comand "$toolsPath\TCPView\tcpview64.exe"
	Start-Sleep(500)

	$runWinpeas = Read-Host -Prompt "Would you like to run Winpeas"
	if ($runWinpeas -eq ("y" -or "Y")) {
		
        # run winpeas in the terminal
		$url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
		$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("log")

		# execute the parsers to convert to pdf
		$installPython = Read-Host -Prompt "Would you like to install Python?"
		if ($installPython -eq ("y" -or "Y")) {
		
        	Write-Host "[+] WARNING this can leave your system vulnerable" 
			Write-Host "[+] Consider removing these items after use if they aren't going to be controlled" 

			Invoke-Webrequest "https://www.python.org/ftp/python/3.11.2/python-3.11.2-amd64.exe" -Outfile '$toolsPath\python3.exe' -ErrorAction Continue -ErrorVariable $DownPYTHON

            if ($DownPYTHON) {
                
                Write-Output "[-] Error in downloading python3 installer, make sure you have internet access" | Out-File -FilePath "$toolsPath\ErrLog.txt"

            }

            # still need to manually install
            Write-Host "[+] install python and make sure to add to your path"

            Invoke-Expression -Command "$toolSPath\python3.exe" 

            # should refresh the path so that the parsers can be used in the same session
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

            # -- download the parsers used for the output --
		
			$jsonUrl = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/peas2json.py" 
			Invoke-WebRequest $jsonUrl -OutFile "$toolsPath\peas2json.py" -ErrorAction Continue -ErrorVariable $DownJSONPARSE

            if ($DownJSONPARSE) {
        
                Write-Output "[-] Error in downloading json peas parser, make sure you have internet access" | Out-File -FilePath "$toolsPath\ErrLog.txt"

            }
            
			$pdfUrl = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/json2pdf.py"
			Invoke-WebRequest $pdfUrl -OutFile "$toolsPath\json2pdf.py" -ErrorAction Continue -ErrorVariable $DownPDFPARSE

            if ($DownPDFPARSE) {
        
                Write-Output "[-] Error in downloading pdf peas parser, make sure you have internet access" | Out-File -FilePath "$toolsPath\ErrLog.txt"

            }

		}
		
        # run the parsers so that it can be viewed easily
        python3.exe '$toolsPath\peas2json.py $toolsPath\log.out $toolsPath\peas.json'

		python3.exe '$toolsPath\json2pdf.py $toolsPath\peas.json $toolsPath\peas.pdf'
    
        # open the pdf for viewing
        Start-Process ((Resolve-Path "C:\..\peas.pdf").Path)
        
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
        $mode
	)
    
    Import-Module ExchangePowerShell

    if ($mode = "undo") {
        # do the hardening
    }

    if ($mode = "undo") {

        # do the unhardening
    }

    
}


# updates windows
function winUP {
	param (
		
	)

	# TODO check and see if this actually works/if we want it
	Write-Host "[+] Setting up Windows Update..."
	
	# we will have to install this / need to make sure we can
	Install-Module -Name PSWindowsUpdate -ErrorAction Continue -ErrorVariable $INSPSudpate

    if ($INSPSudpate) {
        
        Write-Output "[-] Error in installing PSUpdate" | Out-File -FilePath "$toolsPath\ErrLog.txt"

    }else{

	    Import-Module PSWindowsUpdate
        
        Write-Host "[+] This will work in the background and will need to Reboot when finished"
	
	    Get-WindowsUpdate -AcceptAll -Install
    }

	

}


# winfire only blocks certain ports at the moment
function winFire {
	param (
       $mode 
	)

	Write-Host "[+] hardening firewall with $mode..."

	# turn defaults on and set logging
	Set-NetFirewallProfile -Profile Dowmain, Public,Private -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow -NotifyOnListen True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

	# get the current listening conections ports
	$a = Get-NetTCPConnection -State Listen | Select-Object -Property LocalPort -ErrorVariable $GetListen -ErrorAction Continue

    if ($GetListen) {

        Write-Output "[-] Error in geting the active list of listening ports" | Out-File -FilePath "toolsPath\ErrOut.txt"
                 
    }

	Write-Host "[+] You are possibly going to be asked if you want to block certain ports"
	Write-Host "[+] your options are ( y ) or ( n )"

	# parse the list to remove ports that shouldn't 
	foreach ($x in $a) {
		
		if ($x -eq 22) {

			$response = Read-Host -Prompt "Do you want to block ssh?"

			if ($response -eq ("y" -or "Y")) {
			
               	$a[$x].Remove	
				Write-Host "[+] ssh(22) blocked"

			}else{

				Write-Host "[+] ssh(22) will remain open"

			}
		}

		if ($x -eq 5900) {
	
    		$response = Read-Host -Prompt "Do you want to block vnc?"

			if ($response -eq "y" -or "Y") {
	
    			$a[$x].Remove
    			Write-Host "[+] vnc(5900) blocked"

			}else{
	
    			Write-Host "[+] vnc(5900) will remain open"
	
    		}
		}

		if ($x -eq 3389) {
	
    		$response = Read-Host -Prompt "Do you want to block rdp?"

			if ($response -eq "y" -or "Y") {
	
    			$a[$x].Remove
	
    			Write-Host "[+] rdp(389) blocked"
	
    		}else{
	
    			Write-Host "[+] rdp(389) will remain open"
	
    		}
		}


	}

	# TODO supposed to allow already existing connections and remove ports that aren't being used
    if ($mode -eq "Harden") {
        New-NetFirewallRule -DisplayName "allow all ports that are currently listening" -Direction Inbound -LocalPort $a.LocalPort -Action Allow
        New-NetFirewallRule -DisplayName "block all ports not in current use" -Direction Inbound -LocalPort Any -Action Block

        Write-Host "[+] finished hardening firewall"
        Write-Host "[+] remember to do a deeper dive later and patch any holes"
    }elif ($mode = "undo") {
        Set-NetFirewallRule -DisplayName "allow all ports that are currently listening" -Enabled $false
        Set-NetFirewallRule -DisplayName "block all ports not in current use" -Enabled $false

        Write-Host "[+] disabled the firewall rules created during hardening"
        Write-Host "[+] re-enable or edit it manually in Windows Advanced Firewall"
    }
}


# open/close the ports that are requested
function editFirewallRule {
	param (
		$portNum, $action, $direction, $protocol, $toolsPath, $status
	)

	Write-Host "[+] editing firewall rule..."
	
	Set-NetFirewallRule -DisplayName "$action $direction $portNum" -Direction $direction -LocalPort $portNum  -Protocol $protocol -Action $action -Enabled $status -ErrorVariable $EditRule -ErrorAction Continue
    
    if ($EditRule) {

        Write-Output "[-] Error in editing firewall rule" | Out-File -FilePath "$toolsPath\ErrLog.txt" -InputObject $errStr

    }

	Write-Host "[+] changed firewall rule for $port"
}

# change the password on admin account
function changeCreds {
	param (
		$curUsr
	)

	Write-Host "[+] You are about to change the username of the current admin"
	$newUsername = Read-Host -Prompt "What is the new name?"
	Rename-LocalUser -Name "$curUsr" -NewName "$newUsername" -ErrorVariable $FailUsername -ErrorAction Continue
	
    if ($FailUsername) {

        Write-Output "[-] Error in trying to change the username" | Out-File -FilePath "$toolsPath\ErrLog.txt"

        Write-Host "Run step 11 on the hardening checklist"

    }else{

        Write-Host "[+] New username set"
    
    }

	Write-Host "[+] You are now about to change your password"

	$Password = Read-Host "Enter the new password" -AsSecureString
	Get-LocalUser -Name "$curUsr" | Set-LocalUser -Password $Password -ErrorVariable $FailPasswd -ErrorAction Continue
	
    if ($FailPasswd) {
        
        Write-Output "[-] Error in changing the password" | Out-File -FilePath "$toolsPath\ErrLog.txt"

        Write-Host "Run step 9 on the hardening checklist"

    }else{

        Write-Host "[+] changed password for $curUsr"
        Write-Host "[+] MAKE SURE TO LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT"
    
    }

	
}

function  removeTools {
	param (
		$toolsPath
	)

	Write-Host "[+] Removing the tools directory..."

    # todo need to setup uninstallation of python and malwarebytes
    #

    # remove the directory with all of the installed tools in it
	Remove-Item -LiteralPath "$toolsPath" -Force -Recurse -ErrorVariable $RmTools -ErrorAction Continue
    
    if ($RmTools) {
        
        Write-Output "[-] Error in trying to remove the Tools directory" | Out-File -FilePath "$toolsPath\ErrLog.txt"
         
    }

	Write-Host "[+] Deleted the tools directory"
}

function discovery {
	param (
		$curUsr,	
        $mode
	)

    $discoverypath = "C:\Users\$curUsr\Desktop\Discovery"

    #note in this case removing the dump is = "undoing it"
    if ($mode -eq "undo") {
        
	    Remove-Item -LiteralPath "$discoverypath" -Force -Recurse -ErrorVariable $RmDiscovery -ErrorAction Continue

        if ($RmDiscovery) {

            Write-Output "[-] Error in trying to remove the discovery dump" | Out-File -FilePath "$toolsPath\ErrLog.txt"
        
        }

    } else { 

        Write-Host "[+] running discovery dump..."
        Write-Host "[+] YOU SHOULD STILL BE USING THE OTHER TOOLS THAT WERE INSTALLED"

        New-Item -Path "C:\Users\$curUsr\Desktop" -Name Discovery -type Directory

        # -- prints the results of data dumps into a nicely formatted table for saving --

        Write-Host "[+] gathering services..."
        Get-Service -Verbose | Format-Table -AutoSize > "$discoverypath\services.txt"

        Write-Host "[+] gathering processes..."
        Get-Process -Verbose | Format-Table -AutoSize > "$discoverypath\processes.txt"

        Write-Host "[+] gathering tcp connections..."
        Get-NetTCPConnection -Verbose | Format-Table -AutoSize > "$discoverypath\processes.txt"

        Write-Host "[+] gathering any scheduled tasks..."
        Get-ScheduledTask -Verbose | Format-Table -AutoSize > "$discoverypath\scheduledtasks.txt"

        Write-Host "[+] gathering any startup apps..."
        wmic startup list full | Format-Table -AutoSize > "$discoverypath\startupapps.txt"

        Write-Host "[+] data dumped to 'Discovery' folder on your desktop"
    
    }

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


function enableDefenderOn {
    param (
        $mode,
        $step
    )

    if (Get-MpComputerStatus | Select-Object "AntivirusEnabled" -eq $false) {
        
        $turnDefenderOn = Read-Host -Prompt "Do you want to turn on Windows Defender (y) or (undo)"
        # TODO need to test

        
        if ($turnDefenderOn -eq ("y" -or "Y")) {
        
            Write-Host "Enabling Windows Defender..."

            Set-MpPreference -DisableRealtimeMonitoring $false
            Set-MpPreference -DisableIOAVProtection $false
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
            start-service WinDefend
            start-service WdNisSvc	
        
            if (Get-MpComputerStatus | Select-Object "AntivirusEnabled" -eq $true) {
                Write-Host "Windows Defender Enabled"
            }else{
                Write-Output "[-] Error in trying to startup Windows Defender" | Out-File -FilePath "$toolsPath\ErrLog.txt"
            }
        }elif (($turnDefenderOn -eq "undo") -and ($step -eq 4)) {

            Write-Host "Stopping Windows Defender..."

            Stop-Service WdNisSvc
            Stop-Service WinDefend
            Set-MpPreference -DisableRealtimeMonitoring $true
            Set-MpPreference -DisableIOAVProtection $true
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
            Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force

            if (Get-MpComputerStatus | Select-Object "AntivirusEnabled" -eq $false) {
                Write-Host "Windows Defender Disabled"
            }else{
                Write-Output "[-] Error in trying to stop Windows Defender" | Out-File -FilePath "$toolsPath\ErrLog.txt"
            }
        }

    }
}


function Harden() {
    param (
       $curUsr,
       $toolsPath,
       $mode
    )
        
        
        
        # check if the Tools folder is already created
	    if (Test-Path -Path "C:\Users\$curUsr\Desktop\Tools" -eq True) {

		    Write-Host "[+] checking to see if the tools are installed..."
		    
            if (Get-ChildItem -Path "C:\Users\$curUsr\Desktop\Tools" -Recurse | Measure-Object -eq 0) {

			    installtools ($toolsPath)
		    
            }
	    }

		# install malwarebytes
		Write-Host "[+] downloading malwarebytes..."
		Invoke-WebRequest "https://downloads.malwarebytes.com/file/mb-windows" -OutFile "$toolsPath\mb.exe" -ErrorAction Continue -ErrorVariable $DOWNMB

        if ($DOWNMB) {
        
            Write-Output "[-] Error in downloading malwarebytes, make sure you have internet access" | Out-File -FilePath "$toolsPath\ErrLog.txt"

        }

		# Run Malwarebytes
		Write-Host "[+] click to install the software"
		Invoke-Expression "$toolsPath\mb.exe"

		Start-Sleep -Milliseconds 1000
		
		#Long but disables all guests
		Write-Host "[+] clearing out guest accounts..."

        # note this should not need undo because no quests accounts should be allowed
		$user = Get-LocalGroup -Name "guests" | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -Skip 4
		foreach ($x in $user) { 
			
            Write-Output "disabling guest: $x"
			Disable-LocalUser -Name $x
		
        }
		Write-Host "[+] guest accounts cleared"

		# remove all the non-required admin accounts
		Write-Host "[+] removing all admin accounts...execpt yours"

		# TODO this only works if the admin group is called "Administrators"
        # note this should not need undo because it only removes the account from the Administrators group
		$user = Get-LocalGroup -Name "Administrators" | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -Skip 4
		foreach ($x in $user) {
		   
        	if ($curUsr -notmatch $user) {
		
        		Write-Output "disabling admin: $x"
		   		Remove-LocalGroupMember -Group "Administrators" "$x"
			
            }
		}
		Write-Host "[+] pruned Administrator accounts"


		# harden the firewall for remote or lan comps
		$winFirewallOn = Read-Host -Prompt "Do you want to turn on the windows firewall (y)"
		if ($winFirewallOn -eq ("y" -or "Y")) {
			
			winFire ($mode, $step)
		
        }


		$hardenExch = Read-Host -Prompt "Do you want to Harden Exchange (y)"
		if ($hardenExch -eq ("y" -or "Y")) {
            
            # Todo need to fix to find services that are only on Exchange Server
            if (Get-Service -DisplayName "Exchange") {

                ExchangeHard ($mode)
            
            }
		}


		# turn on Windows Defender
		# Windows 8.1 (server 2016+) should already be on
        enableDefenderOn($mode, $step)
		
		# start all the installed tools to find any possible weird things running
		toolstart($toolsPath)


		# change the execution policy for powershell for admins only (works for the current machine)
		# rest of restrictions happen in group policy and active directory
		Write-Host "[+] changing powershell policy..."
		
        Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -ErrorAction Continue -ErrorVariable $SETPOW 

        if ($SETPOW) {
            
            Write-Output "[-] Error in changing the execution policy to restricted" | Out-File -FilePath "$toolsPath\ErrLog.txt"
        
        }else{
    	
    	    Write-Host "[+] Changed the Powershell policy to Restricted"
        
        }
	   

    	# disable WinRM
		$disableWinRm = Read-Host -Prompt "disable WinRm? (y)"
	
    	if ($disableWinRm -eq ("y" -or "Y")) {
	   
    		Disable-PSRemoting -Force -ErrorAction Continue -ErrorVariable $PSRREMOTE 
            
            if ($PSRREMOTE) {

                Write-Output "[-] Error in disabling WinRm" | Out-File -FilePath "$toolsPath\ErrLog.txt"

            }else{

			    Write-Host "[+] disabled WinRm"
	        
            }
    	}


		# change the password/username of the current admin
		changeCreds($curUsr)
		

		# setup UAC
		setUAC


		# disable anonymous logins
		Write-Host "[+] disabling anonymous users..."

		Set-CsAccessEdgeConfiguration -AllowAnonymousUsers $False

		Write-Host "[+] disabled anonymous users"


		# TODO enable/install wdac/applocker/or DeepBlue CLi?



		# disable netbios ??????(might be too good)
		$adapters=(Get-WmiObject win32_networkadapterconfiguration )
		
        foreach ($adapter in $adapters){
		   
        	Write-Host $adapter
			$adapter.settcpipnetbios(0)
		
        }

		
        # update windows if it is in the scope of the rules
		$updates = Read-Host -Prompt "Do you want to update (y)"
		
        if ($updates -eq ("y" -or "Y")) {
			winUP
		}

}

function Undo {
    param (
        $curUsr,
        $toolsPath
    )

        [String]$mode = "undo"

        Write-Host "
        - (1) To uninstall all tool installed  use removeTools in the control menu
        - (2) winfire
        - (3) Exchange(TODO)
        - (4) Windows Defender
        - (5) Psh Policy
        - (6) Enable WinRM(?????)
        - (7) re-enable netbios(todo)
        "

        [Int]$step = Read-Host -Prompt "What step do you want to undo"

        switch ($step) {

        "2" { winfire($mode) }

        "3" { 

            # Todo need to fix to find services that are only on Exchange Server
            if (Get-Service -DisplayName "Exchange") {

                ExchangeHard ($mode) 
                
            }else {

                Write-Host "this machine is not runnning an Exchange instance"
                
            }
        }

        "4" {

            enableDefenderOn($mode)

        }

        "5" {

            Write-Host "[+] changing powershell policy..."
		
            Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope LocalMachine -ErrorAction Continue -ErrorVariable $SETPOW -Confirm

            if ($SETPOW) {
                
                Write-Output "[-] Error in changing the execution policy to Undefined" | Out-File -FilePath "$toolsPath\ErrLog.txt"
            
            }else{
            
                Write-Host "[+] Changed the Powershell policy to Undefined"
            
            }
        }

        "6" {

            # note need to confirm that we want this first 
            break;

            # enable WinRM
            $enableWinRm = Read-Host -Prompt "enable WinRm? (y) or (n), WARNING his will make your machine vulnerable to RCE"
        
            if ($enableWinRm -eq ("y" -or "Y")) {
           
                Enable-PSRemoting -Force -ErrorAction Continue -ErrorVariable $PSRREMOTE -Confirm
                
                if ($PSRREMOTE) {

                    Write-Output "[-] Error in enabling WinRm" | Out-File -FilePath "$toolsPath\ErrLog.txt"

                }else{

                    Write-Host "[+] Enabled WinRm"
                
                }
            }

        }

        default {continue}
    }

}


function main {
    param (

    )

	$curUsr = [Environment]::UserName
	$toolsPath = "C:\Users\$curUsr\Desktop\Tools"

	Write-Host "[+] choose a mode to run the script"
	Start-Sleep -Milliseconds 500
	Write-Host "[+] harden will start the hardening process on the current machine"
	Start-Sleep -Milliseconds 500
	Write-Host "[+] control will allow the user to make changes to windows without having to navigate around"
	Start-Sleep -Milliseconds 500
    Write-Host "[+] if any errors are made, a message will be printed to the console and stored into \Desktop\Tools\ErrLog.txt"

	$usermode = Read-Host -Prompt "(Harden) or (Control)"
	if ($usermode -eq ("harden" -or "Harden")) {
        $mode = "Harden";
        Harden($curUsr, $toolsPath, $mode)
    } else {

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
            - Undo(9)
            - quit
            "
            
            $choice = Read-Host 
            switch ($choice) {

                "1" {
                    [Int]$portNum = Read-Host -Prompt "which port (num)"
                    $action = Read-Host -Prompt "(allow) or (block)"
                    $direction = Read-Host -Prompt "which direction (in) or (out)"
                    [Bool]$status = Read-Host -Prompt "to create the rule use True
                    to undo use false"
                    
                    editFirewallRule ($portNum, $action, $direction, $toolsPath, $status)
                }

                "2" {

                    # TODO populate this with stuff after group policy is added
                }

                "3" {changeCreds($curUsr)}

                
                "4" {installtools($toolsPath, $curUsr)}

                
                "5" {toolstart($toolsPath)}

                
                "6" {removeTools($toolsPath)}

                
                "7" {

                    Write-Host "Do you want to perform a dump (y) or (n), 
                    WARNING (n) will remove the dump"

                    $mode = Read-Host -Prompt "What mode?"
                    
                    discovery($curUsr, $mode)
                }

                
                "8" {DefenderScan}


                "9" {
                    
                    # TODO write the undo steps once they are created
                    
                    Write-Host "Remember that functions already exist that can undo"

                    Undo

                }
                
                "quit" {break}

                
                default {continue}
            } 
        }
    }
}
