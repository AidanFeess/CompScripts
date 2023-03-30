Import-Module Defender
Import-Module NetSecurity
Import-Module NetTCPIP
Import-Module GroupPolicy
Import-Module ScheduledTasks

Enum Tools{  
    TCPView
    Procmon
    Autoruns
}

# Enum PythonTools {
#     python3.exe;
#     peas2json.py;
#     json2pdf.py;
# }


# install the list of tools
function InstallTools {
	param (
	)

	Write-Host "[+] installing tools..."

	# create a folder in the user directory
	New-Item -Path "$env:USERPROFILE\Desktop\" -Name Tools -type Directory
	
	# -- Download the specific tools instead of downloading the entire suite --
    
    $urls = @(
        TCPView = "https://download.sysinternals.com/files/TCPView.zip",
        Procmon = "https://download.sysinternals.com/files/ProcessMonitor.zip", 
        Autoruns = "https://download.sysinternals.com/files/Autoruns.zip"
    )

    $zipPath = @(
        TCPView = "$env:USERPROFILE\Desktop\Tools\TCPView.zip", 
        Procmon = "$env:USERPROFILE\Desktop\Tools\ProcessMonitor.zip", 
        Autoruns = "$env:USERPROFILE\Desktop\Tools\Autoruns.zip"
    )

    foreach ($tool in $Tools) {
        
        try {
            Invoke-WebRequest $urls[$tool] -OutFile "$env:USERPROFILE\Desktop\Tools\$tool.zip" -ErrorAction Continue -ErrorVariable $DownTool
        }catch {

            Write-Output "[-] Error in downloading Tool, make sure you have internet access" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"
            throw $_
        }

        try {
            Expand-Archive -LiteralPath "$zipPath[$tool]" -DestinationPath "$env:USERPROFILE\Desktop\Tools\$tool" -ErrorAction Continue -ErrorVariable $UNZIP
        } catch {
            
            Write-Output "[-] Error in unziping TCPView, make sure it was downloaded" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"
            throw $_
        } 
    }   
	
	Write-Host "[+] finished installing tools"
}

# once tools are run winpeas and parse the output and save it
function ToolStart {
	param (
        $toolsPath
	)

	Write-Host "[+] opening tools..."

    $paths = @(
        "$env:USERPROFILE\Desktop\Tools\Procmon\Procmon64.exe"
        "$env:USERPROFILE\Desktop\Tools\Autoruns\Autoruns64.exe"
        "$env:USERPROFILE\Desktop\Tools\TCPView\tcpview64.exe"
    )

	# open autoruns, procmon, TCPView
    foreach ($path in $paths) {
        try {
        Invoke-Expression -Command $path
	    Start-Sleep -Milliseconds 500
        } catch {
            throw $_
        }
    }

	$runWinpeas = Read-Host -Prompt "Would you like to run Winpeas"
	if ($runWinpeas -eq "y") {
		
        # run winpeas in the memory
		$url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
		$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("log") > "$toolsPath\winpeas.txt"

		# execute the parsers to convert to pdf
		$installPython = Read-Host -Prompt "Would you like to install Python?"
		if ($installPython -eq "y") {
		
        	Write-Host "[+] WARNING this can leave your system vulnerable" 
			Write-Host "[+] Consider removing these items after use if they aren't going to be controlled" 

            $pythonList = @(
                "https://www.python.org/ftp/python/3.11.2/python-3.11.2-amd64.exe", 
                "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/peas2json.py",
                "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/json2pdf.py"  
            )

            foreach ($tools in PythonTools) {

			    Invoke-Webrequest "$pythonList[$tools]" -Outfile "$env:USERPROFILE\Desktop\Tools\$tools" -ErrorAction Continue -ErrorVariable $DownPYTHON
                if ($DownPYTHON) {
                    
                    Write-Output "[-] Error in downloading python3 installer, make sure you have internet access" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"

                }
                
                if ($tools -eq python3.exe) {

                    # still need to manually install
                    Write-Host "[+] install python and make sure to add to your path"

                    Invoke-Expression -Command "$env:USERPROFILE\Desktop\Tools\python3.exe" 
                }
        
            }

            # should refresh the path so that the parsers can be used in the same session
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

		}
		
        # run the parsers so that it can be viewed easily
        python3.exe '$env:USERPROFILE\Desktop\Tools\peas2json.py $env:USERPROFILE\Desktop\Tools\log.out $env:USERPROFILE\Desktop\Tools\peas.json'

		python3.exe '$env:USERPROFILE\Desktop\Tools\json2pdf.py $env:USERPROFILE\Desktop\Tools\peas.json $env:USERPROFILE\Desktop\Tools\peas.pdf'
    
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
function WinUP {
	param (
		
	)

	# TODO check and see if this actually works/if we want it
	Write-Host "[+] Setting up Windows Update..."
	
	# we will have to install this / need to make sure we can
	Install-Module -Name PSWindowsUpdate -ErrorAction Continue -ErrorVariable $INSPSudpate

    if ($INSPSudpate) {
        
        Write-Output "[-] Error in installing PSUpdate" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"

    }else{

	    Import-Module PSWindowsUpdate
        
        Write-Host "[+] This will work in the background and will need to Reboot when finished"
	
        # note this only installs the updates
        # it will help us control when we bring servers down for updates
	    Get-WindowsUpdate -AcceptAll -Install

    }
}


# winfire only blocks certain ports at the moment
function WinFire {
	param (
       $mode 
	)

	Write-Host "[+] hardening firewall with $mode..."

	# turn defaults on and set logging
	Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow -NotifyOnListen True -LogAllowed True -LogIgnored True -LogBlocked True -LogMaxSize 4096 -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

	# get the current listening conections ports
	$a = Get-NetTCPConnection -State Listen | Select-Object -Property LocalPort -ErrorVariable $GetListen -ErrorAction Continue

    # create the rule to block all unused ports and activate it later
    New-NetFirewallRule -DisplayName "Block all ports" -Direction Inbound -LocalPort Any -Action Block -Enabled False
    
    if ($GetListen) {

        Write-Output "[-] Error in geting the active list of listening ports" | Out-File -FilePath "toolsPath\ErrOut.txt"
                 
    }

	Write-Host "[+] You are possibly going to be asked if you want to block certain ports"
	Write-Host "[+] your options are ( y ) or ( n )"

	# parse the list to remove ports that shouldn't 
	for ($x = 0; $x -lt ($a.Length - 1); $x++) {
		
        $portNum = $a[$x].LocalPort

        # uncomment for debug
        # Write-Host "$portNum"

		if ($x -eq 22) {

			$response = Read-Host -Prompt "Do you want to block ssh?"

			if ($response -eq ("y")) {
			
                New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Inbound -LocalPort $portNum -Action Block
                New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Outbound -LocalPort $portNum -Action Block

				Write-Host "[+] ssh(22) blocked"

			}else{

				Write-Host "[+] ssh(22) will remain open"

			}
		}

		if ($x -eq 5900) {
	
    		$response = Read-Host -Prompt "Do you want to block vnc?"

			if ($response -eq "y") {
	
                New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Inbound -LocalPort $portNum -Action Block
                New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Outbound -LocalPort $portNum -Action Block

    			Write-Host "[+] vnc(5900) blocked"

			}else{
	
    			Write-Host "[+] vnc(5900) will remain open"
	
    		}
		}

		if ($x -eq 3389) {
	
    		$response = Read-Host -Prompt "Do you want to block rdp?"

			if ($response -eq "y") {
	
                New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Inbound -LocalPort $portNum -Action Block
                New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Outbound -LocalPort $portNum -Action Block

    			Write-Host "[+] rdp(3389) blocked"
	
    		}else{
	
    			Write-Host "[+] rdp(3389) will remain open"
	
    		}
		}

        # allow the port if it was previously listening
        New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Inbound -LocalPort $portNum -Action Allow
	}

    # activate the rule from earlier
    # Enable-NetFirewallRule -DisplayName "Block all ports"

    Write-Host "[+] finished hardening firewall"
    Write-Host "[+] remember to do a deeper dive later and patch any holes"

}


# open/close the ports that are requested
function EditFirewallRule {
	param (
		$portNum, $action, $direction, $protocol, $status
	)

	Write-Host "[+] editing firewall rule..."
	
	Set-NetFirewallRule -DisplayName "$action $portNum" -Direction $direction -LocalPort $portNum  -Protocol $protocol -Action $action -Enabled $status -ErrorVariable $EditRule -ErrorAction Continue
    
    if ($EditRule) {

        Write-Output "[-] Error in editing firewall rule" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt" -InputObject $errStr

    }

	Write-Host "[+] changed firewall rule for $port"
}

# change the password on admin account
function ChangeCreds {
	param (
        $mode
	)

    if ($mode -eq "control") {
        # password has to be changed first because it needs the username to change it
        Write-Host "[+] You are now about to change your password"

        $Password = Read-Host "Enter the new password" -AsSecureString
        Get-LocalUser -Name "$env:Username" | Set-LocalUser -Password $Password -ErrorVariable $FailPasswd -ErrorAction Continue
        
        if ($FailPasswd) {
            
            Write-Output "[-] Error in changing the password" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"

            Write-Host "Run step 9 on the hardening checklist"

        }else{

            Write-Host "[+] changed password for ($env::Username)"
            Write-Host "[+] MAKE SURE TO LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT"
        
        }
    }

    # password has to be changed first because it needs the username to change it
    Write-Host "[+] You are now about to change your password"

    $Password = Read-Host "Enter the new password" -AsSecureString
    Get-LocalUser -Name "$env:Username" | Set-LocalUser -Password $Password -ErrorVariable $FailPasswd -ErrorAction Continue
    
    if ($FailPasswd) {
        
        Write-Output "[-] Error in changing the password" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"

        Write-Host "Run step 9 on the hardening checklist"

    }else{

        Write-Host "[+] changed password for ($env::Username)"
        Write-Host "[+] MAKE SURE TO LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT"
    
    }

	Write-Host "[+] You are about to change the username of the current admin"
	$newUsername = Read-Host -Prompt "What is the new name?"
	Rename-LocalUser -Name "$env:Username" -NewName "$newUsername" -ErrorVariable $FailUsername -ErrorAction Continue

	
    if ($FailUsername) {

        Write-Output "[-] Error in trying to change the username" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"

        Write-Host "Run step 11 on the hardening checklist"

    }else{

        Write-Host "[+] New username set"
    
    }
}

function  RemoveTools {
	param (
	)

	Write-Host "[+] Removing the tools directory..."

    $remInstTools = Read-Host -Prompt "Do you want to also remove python3 and malwarebytes (y) or (n)"    
    if ($remInstTools -eq ("y")) {

        # uninstall python3.11
        Write-Host "[+] Python will open and you need to click to uninstall it"
        Start-Sleep -Milliseconds 2000

        Invoke-Expression -Command "$env:USERPROFILE\Desktop\Tools\python3.11.exe" 
        Start-Sleep -Milliseconds 2000

        # uninstall malwarebytes
        Write-Host "[+] Malwarebytes will be uninstalled next, follow the the prompts"
        Start-Sleep -Milliseconds 2000
        Invoke-Expression -Command "C:\'Program Files'\Malwarebytes\Anti-Malware\mb4uns.exe"

    }else {
        
        # move over the python3.11
        Write-Host "[+] Moving python3.11..."
        Move-Item -Path "$env:USERPROFILE\Desktop\Tools\python3.11.exe" -Destination "$env:USERPROFILE\Desktop\" -ErrorVariable $MOVPYTH -ErrorAction Continue
        Write-Host "[+] Python moved"

        # move over the malwarebytes just in case
        Write-Host "[+] Moving malwarebytes..."
        Move-Item -Path "$env:USERPROFILE\Desktop\Tools\mb.exe" -Destination "$env:USERPROFILE\Desktop\"
        Write-Host "[+] Malwarebytes moved" 

    }

    # remove the directory with all of the installed tools in it
	Remove-Item -LiteralPath "$env:USERPROFILE\Desktop\Tools" -Force -Recurse -ErrorVariable $RmTools -ErrorAction Continue
    
    if ($RmTools) {
        
        Write-Output "[-] Error in trying to remove the Tools directory" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"
         
    }

	Write-Host "[+] Deleted the tools directory"
}

function Discovery {
	param (
        $mode
	)
    l

    $discoverypath = "$env:USERPROFILE\Desktop\Discovery"

    # note in this case removing the dump is = "undoing it"
    if ($mode -eq "undo") {
        
	    Remove-Item -LiteralPath "$discoverypath" -Force -Recurse -ErrorVariable $RmDiscovery -ErrorAction Continue

        if ($RmDiscovery) {

            Write-Output "[-] Error in trying to remove the discovery dump" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"
        
        }
    }

    if ($mode -eq "y") { 

        Write-Host "[+] running discovery dump..."
        Write-Host "[+] YOU SHOULD STILL BE USING THE OTHER TOOLS THAT WERE INSTALLED"
        if (Test-Path -Path "$env:USERPROFILE\Desktop\Discovery") {
	    	continue;
    	}else{
	
            New-Item -Path "$env:USERPROFILE\Desktop" -Name Discovery -type Directory
        }

        # -- prints the results of data dumps into a nicely formatted table for saving --

        Write-Host "[+] gathering services..."
        Get-Service -Verbose | Format-Table -AutoSize > "$discoverypath\services.txt"

        # gather the running process on a system with the username tagged to it
        Write-Host "[+] gather running processes..."
        $owners = @{}
        Get-WmiObject win32_process | Foreach-Object {$owners[$_.handle] = $_.getowner().user} -ErrorAction SilentlyContinue
        Get-Process | Select-Object processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}} -ErrorAction SilentlyContinue

        Write-Host "[+] gathering tcp connections..."
        Get-NetTCPConnection -Verbose | Format-Table -AutoSize > "$discoverypath\processes.txt"

        Write-Host "[+] gathering any scheduled tasks..."
        Get-ScheduledTask -Verbose | Format-Table -AutoSize > "$discoverypath\scheduledtasks.txt"

        Write-Host "[+] gathering any startup apps..."
        Get-StartApps | Format-Table -AutoSize > "$discoverypath\startupapps.txt"

        Write-Host "[+] data dumped to 'Discovery' folder on your desktop"
    
        Write-Host "[+] You should still be using other tools because this won't catch everything"
    }
}

function SetUAC {
	param (
		
	)

	Write-Host "[+] setting UAC values..."

	# set the values
	$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
	
    Set-ItemProperty -Path $path -Name 'ConsentPromptBehaviorAdmin' -Value 2 -PropertyType DWORD -Force | Out-Null
	Set-ItemProperty -Path $path -Name 'ConsentPromptBehaviorUser' -Value 3 -PropertyType DWORD -Force | Out-Null
	Set-ItemProperty -Path $path -Name 'EnableInstallerDetection' -Value 1 -PropertyType DWORD -Force | Out-Null
	Set-ItemProperty -Path $path -Name 'EnableLUA' -Value 1 -PropertyType DWORD -Force | Out-Null
	Set-ItemProperty -Path $path -Name 'EnableVirtualization' -Value 1 -PropertyType DWORD -Force | Out-Null
	Set-ItemProperty -Path $path -Name 'PromptOnSecureDesktop' -Value 1 -PropertyType DWORD -Force | Out-Null
	Set-ItemProperty -Path $path -Name 'ValidateAdminCodeSignatures' -Value 0 -PropertyType DWORD -Force | Out-Null
	Set-ItemProperty -Path $path -Name 'FilterAdministratorToken' -Value 0 -PropertyType DWORD -Force | Out-Null

	Write-Host "[+] values set"
}

# runs a basic windows defender scan
function DefenderScan {
	param (
		
	)

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
		Start-MpScan -ScanType FullScan -ScanPath C: -AsJob -OutVariable scanOut
	
    }else {
		Write-Host "[+] error in checking windows defender"
	}
}


function EnableDefenderOn {
    param (
        $mode,
        $step
    )

    # gather the status of WD
    $wdav = Get-MpComputerStatus
    
    if ($wdav.AntivirusEnabled -eq $false) {
        
        $turnDefenderOn = Read-Host -Prompt "Do you want to turn on Windows Defender (y) or (undo)"
        # TODO need to test
    
        if ($turnDefenderOn -eq ("y")) {
        
            Write-Host "Enabling Windows Defender..."

            Set-MpPreference -DisableRealtimeMonitoring $false
            Set-MpPreference -DisableIOAVProtection $false
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
          
            Start-Service -DisplayName "Windows Defender Antivirus Service"
            Start-Service -DisplayName "Windows Defender Antivirus Network Inspection Service"	
        
        
            $wdav = Get-MpComputerStatus
            if ($wdav.AntivirusEnabled -eq $true) {
                Write-Host "Windows Defender Enabled"
            }else{
                Write-Output "[-] Error in trying to startup Windows Defender" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"
            }
        }elseif (($turnDefenderOn -eq "undo") -and ($step -eq 4)) {

            Write-Host "Stopping Windows Defender..."

            Stop-Service -DisplayName "Windows Defender Antivirus Service"
            Stop-Service -DisplayName "Windows Defender Antivirus Network Inspection Service"	
            
            Set-MpPreference -DisableRealtimeMonitoring $true
            Set-MpPreference -DisableIOAVProtection $true

            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
            Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force

            $wdav = Get-MpComputerStatus
            if ($wdav.AntivirusEnabled -eq $false) {
                Write-Host "Windows Defender Disabled"
            }else{
                Write-Output "[-] Error in trying to stop Windows Defender" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"
            }
        }
    } else {
        Write-Host "[+] Windows Defender is already active"
    }
}


function Harden {
    param (
       $mode
    )
        
        # check if the Tools folder is already created
		Write-Host "[+] checking to see if the tools are installed..."
	    if (Test-Path -Path "$env:USERPROFILE\Desktop\Tools") {

        } else {

            InstallTools

	    }

		# install malwarebytes
		Write-Host "[+] downloading malwarebytes..."
		Invoke-WebRequest "https://downloads.malwarebytes.com/file/mb-windows" -OutFile "$env:USERPROFILE\Desktop\Tools\mb.exe" -ErrorAction Continue -ErrorVariable $DOWNMB
        if ($DOWNMB) {
        
            Write-Output "[-] Error in downloading malwarebytes, make sure you have internet access" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"

        }

		# Run Malwarebytes
		Write-Host "[+] click to install the software"
		Invoke-Expression "$env:USERPROFILE\Desktop\Tools\mb.exe"

		Start-Sleep -Milliseconds 1000
		
		#Long but disables all guests
		Write-Host "[+] clearing out guest accounts..."

        # note this should not need undo because no guests accounts should be allowed
		$user = Get-LocalGroupMember -Name "Guests" 
		foreach ($j in $user) { 
			
            Write-Output "disabling guest: $j"
			Disable-LocalUser -Name $j
		
        }
		Write-Host "[+] guest accounts cleared"

		# remove all the non-required admin accounts
		Write-Host "[+] removing all admin accounts...execpt yours"

        # read the groups and select the correct admin group
        $a = Get-LocalGroup | Select-Object -Property "Name" | Select-String -Pattern "admin"
        Write-Host "$a"
        [Int]$c = Read-Host -Prompt "Which one is the real admin group"
        foreach ($i in $a) {
            if ($i -eq $a[$c]) {
                [String]$adminGroup = $i
            }
        }

        # grabs the group name from the object
        $adminGroup -match '(?<==)[\w]+'

        # note this should not need undo because it only removes the account from the Administrators group
		$user = Get-LocalGroupMember -Name $Matches[0]
		foreach ($x in $user) {
            $st =[string]$x.Name
            if ( -Not $st.Contains($env:USERNAME)) {
            
                Write-Output "disabling admin: $st"
                Remove-LocalGroupMember -Group $Matches[0] $st
            
            }
        }
		Write-Host "[+] pruned Administrator accounts"


		# harden the firewall for remote or lan comps
		$winFirewallOn = Read-Host -Prompt "Do you want to turn on the windows firewall (y)"
		if ($winFirewallOn -eq ("y")) {
			
			WinFire ($mode, $step)
		
        }


		$hardenExch = Read-Host -Prompt "Do you want to Harden Exchange (y)"
		if ($hardenExch -eq ("y")) {
            
            # looks for services that have "Exchange"
            # seems to be the naming convention
            if (Get-Service | Select-Object -Property "Name" | Select-String -Pattern "Exchange") {

                ExchangeHard ($mode)
            
            }
		}


		# turn on Windows Defender
		# Windows 8.1 (server 2016+) should already be on
        EnableDefenderOn($mode, $step)
		

		# start all the installed tools to find any possible weird things running
		ToolStart ($toolsPath)


		# change the execution policy for powershell for admins only (works for the current machine)
		# rest of restrictions happen in group policy and active directory
		Write-Host "[+] changing powershell policy..."
		
        Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -ErrorAction Continue -ErrorVariable $SETPOW 

        if ($SETPOW) {
            
            Write-Output "[-] Error in changing the execution policy to restricted" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"
        
        }else{
    	
    	    Write-Host "[+] Changed the Powershell policy to Restricted"
        
        }
	   

    	# disable WinRM
		$disableWinRm = Read-Host -Prompt "disable WinRm? (y)"
    	if ($disableWinRm -eq ("y")) {
	   
    		Disable-PSRemoting -Force -ErrorAction Continue -ErrorVariable $PSRREMOTE 
            
            if ($PSRREMOTE) {

                Write-Output "[-] Error in disabling WinRm" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"

            }else{

			    Write-Host "[+] disabled WinRm"
	        
            }
    	}


		# change the password/username of the current admin
		ChangeCreds($mode)
		

		# setup UAC
		SetUAC


		# disable anonymous logins
		Write-Host "[+] disabling anonymous users..."
        $a = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymous"
        if ($a.restrictanonymous -eq 1) {
        }else{
            try {
            Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymous" -Value 1 -Force
            } catch {
                throw $_
            }
        }
		Write-Host "[+] disabled anonymous users"

        
        # disable anonymous sam
        Write-Host "[+] disabling anonymous sam touching..."
        $a = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymoussam"
        if ($a.restrictanonymoussam -eq 1) {
        } else {
            try {
            Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymoussam" -Value 1 -Force
            } catch {
                throw $_
            }
        }
        Write-Host "[+] anonymous sam touching disabled"
        
        # disable editing of the registry through tools
        # warning this will stop a user from editing the registry all together
        Write-Host "[+] disabling redgedit..."
        $a = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name "disableregistrytools"
        if ($a.disableregistrytools -eq 2) {
        } else {
            try {
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name "disableregistrytools" -Value 2 -Force
            } catch {
                throw $_
            }
        }
        Write-Host "[+] registry editing via tools disabled"

		# TODO enable/install wdac/applocker/or DeepBlue CLi?


		# disable netbios ??????(might be too good)
		$adapters=(Get-WmiObject win32_networkadapterconfiguration )
        foreach ($adapter in $adapters){
		   
        	Write-Host $adapter
			$adapter.settcpipnetbios(0)
		
        }

		
        # update windows if it is in the scope of the rules
		$updates = Read-Host -Prompt "Do you want to update (y)"
		
        if ($updates -eq ("y")) {
			WinUP
		}
}

function Undo {
    param (
    )

        [String]$mode = "undo"

        Write-Host "
        - (#) To uninstall all tool installed use RemoveTools in the control menu
        - (Exchange) Exchange(TODO)
        - (Defender) Windows Defender
        - (Psh) Psh Policy
        - (WinRm) Enable WinRM(why?????)
        - (netbios) re-enable netbios(TODO)
        "

        [Int]$step = Read-Host -Prompt "What step do you want to undo"

        switch ($step) {

        "Exchange" { 
            
            continue;

            # looks for services that have "Exchange"
            # seems to be the naming convention
            if (Get-Service | Select-Object -Property "Name" | Select-String -Pattern "Exchange") {

                ExchangeHard ($mode) 
                
            }else {

                Write-Host "This machine is not runnning Exchange"
                
            }
        }

        "Defender" {

            EnableDefenderOn($mode)

        }

        "Psh" {

            Write-Host "[+] changing powershell policy..."
		
            Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope LocalMachine -ErrorAction Continue -ErrorVariable $SETPOW -Confirm

            if ($SETPOW) {
                
                Write-Output "[-] Error in changing the execution policy to Undefined" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"
            
            }else{
            
                Write-Host "[+] Changed the Powershell policy to Undefined"
            
            }
        }

        "WinRM" {

            # enable WinRM
            $enableWinRm = Read-Host -Prompt "enable WinRm? (y) or (n), WARNING his will make your machine vulnerable to RCE"
        
            if ($enableWinRm -eq ("y")) {
           
                Enable-PSRemoting -Force -ErrorAction Continue -ErrorVariable $PSRREMOTE -Confirm
                
                if ($PSRREMOTE) {

                    Write-Output "[-] Error in enabling WinRm" | Out-File -FilePath "$env:USERPROFILE\Desktop\ErrLog.txt"

                }else{

                    Write-Host "[+] Enabled WinRm"
                
                }
            }

        }

        "netbios" { continue }

        default { continue }
    }

}


function Main {
    param (

    )

    # should stop redteam from just running the script
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    $p = New-Object System.Security.Principal.WindowsPrincipal($id)

    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { 
        Write-Host "Welcome to WindowsHard!"
        Write-Host "Goodluck Today!!!"
    
    }else{ 
        Write-Host "No Red Team Allowed!!!"
        Write-Host "Hope You Have a Good Day!!!"
    }


	Write-Host "[+] choose a mode to run the script"
	Start-Sleep -Milliseconds 500
	Write-Host "[+] harden will start the hardening process on the current machine"
	Start-Sleep -Milliseconds 500
	Write-Host "[+] control will allow the user to make changes to windows without having to navigate around"
	Start-Sleep -Milliseconds 500
    Write-Host "[+] If any errors are made, a message will be printed to the console and stored into \Desktop\Tools\ErrLog.txt"

	$usermode = Read-Host -Prompt "Harden(h) or Control(c)"
	if ($usermode -eq ("h")) {
		$mode = "harden";
		Harden($mode)
    } 

    if ($usermode -eq ("c"))  {

        while($true) {
            Write-Host "[+] what would you like to do
            - edit a firewall rule(1)
            - change a group policy(2) (TODO)
            - Change Password(3)
            - Install Tools(4)
            - Start Tools(5)
            - Remove Tools(6)
            - Discovery(7)
            - DefenderScan(8)
            - Undo(9)
            - OSK Spawn(10)
            - Start Wonk(Wonk)(???)
            - quit
            "
            
            $choice = Read-Host -Prompt "which mode do you want?"
            switch ($choice) {

                "1" {
                    [Int]$portNum = Read-Host -Prompt "which port (num)"
                    $action = Read-Host -Prompt "(allow) or (block)"
                    $direction = Read-Host -Prompt "which direction (in) or (out)"
                    [Bool]$status = Read-Host -Prompt "to create the rule use True
                    to undo use false"
                    
                    EditFirewallRule ($portNum, $action, $direction, $status)
                }

                "2" {

                    continue;

                    # TODO populate this with stuff after group policy is added
                }

                "3" {
                    $credsmode = "control"
                    ChangeCreds($credsmode)
                }

                "4" {InstallTools}

                "5" {ToolStart($toolsPath)}

                "6" {RemoveTools}
                
                "7" {

                    Write-Host "Do you want to perform a dump (y) or (undo), 
                    WARNING (undo) will remove the dump"

                    $discoveryMode = Read-Host -Prompt "What mode?"
                    
                    Discovery($discoveryMode)
                }
                
                "8" {DefenderScan}

                "9" {
                    
                    Write-Host "Remember that functions already exist that can undo like RemoveTools"

                    Undo

                }

                "10" {
                    
                    continue;
                    # TODO finish fun

                    $punUser = Read-Host -Prompt "What user do you want to punish?"
                    while ($true) {
                        Start-Process -FilePath "C:\Windows\System32\osk.exe" -WindowStyle Maximized -RunAs $punUser
                        Start-Sleep (5)
                    }
                     
                }

                "Wonk" {
                    
                    # Wonks a selected session that is seen as the operator as not being legit
                    $to_Wonk_or_Not_to_Wonk = Read-Host -Prompt "Are you sure you want to Wonk?"

                    if ($to_Wonk_or_Not_to_Wonk -eq ("y")) {
                        $wonkable = Get-NetTCPConnection -State Established -Verbose | Select-Object -Property LocalPort, RemotePort, OwningProcess

                        foreach ($x in $wonkable) {
                            if ($x.LocalPort -eq (22)) {
                                Write-Host "$x"
                            }

                            if ($x.LocalPort -eq (3389)) {
                                Write-Host "$x"
                            }

                            if ($x.LocalPort -eq (5900)) {
                                Write-Host "$x"
                            }
                        }

                        # note the TM is a joke
                        $bewonked = Read-Host -Prompt "What process do you want to (*PRE*)Wonk(TM)"

                        # Wonks the target
                        Stop-Process $bewonked

                        Write-Host "[+] Session has been (*PRE*)Wonked"
                    }
                }
                
                "quit" {return}

                default {continue}
            } 
        }
    }
}

Main
