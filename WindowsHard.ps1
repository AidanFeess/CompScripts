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

enum PythonTools {
    python3;
    peas2json;
    json2pdf;
}


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
                python3 = "https://www.python.org/ftp/python/3.11.2/python-3.11.2-amd64.exe", 
                peas2json = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/peas2json.py",
                json2pdf = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/json2pdf.py"  
            )

            foreach ($tools in PythonTools) {

                try {
			        Invoke-Webrequest "$pythonList[$tools]" -Outfile "$env:USERPROFILE\Desktop\Tools\$tools" -ErrorAction Continue -ErrorVariable $DownPYTHON
                } catch {
                    throw $_
                }
                    
                if ($tools -eq [Tools].python3) {

                    # still need to manually install
                    Write-Host "[+] install python and make sure to add to your path"
                    Invoke-Expression -Command "$env:USERPROFILE\Desktop\Tools\python3.exe" 
                }
            }
            
            # wait for python to finish installing
            while (Get-Procces -Name python3 -ErrorAction SilentlyContinue) {
               continue; 
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
    try {
        $a = Get-NetTCPConnection -State Listen | Select-Object -Property LocalPort -ErrorVariable $GetListen -ErrorAction Continue
    } catch {
        throw $_
    }

    # create the rule to block all unused ports and activate it later
    New-NetFirewallRule -DisplayName "Block all ports" -Direction Inbound -LocalPort Any -Action Block -Enabled False
    
	Write-Host "[+] You are possibly going to be asked if you want to block certain ports"
	Write-Host "[+] your options are ( y ) or ( n )"

	# parse the list to remove ports that shouldn't be open
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
        
        if ($x -eq 5985) {
	
    		$response = Read-Host -Prompt "Do you want to block WinRM http?"

			if ($response -eq "y") {
	
                New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Inbound -LocalPort $portNum -Action Block
                New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Outbound -LocalPort $portNum -Action Block

    			Write-Host "[+] WinRM(5985) blocked"
	
    		}else{
	
    			Write-Host "[+] WinRM(5985) will remain open"
	
    		}
		}

        if ($x -eq 5986) {
	
    		$response = Read-Host -Prompt "Do you want to block WinRM https?"

			if ($response -eq "y") {
	
                New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Inbound -LocalPort $portNum -Action Block
                New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Outbound -LocalPort $portNum -Action Block

    			Write-Host "[+] WinRM(5986) blocked"
	
    		}else{
	
    			Write-Host "[+] WinRM(5986) will remain open"
	
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

    # password has to be changed first because it needs the username to change it
    if ($mode -eq "control") {
        Write-Host "[+] You are now about to change your password"

        $Password = Read-Host "Enter the new password" -AsSecureString
        try {
        Get-LocalUser -Name "$env:Username" | Set-LocalUser -Password $Password -ErrorAction Continue
        } catch {
            throw $_
            Write-Host "[-] Error in changing password, checks docs to perform manual change"
        }
        Write-Host "[+] changed password for ($env::Username)"
        Write-Host "[+] MAKE SURE TO LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT"

        return;
    }

    # password has to be changed first because it needs the username to change it
    Write-Host "[+] You are now about to change your password"
    $Password = Read-Host "Enter the new password" -AsSecureString

    try {
    Get-LocalUser -Name "$env:Username" | Set-LocalUser -Password $Password -ErrorAction Continue
    } catch {
        throw $_
        Write-Host "[-] Error in changing password, checks docs to perform manual change"
    }
    Write-Host "[+] changed password for ($env::Username)"
    Write-Host "[+] MAKE SURE TO LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT"

	Write-Host "[+] You are about to change the username of the current admin"
	$newUsername = Read-Host -Prompt "What is the new name?"

    try {
        Rename-LocalUser -Name "$env:Username" -NewName "$newUsername" -ErrorAction Continue
    } catch {
        throw $_
    }
    Write-Host "[+] New username set"
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
        Move-Item -Path "$env:USERPROFILE\Desktop\Tools\python3.11.exe" -Destination "$env:USERPROFILE\Desktop\" -ErrorAction Continue
        Write-Host "[+] Python moved"

        # move over the malwarebytes just in case
        Write-Host "[+] Moving malwarebytes..."
        Move-Item -Path "$env:USERPROFILE\Desktop\Tools\mb.exe" -Destination "$env:USERPROFILE\Desktop\"
        Write-Host "[+] Malwarebytes moved" 

    }

    # remove the directory with all of the installed tools in it
    try {
        Remove-Item -LiteralPath "$env:USERPROFILE\Desktop\Tools" -Force -Recurse -ErrorAction Continue
    } catch {
        throw $_
    }
	Write-Host "[+] Deleted the tools directory"
}

function Discovery {
	param (
        $mode
	)

    $discoverypath = "$env:USERPROFILE\Desktop\Discovery"

    # note in this case removing the dump is = "undoing it"
    if ($mode -eq "undo") {
        
	    Remove-Item -LiteralPath "$discoverypath" -Force -Recurse -ErrorAction Continue

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

        Write-Host "[+] gathering list of users for diff..."
        Get-ADGroupMember | Format-Table -AutoSize > "$discoverypath\lsadusrs.txt"
        Get-LocalUser | Format-Table -AutoSize > "$discoverypath\lslusrs.txt"

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
    
        if ($turnDefenderOn -eq "y") {
        
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
                Write-Output "[-] Error in trying to startup Windows Defender"
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
                Write-Output "[-] Error in trying to stop Windows Defender"
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
            continue;
        } else {
            InstallTools
	    }

		# install malwarebytes
		Write-Host "[+] downloading malwarebytes..."
        try {
            Invoke-WebRequest "https://downloads.malwarebytes.com/file/mb-windows" -OutFile "$env:USERPROFILE\Desktop\Tools\mb.exe" -ErrorAction Continue
        } catch {
            throw $_
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
        try {
            Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -ErrorAction Continue
        } catch {
            throw $_
        }
	   

    	# disable WinRM
		$disableWinRm = Read-Host -Prompt "disable WinRm? (y)"
    	if ($disableWinRm -eq ("y")) {
            try {
    		    Disable-PSRemoting -Force -ErrorAction Continue
            } catch {
                throw $_
            }
    	}


		# change the password/username of the current admin user
		ChangeCreds($mode)
		

		# setup UAC
		SetUAC


		# disable anonymous logins
		Write-Host "[+] disabling anonymous users..."
        $a = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymous"
        if ($a.restrictanonymous -ne 1) {
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
        if ($a.restrictanonymoussam -ne 1) {
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
        if ($a.disableregistrytools -ne 2) {
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
            try {
                Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope LocalMachine -ErrorAction Continue -Confirm
            } catch {
                throw $_
                Write-Output "[-] Error in changing the execution policy to Undefined"
            }
            Write-Host "[+] Changed the Powershell policy to Undefined"
        }

        "WinRM" {

            # enable WinRM
            $enableWinRm = Read-Host -Prompt "enable WinRm? (y) or (n), WARNING his will make your machine vulnerable to RCE"
        
            if ($enableWinRm -eq ("y")) {
                try {
                    Enable-PSRemoting -Force -ErrorAction Continue -Confirm
                } catch {
                    throw $_
                    Write-Host "[-] Error in Enabling WinRM"
                }
                Write-Host "[+] Enabled WinRm"
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
            - (fw) edit a firewall rule
            - (gpo) Change a group policy (TODO)
            - (chpwd) Change Password
            - (instls) Install Tools
            - (strtls) Start Tools
            - (rmtls) Remove Tools
            - (disc) Discovery
            - (scan) DefenderScan
            - (Undo) Undo
            - (OSK) OSK Spawn
            - (Wonk) Start Wonk (???)
            - (blkpwd) Bulk Password Change (AD)
            - quit
            "
            
            $choice = Read-Host -Prompt "which mode do you want?"
            switch ($choice) {

                "fw" {
                    [Int]$portNum = Read-Host -Prompt "which port (num)"
                    $action = Read-Host -Prompt "(allow) or (block)"
                    $direction = Read-Host -Prompt "which direction (in) or (out)"
                    [Bool]$status = Read-Host -Prompt "to create the rule use True
                    to undo use false"
                    
                    EditFirewallRule ($portNum, $action, $direction, $status)
                }

                "gpo" {

                    continue;

                    # TODO populate this with stuff after group policy is added
                }

                "chpwd" {
                    $credsmode = "control"
                    ChangeCreds($credsmode)
                }

                "instls" {InstallTools}

                "strtls" {ToolStart($toolsPath)}

                "rmtls" {RemoveTools}
                
                "disc" {
                    Write-Host "Do you want to perform a dump (y) or (undo), 
                    WARNING (undo) will remove the dump"

                    $discoveryMode = Read-Host -Prompt "What mode?"
                    Discovery($discoveryMode)
                }
                
                "scan" {DefenderScan}

                "Undo" {
                    
                    Write-Host "Remember that functions already exist that can undo like RemoveTools"
                    Undo

                }

                "OSK" {
                    
                    continue;
                    # TODO finish fun

                    $punUser = Read-Host -Prompt "What user do you want to punish?"
                    while ($true) {
                        Start-Process -FilePath "C:\Windows\System32\osk.exe" -WindowStyle Maximized -RunAs $runUser
                        Start-Sleep (5)
                    }
                     
                }

                "Wonk" {
                    # download the version of dotnet required to run wonk
                    Invoke-WebRequest "https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-7.0.202-windows-x64-installer" -OutFile "$env:Userprofile\Desktop\Tools\dotnet7.exe"
                    Invoke-Expression "$env:USERPROFILE\Desktop\Tools\dotnet7.exe"

                    # TODO fix later creates the scheduled task for wonk persistance
                    $action = New-ScheduledTaskAction -Execute "powershell.exe if (Get-Procces -Name wonk.exe) {}else{.\wonk.exe}"
                    $trigger = New-ScheduledTaskTrigger -RepetitionInterval 3mins
                    $principal = New-ScheduledTaskPrincipal -RequiredPrivilege "Administrator"
                    $settings = New-ScheduledTaskSettingsSet -Hidden
                    $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings

                    Register-ScheduledTask "wakeup" -InputObject $task
                }

                "blkpwd" {
                    # from Doggle, who was the best at hardening AD

                    # build the character array for generating the passwords
                    $alph=@()
                    65..122|foreach{$alph += [char]$_}
                    $alph

                    # just to help make things more random
                    $alph = $alph | Get-Random -Shuffle

                    $users = Get-ADGroupMember -Identity 'Internals'
                    $pass = Read-Host -Prompt "password" -AsSecureString

                    # take the users and generate their passwords and set them
                    # save them to a csv file for transport
                    foreach($user in $users){
                        for($i = 0; $i -lt 21; $i++) { $pass = $alph | Get-Random }
                        ConvertTo-SecureString -AsPlainText $pass;
                        Set-ADAccountPassword -Identity $user -Reset -NewPassword $pass; 
                        $temp = $user.SamAccountName;
                        echo "$temp,$pass" >> C:\Users\$env:Username\Desktop\export.csv
                    }
                }
                
                "quit" {return}

                default {continue}
            } 
        }
    }
}

Main
