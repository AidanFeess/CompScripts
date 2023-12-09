Import-Module Defender
Import-Module NetSecurity
Import-Module NetTCPIP
Import-Module ScheduledTasks

enum Tools{  
    TCPView
    Procmon
    Autoruns
}

enum PyTools {
    python3
    peas2json
    json2pdf
}

function PrintErr {
    param (
        $ifError, $errString
    )

    if ($ifError) {
        Write-Host "[-] $errString" -ForegroundColor Red
    }
}

# install the list of tools
function InstallTools {
    param (
    )

    Write-Host "[+] Installing tools..."

    New-Item -Path "$env:USERPROFILE\Desktop\" -Name Tools -type Directory
    
    # -- Download the specific tools instead of downloading the entire suite --
    
    $urls = @{
        [Tools]::TCPView = "https://download.sysinternals.com/files/TCPView.zip"
        [Tools]::Procmon = "https://download.sysinternals.com/files/ProcessMonitor.zip"
        [Tools]::Autoruns = "https://download.sysinternals.com/files/Autoruns.zip"
    }

    $zipPath = @{
        [Tools]::TCPView  = "$env:USERPROFILE\Desktop\Tools\TCPView.zip"
        [Tools]::Procmon  = "$env:USERPROFILE\Desktop\Tools\ProcessMonitor.zip"
        [Tools]::Autoruns = "$env:USERPROFILE\Desktop\Tools\Autoruns.zip"
    }

    foreach ($tool in [Tools].GetEnumValues()) {
        Invoke-WebRequest -Uri $urls[$tool].ToString() -OutFile "$env:USERPROFILE\Desktop\Tools\$tool.zip"
        PrintErr(!$?,"Error in downloading Tool, make sure you have internet access")

        Expand-Archive -LiteralPath $zipPath[$tool].ToString() -DestinationPath "$env:USERPROFILE\Desktop\Tools\$tool"
        PrintErr(!$?, "Error in unziping Tool, make sure it was downloaded")
    }   
    
    Write-Host "[+] Finished installing tools" -ForegroundColor Green
}

# once tools are run winpeas and parse the output and save it
function ToolStart {
    param (
        $toolsPath
    )

    Write-Host "[+] Opening tools..." -ForegroundColor Yellow

    $paths = @(
        "$env:USERPROFILE\Desktop\Tools\Procmon\Procmon64.exe"
        "$env:USERPROFILE\Desktop\Tools\Autoruns\Autoruns64.exe"
        "$env:USERPROFILE\Desktop\Tools\TCPView\tcpview64.exe"
    )

    # open autoruns, procmon, TCPView
    foreach ($path in $paths) {
        Invoke-Expression -Command $path
        Start-Sleep -Milliseconds 500
        PrintErr(!$?, "Error in trying to start up tools")
    }

    Write-Host "[+] All tools opened" -ForegroundColor Green
}

# Downloads and runs winpeas on the system
function Winpeas {
    param (

    )
    
    $runWinpeas = $(Write-Host "[?] Would you like to run Winpeas: " -ForegroundColor Magenta -NoNewline; Read-Host)
    if ($runWinpeas -eq "y") {
        
        # download and run winpeas in memory
        $url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
        $wp = [System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("log") > "$env:USERPROFILE\Desktop\Tools\winpeas.txt"

        # execute the parsers to convert to pdf
        $installPython = $(Write-Host "[?] Would you like to install Python?: " -ForegroundColor Magenta -NoNewline; Read-Host)
        if ($installPython -eq "y") {
        
            Write-Host "[i] ***WARNING*** this can leave your system vulnerable" -ForegroundColor Yellow
            Write-Host "[i] Consider removing these items after use if they aren't going to be controlled" -ForegroundColor Yellow

            $pythonList = @{
                [PyTools]::python3   = "https://www.python.org/ftp/python/3.11.2/python-3.11.2-amd64.exe"
                [PyTools]::peas2json = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/peas2json.py"
                [PyTools]::json2pdf  = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/json2pdf.py"  
            }

            # should do this whole thing in parallel
            foreach ($tools in [PyTools].GetEnumValues()) {
                Invoke-Webrequest $pythonList[$tools].ToString() -Outfile "$env:USERPROFILE\Desktop\Tools\$tools"
                PrintErr(!$?, "Error while trying to download python and winpeas parsers")
                    
                if ($tools -eq [PyTools].python3) {
                    # still need to manually install
                    Write-Host "[i] Install python by following the installer" -ForegroundColor Yellow
                    Write-Host "[i] Make sure to check the box that adds it to your path" -ForegroundColor Yellow
                    Start-Sleep -Milliseconds 500
                    Invoke-Expression -Command "$env:USERPROFILE\Desktop\Tools\python3.exe" 
                }
            }
            
            # wait for python to finish installing
            while (Get-Procces -Name python3 -ErrorAction SilentlyContinue) {continue;}

            # should refresh the path so that the parsers can be used in the same session
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        }
        
        # run the parsers so that it can be viewed easily
        python3.exe '$env:USERPROFILE\Desktop\Tools\peas2json.py $env:USERPROFILE\Desktop\Tools\log.out $env:USERPROFILE\Desktop\Tools\peas.json'

        python3.exe '$env:USERPROFILE\Desktop\Tools\json2pdf.py $env:USERPROFILE\Desktop\Tools\peas.json $env:USERPROFILE\Desktop\Tools\peas.pdf'
    
        # open the pdf for viewing
        Start-Process ((Resolve-Path "C:\..\peas.pdf").Path)
    }
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
    Write-Host "[+] Setting up Windows Update..." -ForegroundColor Yellow
    
    # we will have to install this / need to make sure we can
    Install-Module -Name PSWindowsUpdate -ErrorAction Continue

    if (!$?) {
        Write-Output "[-] Error in installing PSUpdate" -ForegroundColor Red
    }else{
        Import-Module PSWindowsUpdate
        
        Write-Host "[i] This will work in the background and will need to Reboot when finished" -ForegroundColor Yellow
    
        # note this only installs the updates
        # it will help us control when we bring servers down for updates
        Get-WindowsUpdate -AcceptAll -Install
    }
}


# winfire only blocks certain ports at the moment
function WinFire {
    param (

    )

    Write-Host "[+] Hardening firewall..." -ForegroundColor Green

    # turn defaults on and set logging
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow -NotifyOnListen True -LogAllowed True -LogIgnored True -LogBlocked True -LogMaxSize 4096 -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

    # get the current listening conections ports
    $listening = Get-NetTCPConnection -State Listen, Established | Select-Object -Property LocalPort
    $allports = Get-NetTCPConnection | Select-Object -Property LocalPort

    PrintErr(!$?, "Error in trying to gather the currently listening ports")

    # create the rule to block all unused ports and activate it later
    # New-NetFirewallRule -DisplayName "Block all ports" -Direction Inbound -LocalPort Any -Action Block -Enabled False
    
    Write-Host "[i] You are possibly going to be asked if you want to block certain ports" -ForegroundColor Yellow
    Write-Host "[i] Your options are ( y ) or ( n )" -ForegroundColor Yellow

    Start-Sleep -Milliseconds 500

    # parse the list to block common remote access ports
    for ($x = 0; $x -lt ($allports.Length - 1); $x++) {

        $portNum = $allports[$x].LocalPort

        # uncomment for debug
        # Write-Host "$portNum"

        # 12/8/2023 Changing these if statements to switch statements
        
        switch ($portNum)
        {
            22 { # Disable SSH

                Write-Host $x
                $response = $(Write-Host "[?] Do you want to block ssh?: " -ForegroundColor Magenta -NoNewline; Read-Host)
    
                if ($response -eq ("y")) {
                
                    New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction in -LocalPort $portNum -Action Block
                    New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction out -LocalPort $portNum -Action Block
    
                    Write-Host "[+] SSH(22) blocked" -ForegroundColor Green
                    continue
    
                }else{
    
                    Write-Host "[+] SSH(22) will remain open" -ForegroundColor Green
                    continue
    
                }
            }
            5900 { # Disable VNC
        
                $response = $(Write-Host "[?] Do you want to block vnc?: " -ForegroundColor Magenta -NoNewline; Read-Host)
    
                if ($response -eq "y") {
        
                    New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction in -LocalPort $portNum -Action Block
                    New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction out -LocalPort $portNum -Action Block
    
                    Write-Host "[+] VNC(5900) blocked" -ForegroundColor Green
    
                    continue
    
                }else{
    
                    Write-Host "[+] VNC(5900) will remain open" -ForegroundColor Green
                    continue
    
                }
            }
            3389 { # Disable RDP
        
                $response = $(Write-Host "[?] Do you want to block rdp?: " -ForegroundColor Magenta -NoNewline; Read-Host)
    
                if ($response -eq "y") {
        
                    New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction in -LocalPort $portNum -Action Block
                    New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction out -LocalPort $portNum -Action Block
    
                    Write-Host "[+] RDP(3389) blocked" -ForegroundColor Green
                    continue
        
                }else{
    
                    Write-Host "[+] RDP(3389) will remain open" -ForegroundColor Green
                    continue
    
                }
            }
        }
        
        # allow the port if it is currently being used
        if ($allports[$x].LocalPort -in $listening) {
            New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction in -LocalPort $portNum -Action Allow
        } else {
            New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction out -LocalPort $portNum -Action Block
        }

        $FirewallProgress= @{
            Activity         = 'Configuring Firewall rules'
            Status           = 'Configuring'
            PercentComplete  = ($x / ($allports.Length-2)) * 100
            CurrentOperation = "port: number $x"
        }
        Write-Progress @FirewallProgress
    }

    # activate the rule from earlier
    # Enable-NetFirewallRule -DisplayName "Block all ports"

    Write-Host "[+] Finished hardening firewall" -ForegroundColor Green
    Write-Host "[i] Remember to do a deeper dive later and patch any holes" -ForegroundColor Yellow

}


# open/close the ports that are requested
function EditFirewallRule {
    param (
        $portNum, $action, $direction, $status, $protocol # protocol not assigned yet at 'Control', also status is string not bool
    )

    Write-Host "[+] Editing firewall rule..." -ForegroundColor Green
    #example: Set-NetFirewallRule -DisplayName "Block 22" -Protocol tcp -Direction Inbound -LocalPort 22 -Action Block -Enabled False
    Set-NetFirewallRule -DisplayName "$action $portNum" -Protocol $protocol -Direction $direction -LocalPort $portNum -Action $action -Enabled $status 
    PrintErr(!$?, "Error in editing firewall rule")

    Write-Host "[+] Changed firewall rule for port $portNum" -ForegroundColor Green
}

# change the password on admin account
function ChangeCreds {
    param (
        $mode
    )

    # password has to be changed first because it needs the username to change it
    if ($mode -eq "control") {
        Write-Host "[+] You are now about to change your password" -ForegroundColor Yellow

        $Password = $(Write-Host "Enter the new password: " -ForegroundColor Magenta -NoNewline; Read-Host -AsSecureString)
        Get-LocalUser -Name "$env:Username" | Set-LocalUser -Password $Password
        PrintErr(!$?, "Error in changing password, checks docs to perform manual change")

        Write-Host "[+] Changed password for ($env:Username)" -ForegroundColor Green
        Write-Host "[i] MAKE SURE TO LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT" -ForegroundColor Yellow

        return
    }

    # password has to be changed first because it needs the username to change it
    Write-Host "[+] You are now about to change your password" -ForegroundColor Yellow
    $Password = Read-Host "Enter the new password" -AsSecureString

    Get-LocalUser -Name "$env:Username" | Set-LocalUser -Password $Password
    PrintErr(!$?, "Error in changing password, checks docs to perform manual change")

    Write-Host "[+] Changed password for ($env:Username)" -ForegroundColor Green
    Write-Host "[i] MAKE SURE TO LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT" -ForegroundColor Yellow

    Write-Host "[+] You are about to change the username of the current admin"
    $newUsername = $(Write-Host "[?] What is the new name?: " -ForegroundColor Magenta -NoNewline; Read-Host)

    Rename-LocalUser -Name "$env:Username" -NewName "$newUsername"
    PrintErr(!$?, "Error while trying to change the username")

    Write-Host "[+] New username set" -ForegroundColor Green
}

function  RemoveTools {
    param (

    )

    Write-Host "[+] Removing the tools directory..." -ForegroundColor Green

    $remInstTools = $(Write-Host "[?] Do you want to also remove python3 and malwarebytes (y) or (n): " -ForegroundColor Magenta -NoNewline; Read-Host)
    if ($remInstTools -eq ("y")) {

        # uninstall python3.11
        Write-Host "[i] Python will open and you need to click to uninstall it" -ForegroundColor Yellow
        Start-Sleep -Milliseconds 2000

        Invoke-Expression -Command "$env:USERPROFILE\Desktop\Tools\python3.exe" 
        Start-Sleep -Milliseconds 2000

        # uninstall malwarebytes
        Write-Host "[i] Malwarebytes will be uninstalled next, follow the the prompts" -ForegroundColor Yellow
        Start-Sleep -Milliseconds 2000
        Invoke-Expression -Command "C:\'Program Files'\Malwarebytes\Anti-Malware\mb4uns.exe"

    }else {
        
        # move over the python3.11
        Write-Host "[+] Moving python3.exe..." -ForegroundColor Green
        Move-Item -Path "$env:USERPROFILE\Desktop\Tools\python3.exe" -Destination "$env:USERPROFILE\Desktop\"
        Write-Host "[+] Python moved" -ForegroundColor Green

        # move over the malwarebytes just in case
        Write-Host "[+] Moving malwarebytes..." -ForegroundColor Green
        Move-Item -Path "$env:USERPROFILE\Desktop\Tools\mb.exe" -Destination "$env:USERPROFILE\Desktop\"
        Write-Host "[+] Malwarebytes moved" -ForegroundColor Green

    }

    # remove the directory with all of the installed tools in it
    Remove-Item -LiteralPath "$env:USERPROFILE\Desktop\Tools" -Force -Recurse
    PrintErr(!$?, "Error while trying to remove the Tools directory")

    Write-Host "[+] Deleted the tools directory" -ForegroundColor Green
}

function Discovery {
    param (
        $mode
    )

    $discoverypath = "$env:USERPROFILE\Desktop\Discovery"

    # note in this case removing the dump is = "undoing it"
    if ($mode -eq "undo") {
        Remove-Item -LiteralPath "$discoverypath" -Force -Recurse 
    }

    if ($mode -eq "y") { 

        Write-Host "[+] Running discovery dump..." -ForegroundColor Green
        Write-Host "[i] YOU SHOULD STILL BE USING THE OTHER TOOLS THAT WERE INSTALLED" -ForegroundColor Yellow
        if (Test-Path -Path "$env:USERPROFILE\Desktop\Discovery") {
            continue
        }else{
            New-Item -Path "$env:USERPROFILE\Desktop" -Name Discovery -type Directory
        }

        # -- prints the results of data dumps into a nicely formatted table for saving --

        Write-Host "[+] Gathering services..." -ForegroundColor Yellow
        Get-Service -Verbose | Format-Table -AutoSize > "$discoverypath\services.txt"

        # gather the running process on a system with the username tagged to it
        Write-Host "[+] Gathering running processes..." -ForegroundColor Green
        $owners = @{}
        Get-WmiObject win32_process | Foreach-Object {$owners[$_.handle] = $_.getowner().user} -ErrorAction SilentlyContinue
        Get-Process | Select-Object processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}} -ErrorAction SilentlyContinue | Format-Table -AutoSize > "$discoverypath\processes.txt"

        Write-Host "[+] Gathering tcp connections..." -ForegroundColor Green
        Get-NetTCPConnection -Verbose | Format-Table -AutoSize > "$discoverypath\connections.txt"

        Write-Host "[+] Gathering any scheduled tasks..." -ForegroundColor Green
        Get-ScheduledTask -Verbose | Format-Table -AutoSize > "$discoverypath\scheduledtasks.txt"

        Write-Host "[+] Gathering any startup apps..." -ForegroundColor Green
        Get-CimInstance Win32_StartupCommand |
        Select-Object Name, command, Location, User |
        Format-Table -AutoSize > "$discoverypath\startupapps.txt"

        Write-Host "[+] Gathering list of users for diff..." -ForegroundColor Green
        Get-ADGroupMember | Format-Table -AutoSize > "$discoverypath\lsadusrs.txt"
        Get-LocalUser | Format-Table -AutoSize > "$discoverypath\lslusrs.txt"

        Write-Host "[+] Data dumped to 'Discovery' folder on your desktop" -ForegroundColor Green
    
        Write-Host "[i] You should still be using other tools because this won't catch everything" -ForegroundColor Yellow
    }
}

function SetUAC {
    param (
        
    )

    Write-Host "[+] Setting UAC values..." -ForegroundColor Green

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

    Write-Host "[+] Values set" -ForegroundColor Green
}

# runs a basic windows defender scan
function DefenderScan {
    param (
        
    )

    # check to make sure windows defender is able to run
    if (Get-MpComputerStatus) {
        
        Write-Host "[+] Setting up for scan..." -ForegroundColor Green
        
        Set-MpPreference -CheckForSignaturesBeforeRunningScan True -CloudBlockLevel

        Write-Host "[+] Removing any exclusions..." -ForegroundColor Green
        
        # remove all exclusion if there are any
        $preference = Get-MpPreference
        
        foreach ($x in $preference.ExclusionPath) {
            Remove-MpPreference -ExclusionPath $x
        }

        Write-Host "[+] Running scan in the background..."
        
        # TODO receive output from scan
        Start-MpScan -ScanType FullScan -ScanPath C: -AsJob -OutVariable scanOut
    
    }else {
        Write-Host "[-] Error in checking windows defender" -ForegroundColor Red
    }
}


function EnableDefenderOn {
    param (
        $mode, $step
    )

    # gather the status of WD
    $wdav = Get-MpComputerStatus
    
    if ($wdav.AntivirusEnabled -eq $false) {
        
        $turnDefenderOn = $(Write-Host "[?] Do you want to turn on Windows Defender (y) or undo(u): " -ForegroundColor Magenta -NoNewline; Read-Host)
        # TODO need to test
    
        if ($turnDefenderOn -eq "y") {
        
            Write-Host "[+] Enabling Windows Defender..." -ForegroundColor Green

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
                Write-Host "[+] Windows Defender Enabled" -ForegroundColor Green
            }else{
                Write-Host "[-] Error in trying to startup Windows Defender" -ForegroundColor Red
            }
        }elseif (($turnDefenderOn -eq "u") -and ($step -eq 4)) {

            Write-Host "[+] Stopping Windows Defender..." -ForegroundColor Green

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
                Write-Host "[+] Windows Defender Disabled" -ForegroundColor Green
            }else{
                Write-Output "[-] Error in trying to stop Windows Defender" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[i] Windows Defender is already active" -ForegroundColor Yellow
    }
}

function Enable-PSScriptBlockLogging {
    $basepath = @(
        'hklm:\software\policies\microsoft\windows'
        'powershell\scriptblocklogging'
    ) -join '\'

    if (-not (test-path $basepath)) {
        $null = new-item $basepath -force
    }

    Set-ItemProperty $basePath -Name EnableScriptBlockLogging -Value "1"
}


function Harden {
    param (

    )

    [String]$mode = "harden"
    
    # check if the Tools folder is already created
    Write-Host "[+] Checking to see if the tools are installed..." -ForegroundColor Green
    $tp = Test-Path -Path "$env:USERPROFILE\Desktop\Tools" 
    if (!$tp) {
        InstallTools
    }

    # install malwarebytes
    Write-Host "[+] Downloading malwarebytes..." -ForegroundColor Green

    Invoke-WebRequest "https://downloads.malwarebytes.com/file/mb-windows" -OutFile "$env:USERPROFILE\Desktop\Tools\mb.exe"
    PrintErr(!$?, "Error while trying to download malwarebytes")
    

    # Run Malwarebytes
    Write-Host "[i] Click to install the software" -ForegroundColor Yellow
    Invoke-Expression "$env:USERPROFILE\Desktop\Tools\mb.exe"

    Start-Sleep -Milliseconds 1000
    
    #Long but disables all guests
    Write-Host "[+] Clearing out guest accounts..." -ForegroundColor Green

    # note this should not need undo because no guests accounts should be allowed
    $user = Get-LocalGroupMember -Name "Guests" 
    foreach ($j in $user) { 
        Write-Host "[i] Disabling guest: $j" -ForegroundColor Yellow
        Disable-LocalUser -Name ([string]$j).Split('\')[1] # grabbing the actual user name
    }
    # note this should error if everything goes well
    Write-Host "[i] Running a different command to make sure Guest was removed" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host "[i] If it errors that means that it worked" -ForegroundColor Yellow
    Start-Sleep(3)
    Get-LocalUser Guest | Disable-LocalUser -ErrorAction continue
    Write-Host "[+] Guest accounts cleared" -ForegroundColor Green

    # remove all the non-required admin accounts
    Write-Host "[+] Removing all admin accounts...except yours" -ForegroundColor Green

    # read the groups and select the correct admin group
    $a = Get-LocalGroup | Select-Object -Property "Name" | Select-String -Pattern "admin"
    Write-Host "$a"
    [Int]$c = $(Write-Host "[?] Enter index of real admin group: " -ForegroundColor Magenta -NoNewline; Read-Host)
    foreach ($i in $a) {
        if ($i -eq $a[$c]) {
            [String]$adminGroup = $i
        }
    }

    # grabs the group name from the object
    # this outputs True and I dont know how to stop it but we also cant touch this line.
    $adminGroup -match '(?<==)[\w]+'

    # note this should not need undo because it only removes the account from the Administrators group
    # TODO need further testing
    $user = Get-LocalGroupMember -Name $Matches[0]
    foreach ($x in $user) {
        $st =[string]$x.Name
        if ($st -eq $env:computername+'\Administrator'){
            continue
        }
        if ( -Not $st.Contains($env:USERNAME)) {
            Write-Host "[i] Removing other admins: $st" -ForegroundColor Yellow
            Remove-LocalGroupMember -Group $Matches[0] $st
        }
    }
    Write-Host "[+] Pruned Administrator accounts" -ForegroundColor Green


    # harden the firewall for remote or lan comps
    $winFirewallOn = $(Write-Host "[?] Do you want to turn on the windows firewall (y): " -ForegroundColor Magenta -NoNewline; Read-Host)
    if ($winFirewallOn -eq ("y")) {
        WinFire
    }


    $hardenExch = $(Write-Host "[?] Do you want to Harden Exchange (y): " -ForegroundColor Magenta -NoNewline; Read-Host)
    if ($hardenExch -eq ("y")) {
        # checking for services of exchange Exchange seems to work the best
        if (Get-Service | Select-Object -Property "Name" | Select-String -Pattern "Exchange") {
            ExchangeHard($mode)
        }
    }


    # turn on Windows Defender
    # note Windows 8.1 (server 2016+) should already be on
    EnableDefenderOn($mode, $step)
    

    # start all the installed tools to find any possible weird things running
    ToolStart ($toolsPath)


    # change the execution policy for powershell for admins only (works only for the current machine)
    # rest of restrictions happen in group policy and active directory
    Write-Host "[+] Changing powershell policy..." -ForegroundColor Green

    Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -ErrorAction Continue
    PrintErr(!$?, "Error in changing execution policy")

    Write-Host "[+] Execution policy was changed to restricted" -ForegroundColor Green
    

    # setup UAC
    SetUAC


    # disable anonymous logins
    Write-Host "[+] Disabling anonymous users..." -ForegroundColor Green
    $a = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymous"
    if ($a.restrictanonymous -ne 1) {
        Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymous" -Value 1 -Force
        PrintErr(!$?, "Error while trying to edit the registry key for anonymous logins")
    }
    Write-Host "[+] Disabled anonymous users" -ForegroundColor Green

    
    # disable anonymous sam
    Write-Host "[+] Disabling anonymous SAM touching..." -ForegroundColor Green
    $a = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymoussam"
    if ($a.restrictanonymoussam -ne 1) {
        Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymoussam" -Value 1 -Force
        PrintErr(!$?, "Error while trying to edit the registry key for anonymous access to SAM")
    }
    Write-Host "[+] Touching SAM anonymously is disabled" -ForegroundColor Green
    
    # disable editing of the registry through tools
    # note warning this will stop a user from editing the registry all together
    Write-Host "[+] Disabling regedit..." -ForegroundColor Green
    $a = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name "disableregistrytools"
    if ($a.disableregistrytools -ne 2) {
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name "disableregistrytools" -Value 2 -Force
        PrintErr(!$?, "Error while trying to disable access to regedit")
    }
    Write-Host "[+] Registry editing via tools disabled" -ForegroundColor Green

    # TODO enable/install wdac/applocker/or DeepBlue CLi?


    # disable netbios ??????(might be too good)
    $adapters=(Get-WmiObject win32_networkadapterconfiguration)
    foreach ($adapter in $adapters){
        Write-Host $adapter
        $adapter.settcpipnetbios(0)
    }

    # configure SMB to report connections to SMBv1 server
    Set-SmbServerConfiguration -AuditSmb1Access $true

    # Enable logging for powershell, very powerfull if we can use it
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1
    Enable-PSScriptBlockLogging

    # change the password/username of the current admin user
    ChangeCreds($mode)
    
    # update windows if it is in the scope of the rules
    $updates = $(Write-Host "[?] Do you want to update (y): " -ForegroundColor Magenta -NoNewline; Read-Host)
    
    if ($updates -eq ("y")) {
        WinUP
    }
}

function Undo {
    param (

    )

        [String]$mode = "undo"

        Write-Host "
        - (#) To uninstall all installed tools use RemoveTools in the control menu
        - (Exchange) Exchange(TODO)
        - (Defender) Windows Defender
        - (Psh) Psh Policy
        - (WinRm) Enable WinRM(why?????)
        - (netbios) re-enable netbios(TODO)
        - (SMB) re-enable SMBv1
        "

        [string]$step = $(Write-Host "[?] What step do you want to undo: " -ForegroundColor Magenta -NoNewline; Read-Host)

        switch ($step) {

        "Exchange" { 
            
            continue;

            # looks for services that have "Exchange"
            if (Get-Service | Select-Object -Property "Name" | Select-String -Pattern "Exchange") {
                ExchangeHard ($mode) 
            }else {
                Write-Host "[i] This machine is not runnning Exchange" -ForegroundColor Yellow
            }
        }

        "Defender" {
            EnableDefenderOn($mode)
        }

        "Psh" {
            Write-Host "[+] Changing powershell policy..." -ForegroundColor Green
            
            Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope LocalMachine -Confirm
            PrintErr(!$?, "Error in changing the execution policy to Undefined")

            Write-Host "[+] Changed the Powershell policy to Undefined" -ForegroundColor Green
        }

        "netbios" { continue }
        
        "SMB" {
            HardenSMB($mode)
        }

        default { continue }
    }

}


function Main {
    param (

    )

    # should stop underprivledged users from running the script
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    $p = New-Object System.Security.Principal.WindowsPrincipal($id)

    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { 
        Write-Host "Welcome to WindowsHard!" -ForegroundColor Green
        Write-Host "Goodluck Today!!!" -ForegroundColor Green
    }else{ 
        Write-Host "No Red Team Allowed >:P!!!" -ForegroundColor Red
        Write-Host "Hope You Have a Good Day!!!" -ForegroundColor Red
        exit
    }

    # introduction
    Write-Host "[i] Choose a mode to run the script" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host "[i] Harden will start the hardening process on the current machine" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host "[i] Control will allow the user to make changes to windows without having to navigate around" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host "[i] If any errors occur, a message will be printed to the console in " -ForegroundColor Yellow -NoNewline; Write-Host "[red]" -ForegroundColor Red
    Start-Sleep -Milliseconds 500
    Write-Host "[i] If any progress is made, a message will be printed to the console in " -ForegroundColor Yellow -NoNewline; Write-Host "[green]" -ForegroundColor Green
    Start-Sleep -Milliseconds 500
    Write-Host "[i] Any side note info will be printed to the console in " -ForegroundColor Yellow -NoNewline; Write-Host "[yellow]" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host "[i] All questions to the user will be printed to the console in " -ForegroundColor Yellow -NoNewline; Write-Host "[magenta]" -ForegroundColor Magenta

    $usermode = $(Write-Host "[?] Harden(h) or Control(c): " -ForegroundColor Magenta -NoNewline; Read-Host)
    if ($usermode -eq ("h")) {
        $mode = "harden";
        Harden($mode)
    } 

    if ($usermode -eq ("c"))  {

        while($true) {
            Write-Host "[?] What would you like to do
            - (efwrule) edit a firewall rule
            - (chpwd) Change Password
            - (instls) Install Tools
            - (strtls) Start Tools
            - (rmtls) Remove Tools
            - (wp) Install & Run winpeas
            - (disc) Discovery
            - (scan) DefenderScan
            - (Undo) Undo
            - (OSK) OSK Spawn
            - (Wonk) Start Wonk
            - quit
            " 
            
            $choice = $(Write-Host "Which mode do you want?: " -ForegroundColor Magenta -NoNewline; Read-Host)
            switch ($choice) {

                "efwrule" {
                    [Int]$portNum = $(Write-Host "[?] Which port (number): " -ForegroundColor Magenta -NoNewline; Read-Host)
                    [String]$action = $(Write-Host "[?] (Allow) or (Block): " -ForegroundColor Magenta -NoNewline; Read-Host)
                    [String]$direction = $(Write-Host "[?] Which direction (in) or (out): " -ForegroundColor Magenta -NoNewline; Read-Host)
                    [String]$status = $(Write-Host "[?] To create the rule use (True) or (False): " -ForegroundColor Magenta -NoNewline; Read-Host)
                    [String]$protocol = $(Write-Host "[?] What protocol (TCP) or (UDP): " -ForegroundColor Magenta -NoNewline; Read-Host)

                    EditFirewallRule $portNum $action $direction $status $protocol
                }

                "chpwd" {
                    $credsmode = "control"
                    ChangeCreds($credsmode)
                }

                "instls" {InstallTools}

                "strtls" {ToolStart($toolsPath)}

                "rmtls" {RemoveTools}

                "wp" {Winpeas}
                
                "disc" {
                    $discoveryMode = $(Write-Host "[?] Do you want to perform a dump (y) or (undo), ***WARNING*** (undo) will remove the dump: " -ForegroundColor Magenta -NoNewline; Read-Host)
                    Discovery($discoveryMode)
                }
                
                "scan" {DefenderScan}

                "Undo" {
                    Write-Host "[i] Remember that functions already exist that can undo like RemoveTools" -ForegroundColor Yellow
                    Undo
                }

                "OSK" {
                    continue;
                    # TODO finish fun
                    # This will only work on Windows 10, removed in Windows 11

                    $runUser = $(Write-Host "[?] What user do you want to punish?: " -ForegroundColor Magenta -NoNewline; Read-Host)
                    Start-Job -scriptblock {while (!(Get-Procces -Name "osk.exe")) {Start-Process -FilePath "C:\Windows\System32\osk.exe" -WindowStyle Maximized -RunAs $runUser}}
                }

                "Wonk" {
                    # -- download/compile/run Wonk --

                    # download the version of dotnet required to run wonk
                    # note installing the sdk also installs the runtime
                    # Write-Host "[+] Installing the verion of .net sdk that is required..." -ForegroundColor Green

                    # Invoke-WebRequest "https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-7.0.202-windows-x64-installer" -OutFile "$env:Userprofile\Desktop\Tools\dotnet7.exe"
                    # PrintErr(!$?,"Error in downloading dotnet installer, make sure you have internet access")

                    # Invoke-Expression "$env:USERPROFILE\Desktop\Tools\dotnet7.exe"
                    # PrintErr(!$?,"Error in running dotnet installer, make sure you have right privs")

                    # Write-Host "[+] .net sdk installed" -ForegroundColor Green
                    
                    # need to refresh the path again to use the cli
                    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
                    
                    Write-Host "[+] Download Wonk..." -ForegroundColor Green

                    # note url is a placeholder
                    Invoke-WebRequest "https://github.com/VJMumphrey/CompScripts/archive/refs/heads/main.zip" -Outfile "$env:Userprofile\Desktop\wonk.zip"
                    PrintErr(!$?,"Error in downloading Wonk, make sure you have internet access")

                    Expand-Archive -LiteralPath "$env:Userprofile\Desktop\wonk.zip" -DestinationPath "$env:USERPROFILE\Desktop\Wonk"

                    Write-Host "[+] Wonk downloaded" -ForegroundColor Green

                    Set-Location "$env:Userprofile\Desktop\Wonk"

                    Write-Host "[+] Building Wonk..." -ForegroundColor Green
                    dotnet build -c release
                    Write-Host "[+] Wonk is built" -ForegroundColor Green

                    Write-Host "[+] Starting up Wonk..." -ForegroundColor Green

                    # TODO test and make sure this starts as intended
                    # Start-Process .\bin\release\net7.0\wonk.exe

                    # create a class for Wonk
                    $params = @{
                        Name = "Wonk"
                        BinaryPathName = "$env:USERPROFILE\Desktop\Wonk\.bin\release\net7.0\wonk.exe"
                        DisplayName = "Wonk Service"
                        StartupType = "AutomaticDelayedStart"
                    }

                    New-Service @params

                    Start-Service -Name "Wonk"

                    PrintErr(!$?,"Error in starting Wonk, make sure you have right privs")

                    Write-Host "[+] Wonk is running" -ForegroundColor Green
                }

                "quit" {return}

                default {continue}
            } 
        }
    }
}

Main
