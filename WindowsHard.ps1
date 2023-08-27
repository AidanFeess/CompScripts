Import-Module Defender
Import-Module NetSecurity
Import-Module NetTCPIP
Import-Module GroupPolicy
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

    Write-Host "[+] installing tools..."

    New-Item -Path "$env:USERPROFILE\Desktop\" -Name Tools -type Directory
    
    # -- Download the specific tools instead of downloading the entire suite --
    
    $urls = @(
        TCPView  = "https://download.sysinternals.com/files/TCPView.zip",
        Procmon  = "https://download.sysinternals.com/files/ProcessMonitor.zip", 
        Autoruns = "https://download.sysinternals.com/files/Autoruns.zip"
    )

    $zipPath = @(
        TCPView  = "$env:USERPROFILE\Desktop\Tools\TCPView.zip", 
        Procmon  = "$env:USERPROFILE\Desktop\Tools\ProcessMonitor.zip", 
        Autoruns = "$env:USERPROFILE\Desktop\Tools\Autoruns.zip"
    )

    foreach ($tool in [Tools].GetEnumNames()) {
        Invoke-WebRequest $urls[$tool] -OutFile "$env:USERPROFILE\Desktop\Tools\$tool.zip"
        PrintErr(!$?,"Error in downloading Tool, make sure you have internet access")

        Expand-Archive -LiteralPath "$zipPath[$tool]" -DestinationPath "$env:USERPROFILE\Desktop\Tools\$tool"
        PrintErr(!$?, "Error in unziping TCPView, make sure it was downloaded")
    }   
    
    Write-Host "[+] finished installing tools" -ForegroundColor Green
}

# once tools are run winpeas and parse the output and save it
function ToolStart {
    param (
        $toolsPath
    )

    Write-Host "[+] opening tools..." -ForegroundColor Yellow

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

    Write-Host "[+] all tools opened" -ForegroundColor Green
}

# Downloads and runs winpeas on the system
function Winpeas {
    param (

    )
    
    $runWinpeas = $(Write-Host "Would you like to run Winpeas: " -ForegroundColor Magenta -NoNewline; Read-Host)
    if ($runWinpeas -eq "y") {
        
        # download and run winpeas in memory
        $url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
        $wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("log") > "$toolsPath\winpeas.txt"

        # execute the parsers to convert to pdf
        $installPython = $(Write-Host "Would you like to install Python?: " -ForegroundColor Magenta -NoNewline; Read-Host)
        if ($installPython -eq "y") {
        
            Write-Host "[+] WARNING this can leave your system vulnerable" -ForegroundColor Magenta
            Write-Host "[+] Consider removing these items after use if they aren't going to be controlled" -ForegroundColor Magenta

            $pythonList = @(
                python3   = "https://www.python.org/ftp/python/3.11.2/python-3.11.2-amd64.exe", 
                peas2json = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/peas2json.py",
                json2pdf  = "https://github.com/carlospolop/PEASS-ng/blob/master/parsers/json2pdf.py"  
            )

            foreach ($tools in [PyTools].GetEnumNames()) {
                Invoke-Webrequest "$pythonList[$tools]" -Outfile "$env:USERPROFILE\Desktop\Tools\$tools"
                PrintErr(!$?, "Error while trying to download python and winpeas parsers")
                    
                if ($tools -eq [PyTools].python3) {
                    # still need to manually install
                    Write-Host "[+] install python and make sure to add to your path" -ForegroundColor Magenta
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
        
        Write-Host "[+] This will work in the background and will need to Reboot when finished" -ForegroundColor Yellow
    
        # note this only installs the updates
        # it will help us control when we bring servers down for updates
        Get-WindowsUpdate -AcceptAll -Install
    }
}


# winfire only blocks certain ports at the moment
function WinFire {
    param (

    )

    Write-Host "[+] hardening firewall..." -ForegroundColor Yellow

    # turn defaults on and set logging
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow -NotifyOnListen True -LogAllowed True -LogIgnored True -LogBlocked True -LogMaxSize 4096 -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

    # get the current listening conections ports
    $listening = Get-NetTCPConnection -State Listen, Established | Select-Object -Property LocalPort
    $allports = Get-NetTCPConnection | Select-Object -Property LocalPort

    PrintErr(!$?, "Error in trying to gather the currently listening ports")

    # create the rule to block all unused ports and activate it later
    # New-NetFirewallRule -DisplayName "Block all ports" -Direction Inbound -LocalPort Any -Action Block -Enabled False
    
    Write-Host "[+] You are possibly going to be asked if you want to block certain ports" -ForegroundColor Green
    Write-Host "your options are ( y ) or ( n )" -ForegroundColor Yellow

    # parse the list to block common remote access ports
    for ($x = 0; $x -lt ($allports.Length - 1); $x++) {

        $portNum = $allports[$x].LocalPort

        # uncomment for debug
        # Write-Host "$portNum"

        if ($x -eq 22) {

            $response = $(Write-Host "Do you want to block ssh?: " -ForegroundColor Magenta -NoNewline; Read-Host)

            if ($response -eq ("y")) {
            
                New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction Inbound -LocalPort $portNum -Action Block
                New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction Outbound -LocalPort $portNum -Action Block

                Write-Host "[+] ssh(22) blocked" -ForegroundColor Green
                continue

            }else{

                Write-Host "[+] ssh(22) will remain open" -ForegroundColor Green
                continue

            }
        }

        if ($x -eq 5900) {
    
            $response = $(Write-Host "Do you want to block vnc?: " -ForegroundColor Magenta -NoNewline; Read-Host)

            if ($response -eq "y") {
    
                New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction Inbound -LocalPort $portNum -Action Block
                New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction Outbound -LocalPort $portNum -Action Block

                Write-Host "[+] vnc(5900) blocked" -ForegroundColor Green

                continue

            }else{

                Write-Host "[+] vnc(5900) will remain open" -ForegroundColor Green
                continue

            }
        }

        if ($x -eq 3389) {
    
            $response = $(Write-Host "Do you want to block rdp?: " -ForegroundColor Magenta -NoNewline; Read-Host)

            if ($response -eq "y") {
    
                New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction Inbound -LocalPort $portNum -Action Block
                New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction Outbound -LocalPort $portNum -Action Block

                Write-Host "[+] rdp(3389) blocked" -ForegroundColor Green
                continue
    
            }else{

                Write-Host "[+] rdp(3389) will remain open" -ForegroundColor Green
                continue

            }
        }
        
        # allow the port is it is currently being used
        if ($allports[$x].LocalPort -in $listening) {
            New-NetFirewallRule -DisplayName "Allow $portNum" -Protocol tcp -Direction Inbound -LocalPort $portNum -Action Allow
        } else {
            New-NetFirewallRule -DisplayName "Block $portNum" -Protocol tcp -Direction Inbound -LocalPort $portNum -Action Block
        }
    }

    # activate the rule from earlier
    # Enable-NetFirewallRule -DisplayName "Block all ports"

    Write-Host "[+] finished hardening firewall" -ForegroundColor Green
    Write-Host "[+] remember to do a deeper dive later and patch any holes" -ForegroundColor Magenta

}


# open/close the ports that are requested
function EditFirewallRule {
    param (
        $portNum, $action, $direction, $protocol, $status
    )

    Write-Host "[+] editing firewall rule..." -ForegroundColor Yellow
    
    Set-NetFirewallRule -DisplayName "$action $portNum" -Direction $direction -LocalPort $portNum  -Protocol $protocol -Action $action -Enabled $status 
    PrintErr(!$?, "Error in editing firewall rule")

    Write-Host "[+] changed firewall rule for $port" -ForegroundColor Green
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

        Write-Host "[+] changed password for ($env:Username)" -ForegroundColor Green
        Write-Host "[+] MAKE SURE TO LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT" -ForegroundColor Magenta

        return
    }

    # password has to be changed first because it needs the username to change it
    Write-Host "[+] You are now about to change your password" -ForegroundColor Yellow
    $Password = Read-Host "Enter the new password" -AsSecureString

    Get-LocalUser -Name "$env:Username" | Set-LocalUser -Password $Password
    PrintErr(!$?, "Error in changing password, checks docs to perform manual change")

    Write-Host "[+] changed password for ($env:Username)" -ForegroundColor Green
    Write-Host "[+] MAKE SURE TO LOGOUT AND LOG BACK IN FOR THE CHANGE TO TAKE EFFECT" -ForegroundColor Magenta

    Write-Host "[+] You are about to change the username of the current admin"
    $newUsername = $(Write-Host "What is the new name?: " -ForegroundColor Magenta -NoNewline; Read-Host)

    Rename-LocalUser -Name "$env:Username" -NewName "$newUsername"
    PrintErr(!$?, "Error while trying to change the username")

    Write-Host "[+] New username set" -ForegroundColor Green
}

function  RemoveTools {
    param (

    )

    Write-Host "[+] Removing the tools directory..." -ForegroundColor Yellow

    $remInstTools = $(Write-Host "Do you want to also remove python3 and malwarebytes (y) or (n): " -ForegroundColor Magenta -NoNewline; Read-Host)
    if ($remInstTools -eq ("y")) {

        # uninstall python3.11
        Write-Host "[+] Python will open and you need to click to uninstall it" -ForegroundColor Magenta
        Start-Sleep -Milliseconds 2000

        Invoke-Expression -Command "$env:USERPROFILE\Desktop\Tools\python3.11.exe" 
        Start-Sleep -Milliseconds 2000

        # uninstall malwarebytes
        Write-Host "[+] Malwarebytes will be uninstalled next, follow the the prompts" -ForegroundColor Magenta
        Start-Sleep -Milliseconds 2000
        Invoke-Expression -Command "C:\'Program Files'\Malwarebytes\Anti-Malware\mb4uns.exe"

    }else {
        
        # move over the python3.11
        Write-Host "[+] Moving python3.11..." -ForegroundColor Yellow
        Move-Item -Path "$env:USERPROFILE\Desktop\Tools\python3.11.exe" -Destination "$env:USERPROFILE\Desktop\"
        Write-Host "[+] Python moved" -ForegroundColor Green

        # move over the malwarebytes just in case
        Write-Host "[+] Moving malwarebytes..." -ForegroundColor Yellow
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

        Write-Host "[+] running discovery dump..." -ForegroundColor Yellow
        Write-Host "[+] YOU SHOULD STILL BE USING THE OTHER TOOLS THAT WERE INSTALLED" -ForegroundColor Magenta
        if (Test-Path -Path "$env:USERPROFILE\Desktop\Discovery") {
            continue
        }else{
            New-Item -Path "$env:USERPROFILE\Desktop" -Name Discovery -type Directory
        }

        # -- prints the results of data dumps into a nicely formatted table for saving --

        Write-Host "[+] gathering services..." -ForegroundColor Yellow
        Get-Service -Verbose | Format-Table -AutoSize > "$discoverypath\services.txt"

        # gather the running process on a system with the username tagged to it
        Write-Host "[+] gathering running processes..." -ForegroundColor Yellow
        $owners = @{}
        Get-WmiObject win32_process | Foreach-Object {$owners[$_.handle] = $_.getowner().user} -ErrorAction SilentlyContinue
        Get-Process | Select-Object processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}} -ErrorAction SilentlyContinue | Format-Table -AutoSize > "$discoverypath\processes.txt"

        Write-Host "[+] gathering tcp connections..." -ForegroundColor Yellow
        Get-NetTCPConnection -Verbose | Format-Table -AutoSize > "$discoverypath\connections.txt"

        Write-Host "[+] gathering any scheduled tasks..." -ForegroundColor Yellow
        Get-ScheduledTask -Verbose | Format-Table -AutoSize > "$discoverypath\scheduledtasks.txt"

        Write-Host "[+] gathering any startup apps..." -ForegroundColor Yellow
        Get-StartApps | Format-Table -AutoSize > "$discoverypath\startupapps.txt"

        Write-Host "[+] gathering list of users for diff..." -ForegroundColor Yellow
        Get-ADGroupMember | Format-Table -AutoSize > "$discoverypath\lsadusrs.txt"
        Get-LocalUser | Format-Table -AutoSize > "$discoverypath\lslusrs.txt"

        Write-Host "[+] data dumped to 'Discovery' folder on your desktop" -ForegroundColor Magenta
    
        Write-Host "[+] You should still be using other tools because this won't catch everything" -ForegroundColor Yellow
    }
}

function SetUAC {
    param (
        
    )

    Write-Host "[+] setting UAC values..." -ForegroundColor Green

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

    Write-Host "[+] values set" -ForegroundColor Green
}

# runs a basic windows defender scan
function DefenderScan {
    param (
        
    )

    # check to make sure windows defender is able to run
    if (Get-MpComputerStatus) {
        
        Write-Host "[+] setting up for scan..." -ForegroundColor Yellow
        
        Set-MpPreference -CheckForSignaturesBeforeRunningScan True -CloudBlockLevel

        Write-Host "[+] removing any exclusions..." -ForegroundColor Green
        
        # remove all exclusion if there are any
        $preference = Get-MpPreference
        
        foreach ($x in $preference.ExclusionPath) {
            Remove-MpPreference -ExclusionPath $x
        }

        Write-Host "[+] running scan in the background..."
        
        # TODO receive output from scan
        Start-MpScan -ScanType FullScan -ScanPath C: -AsJob -OutVariable scanOut
    
    }else {
        Write-Host "[-] error in checking windows defender" -ForegroundColor Red
    }
}


function EnableDefenderOn {
    param (
        $mode, $step
    )

    # gather the status of WD
    $wdav = Get-MpComputerStatus
    
    if ($wdav.AntivirusEnabled -eq $false) {
        
        $turnDefenderOn = $(Write-Host "Do you want to turn on Windows Defender (y) or undo(u): " -ForegroundColor Magenta -NoNewline; Read-Host)
        # TODO need to test
    
        if ($turnDefenderOn -eq "y") {
        
            Write-Host "Enabling Windows Defender..." -ForegroundColor Yellow

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

            Write-Host "Stopping Windows Defender..." -ForegroundColor Yellow

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
        Write-Host "[+] Windows Defender is already active" -ForegroundColor Yellow
    }
}


function Harden {
    param (
       $mode
    )
        
        # check if the Tools folder is already created
        Write-Host "[+] checking to see if the tools are installed..." -ForegroundColor Yellow
        if (Test-Path -Path "$env:USERPROFILE\Desktop\Tools") {
            continue
        } else {
            InstallTools
        }

        # install malwarebytes
        Write-Host "[+] downloading malwarebytes..."

        Invoke-WebRequest "https://downloads.malwarebytes.com/file/mb-windows" -OutFile "$env:USERPROFILE\Desktop\Tools\mb.exe"
        PrintErr(!$?, "Error while trying to download malwarebytes")
        

        # Run Malwarebytes
        Write-Host "[+] click to install the software" -ForegroundColor Magenta
        Invoke-Expression "$env:USERPROFILE\Desktop\Tools\mb.exe"

        Start-Sleep -Milliseconds 1000
        
        #Long but disables all guests
        Write-Host "[+] clearing out guest accounts..." -ForegroundColor Yellow

        # note this should not need undo because no guests accounts should be allowed
        $user = Get-LocalGroupMember -Name "Guests" 
        foreach ($j in $user) { 
            Write-Output "disabling guest: $j" -ForegroundColor Green
            Disable-LocalUser -Name $j
        }
        Write-Host "[+] guest accounts cleared" -ForegroundColor Green

        # remove all the non-required admin accounts
        Write-Host "[+] removing all admin accounts...execpt yours" -ForegroundColor Yellow

        # read the groups and select the correct admin group
        $a = Get-LocalGroup | Select-Object -Property "Name" | Select-String -Pattern "admin"
        Write-Host "$a"
        [Int]$c = $(Write-Host "Which one is the real admin group: " -ForegroundColor Magenta -NoNewline; Read-Host)
        foreach ($i in $a) {
            if ($i -eq $a[$c]) {
                [String]$adminGroup = $i
            }
        }

        # grabs the group name from the object
        $adminGroup -match '(?<==)[\w]+'

        # note this should not need undo because it only removes the account from the Administrators group
        # TODO need further testing
        $user = Get-LocalGroupMember -Name $Matches[0]
        foreach ($x in $user) {
            $st =[string]$x.Name
            if ( -Not $st.Contains($env:USERNAME)) {
                Write-Output "disabling admin: $st"
                Remove-LocalGroupMember -Group $Matches[0] $st
            }
        }
        Write-Host "[+] pruned Administrator accounts" -ForegroundColor Green


        # harden the firewall for remote or lan comps
        $winFirewallOn = $(Write-Host "Do you want to turn on the windows firewall (y): " -ForegroundColor Magenta -NoNewline; Read-Host)
        if ($winFirewallOn -eq ("y")) {
            WinFire
        }


        $hardenExch = $(Write-Host "Do you want to Harden Exchange (y): " -ForegroundColor Magenta -NoNewline; Read-Host)
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
        Write-Host "[+] changing powershell policy..." -ForegroundColor Yellow

        Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -ErrorAction Continue
        PrintErr(!$?, "Error in changing execution policy")

        Write-Host "[+] Execution policy was changed to restricted" -ForegroundColor Green
       

        # disable WinRM
        $disableWinRm = $(Write-Host "disable WinRm? (y): " -ForegroundColor Magenta -NoNewline; Read-Host)
        if ($disableWinRm -eq ("y")) {
            try {
                Disable-PSRemoting -Force -ErrorAction Continue
                New-NetFirewallRule -DisplayName "Block WinRMHTTP" -Protocol tcp -Direction Inbound -LocalPort 5985 -Action Block
                New-NetFirewallRule -DisplayName "Block WinRMHTTPS" -Protocol tcp -Direction Outbound -LocalPort 5986 -Action Block
            } catch {
                throw $_
                Write-Host "[-] Error while trying to disable WinRM" -ForegroundColor Red
            }
        }
        Write-Host "[+] WinRM disabled" -ForegroundColor Green


        # setup UAC
        SetUAC


        # disable anonymous logins
        Write-Host "[+] disabling anonymous users..." -ForegroundColor Yellow
        $a = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymous"
        if ($a.restrictanonymous -ne 1) {
            Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymous" -Value 1 -Force
            PrintErr(!$?, "Error while trying to edit the registry key for anonymous logins")
        }
        Write-Host "[+] disabled anonymous users" -ForegroundColor Green

        
        # disable anonymous sam
        Write-Host "[+] disabling anonymous sam touching..." -ForegroundColor Yellow
        $a = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymoussam"
        if ($a.restrictanonymoussam -ne 1) {
            Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name "restrictanonymoussam" -Value 1 -Force
            PrintErr(!$?, "Error while trying to edit the registry key for anonymous access to SAM")
        }
        Write-Host "[+] touching SAM anonymously is disabled" -ForegroundColor Green
        
        # disable editing of the registry through tools
        # note warning this will stop a user from editing the registry all together
        Write-Host "[+] disabling regedit..." -ForegroundColor Yellow
        $a = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name "disableregistrytools"
        if ($a.disableregistrytools -ne 2) {
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name "disableregistrytools" -Value 2 -Force
            PrintErr(!$?, "Error while trying to disable access to regedit")
        }
        Write-Host "[+] registry editing via tools disabled" -ForegroundColor Green

        # TODO enable/install wdac/applocker/or DeepBlue CLi?


        # disable netbios ??????(might be too good)
        $adapters=(Get-WmiObject win32_networkadapterconfiguration)
        foreach ($adapter in $adapters){
            Write-Host $adapter
            $adapter.settcpipnetbios(0)
        }


        # change the password/username of the current admin user
        ChangeCreds($mode)

        
        # update windows if it is in the scope of the rules
        $updates = $(Write-Host "Do you want to update (y): " -ForegroundColor Magenta -NoNewline; Read-Host)
        
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
        "

        [Int]$step = $(Write-Host "What step do you want to undo: " -ForegroundColor Magenta -NoNewline; Read-Host)

        switch ($step) {

        "Exchange" { 
            
            continue;

            # looks for services that have "Exchange"
            if (Get-Service | Select-Object -Property "Name" | Select-String -Pattern "Exchange") {
                ExchangeHard ($mode) 
            }else {
                Write-Host "This machine is not runnning Exchange" -ForegroundColor Yellow
            }
        }

        "Defender" {
            EnableDefenderOn($mode)
        }

        "Psh" {
            Write-Host "[+] changing powershell policy..." -ForegroundColor Yellow
            
            Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope LocalMachine -Confirm
            PrintErr(!$?, "Error in changing the execution policy to Undefined")

            Write-Host "[+] Changed the Powershell policy to Undefined" -ForegroundColor Green
        }

        "WinRM" {

            # enable WinRM
            $enableWinRm = $(Write-Host "enable WinRM? (y) or (n), WARNING his will make your machine vulnerable to RCE: " -ForegroundColor Magenta -NoNewline; Read-Host)
        
            if ($enableWinRm -eq ("y")) {
                Enable-PSRemoting -Force -Confirm
                PrintErr(!$?, "[-] Error in Enabling WinRM")
                    
                Write-Host "[+] Enabled WinRm" -ForegroundColor Green
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
        Write-Host "Welcome to WindowsHard!" -ForegroundColor Green
        Write-Host "Goodluck Today!!!" -ForegroundColor Green
    }else{ 
        Write-Host "No Red Team Allowed!!!" -ForegroundColor Red
        Write-Host "Hope You Have a Good Day!!!" -ForegroundColor Red
        exit
    }


    Write-Host "[+] choose a mode to run the script" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host "[+] harden will start the hardening process on the current machine" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host "[+] control will allow the user to make changes to windows without having to navigate around" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 500
    Write-Host "[+] If any errors are made, a message will be printed to the console in " ForegroundColor Yellow -NoNewline; Write-Host "red" -ForegroundColor Red

    $usermode = $(Write-Host "Harden(h) or Control(c): " -ForegroundColor Magenta -NoNewline; Read-Host)
    if ($usermode -eq ("h")) {
        $mode = "harden";
        Harden($mode)
    } 

    if ($usermode -eq ("c"))  {

        while($true) {
            Write-Host "[+] what would you like to do
            - (efwrule) edit a firewall rule
            - (gpo) Change a group policy (TODO)
            - (chpwd) Change Password
            - (instls) Install Tools
            - (strtls) Start Tools
            - (rmtls) Remove Tools
            - (wp) Install & Run winpeas
            - (disc) Discovery
            - (scan) DefenderScan
            - (Undo) Undo
            - (OSK) OSK Spawn
            - (Wonk) Start Wonk (???)
            - (blkpwd) Bulk Password Change (AD)
            - quit
            "
            
            $choice = $(Write-Host "which mode do you want?: " -ForegroundColor Magenta -NoNewline; Read-Host)
            switch ($choice) {

                "efwrule" {
                    [Int]$portNum = $(Write-Host "which port (num): " -ForegroundColor Magenta -NoNewline; Read-Host)
                    [String]$action = $(Write-Host "(allow) or (block): " -ForegroundColor Magenta -NoNewline; Read-Host)
                    [String]$direction = $(Write-Host "which direction (in) or (out): " -ForegroundColor Magenta -NoNewline; Read-Host)
                    [Bool]$status = $(Write-Host "to create the rule use true or false: " -ForegroundColor Magenta -NoNewline; Read-Host)
                    
                    EditFirewallRule ($portNum, $action, $direction, $status)
                }

                "gpo" {

                    continue

                    # TODO populate this with stuff after group policy is added
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
                    Write-Host "Do you want to perform a dump (y) or (undo), 
                    WARNING (undo) will remove the dump"

                    $discoveryMode = $(Write-Host "What mode?: " -ForegroundColor Magenta -NoNewline; Read-Host)
                    Discovery($discoveryMode)
                }
                
                "scan" {DefenderScan}

                "Undo" {
                    Write-Host "Remember that functions already exist that can undo like RemoveTools" -ForegroundColor Yellow
                    Undo
                }

                "OSK" {
                    continue;
                    # TODO finish fun
                    # This will only work on Windows 10, removed in Windows 11

                    $runUser = $(Write-Host "What user do you want to punish?: " -ForegroundColor Magenta -NoNewline; Read-Host)
                    Start-Job -scriptblock {while (!(Get-Procces -Name "osk.exe")) {Start-Process -FilePath "C:\Windows\System32\osk.exe" -WindowStyle Maximized -RunAs $runUser}}
                }

                "Wonk" {
                    # -- download/compile/run Wonk --

                    # download the version of dotnet required to run wonk
                    # note installing the sdk also installs the runtime
                    Invoke-WebRequest "https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-7.0.202-windows-x64-installer" -OutFile "$env:Userprofile\Desktop\Tools\dotnet7.exe"
                    Invoke-Expression "$env:USERPROFILE\Desktop\Tools\dotnet7.exe"
                    
                    # need to refresh the path again to use the cli
                    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
                    
                    # note url is a placeholder
                    Invoke-WebRequest "https://github.com/VJMumphrey/CompScripts/archive/refs/heads/main.zip" -Outfile "$env:Userprofile\Desktop\wonk.zip"
                    Expand-Archive -LiteralPath "$env:Userprofile\Desktop\wonk.zip" -DestinationPath "$env:USERPROFILE\Desktop\Wonk"

                    Set-Location "$env:Userprofile\Desktop\Wonk"

                    dotnet build -c release

                    # TODO test and make sure this starts as intended
                    Start-Process .\bin\release\net7.0\wonk.exe

                    # creates the scheduled task for wonk persistance
                    $action = New-ScheduledTaskAction -Execute "powershell.exe if (Get-Procces -Name wonk.exe) {}else{.\wonk.exe}"
                    $trigger = New-ScheduledTaskTrigger -RepetitionInterval 1mins
                    $principal = New-ScheduledTaskPrincipal -RequiredPrivilege "Administrator"
                    $settings = New-ScheduledTaskSettingsSet -Hidden
                    $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings

                    Register-ScheduledTask "wakeup" -InputObject $task
                }

                "blkpwd" {
                    # "ADDS" is the main service of AD so it should be in all instances of AD
                    if (Get-Service | Select-Object -Property "Name" | Select-String -Pattern "Active Directory Domain Services" == $true) {
                       Write-Host "[-] Active Directory is not running on this system" -ForegroundColor Yellow
                       Write-Host "if you are trying to change local passwords then use the accounts menu in the control panel" -ForegroundColor Yellow
                       continue
                    }

                    # from Doggle, who was the best at hardening AD
                    Import-Module ActiveDirectory

                    # build the character array for generating the passwords
                    $alph = foreach($i in 65..122) {[char]$i}

                    $users = Get-ADGroupMember -Identity 'Internals'

                    # generate the users new passwords and save them to a csv file
                    foreach($user in $users){
                        for($i = 0; $i -lt 20; $i++) { $pass += $alph | Get-Random }
                        ConvertTo-SecureString -AsPlainText $pass;
                        Set-ADAccountPassword -Identity $user -Reset -NewPassword $pass; 
                        $temp = $user.SamAccountName;
                        Write-Output "$temp,$pass" >> $env:USERPROFILE\Desktop\export.csv
                    }
                }
                
                "quit" {return}

                default {continue}
            } 
        }
    }
}

Main
