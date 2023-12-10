function Main {
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

Main
