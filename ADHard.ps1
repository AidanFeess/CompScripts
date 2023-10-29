Import-Module ActiveDirectory 

# perform all the harding steps from the docs
# TODO look into running hardening script on all machines in network
function Harden {
    param (
    
    )
    
    $Cred = Get-Credential

    comp_names = @(Get-ADComputer | Select-Object -Property Name)

    # should run WindowsHard on all computers that are listed
    # TODO test to make sure this works
    $Session = New-PSSession -ComputerName comp_names -Credential $Cred
    Invoke-Command -Session $Session -FilePath .\WindowsHard.ps1

    # Setup all the GPOs
    # This needs to include the rule to disable WinRM


    # close all sessions when finished
    Get-PSSession | Remove-PSSession
}

# inventories all the things from AD
# used for inventory and default state
function Discovery {
    param (
    
    )

    # gather a list of all the AD members in the domain
    Get-ADGroupMember | Format-Table > ".\Desktop\users.txt"

    # gather a list of all of the GPOs in the domain
    Get-GPO -All | Format-Table > ".\Desktop\gpo.txt"

}

# perform a bulk password change for the network
# generates a csv for submitting
function BlkPasswd {
    param (

    )
    
    Write-Host "[+] Changing all of the passwords and writing them to a csv..." -ForegroundColor Green
    # build the character array for generating the passwords
    $alph = foreach($i in 65..122) {[char]$i}

    $users = Get-ADGroupMember -Identity 'Internals'

    # generate the users new passwords and save them to a csv file
    foreach($user in $users) {
        for($i = 0; $i -lt 20; $i++) { $pass += $alph | Get-Random }
        ConvertTo-SecureString -AsPlainText $pass;
        if ($user.name = "blackteam") {
            Write-Host "nah"
            continue;
        }
        Set-ADAccountPassword -Identity $user -Reset -NewPassword $pass; 
        PrintErr(!$?,"Error in changing the password for $user, make sure you have right privs")
        $temp = $user.SamAccountName;
        $PasswordProgress = @{
                Activity         = 'Changing Password'
                PercentComplete  = $j
                Status           = 'Progress'
                CurrentOperation = "$user"
        }
        Write-Progress @PasswordProgress
        Write-Output "$temp,$pass" >> $env:USERPROFILE\Desktop\export.csv
    }

    Write-Host "[+] Bulk password change is complete and csv file is located on your desktop" -ForegroundColor Green
}

function Main {
    param (

    )

    $choice = $(Write-Host "which mode do you want?: " -ForegroundColor Magenta -NoNewline; Read-Host)
    switch ($choice) {

    "BlkPasswd" {
        BlkPasswd
    }
    "Harden" {
        Harden
    }

    "Discovery" {
        Discovery
    }

    

    }
}

Main
