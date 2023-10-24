Import-Module ActiveDirectory 

function Harden {
    param (
    
    )

}

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

    

}

Main
