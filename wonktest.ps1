#
# Highly Experimental Prototype
#

# bad actions get a user wonked
enum OffensiveActions {
    TRYADMINACCESS = 422
    CHANGE_SETTINGS
    EDIT_REGISTRY_VALUES = 4657
    USE_ADMIN_PRIVS = 4674
    TOUCHING_SAM = 4661
    ACCESS_TO_SYSTEM = 621
}

# ports that are monitored for remote connections
enum RemoteControlPorts {
    SSH = 22
    RDP = 3389
    VNC = 5900
    WINRM_HTTP = 5985
    WINRM_HTTPS = 5986
}

# used to keep track of which users are logged on
function Eventlog {
    param (

    )

    $results = [System.Collections.Generic.List[object]]::new()
    $result = Get-WinEvent -LogName Security -Id OffensiveActions -Newest 10
    $results = foreach($obj in $result) {
        $obj = [PSCustomObject]@{
            Time = $_.TimeGenerated
            # Machine = $_.ReplacementStrings[6]
            User = $_.ReplacementStrings[5]
            Access = $_.ReplacementStrings[10]
            # SourceAddr = $_.ReplacementStrings[18]
        }
        $results.AddRange((obj))
    }

    $results | Select-Object Time, User, Access | Export-Csv -NoTypeInformation -Path .\Access_Log.csv
}


function Main {
    param (

    )

    # all of this might need to be multithreaded

    # gather users on the system
    # $local_users = @(Get-LocalUser)
    # $ad_users = @(Get-ADGroupMember -Group 'Internals')
    # $users = ($local_users + $ad_users)

    while($true) {

        # gets all the users logged onto a computer
        # TODO fix not consistant
        # TODO parse for just usernames
        $loggedIn = Get-Process -IncludeUserName | Select-Object UserName, SessionId | Sort-Object -Unique

        # gather bad events for users
        foreach ($user in $loggedIn) {
            $bad_users += foreach($event in OffensiveActions ) {Get-WinEvent LogName Security -Newest 5 -Id $event -UserName $user }
        }

        # logoff specfic users (from Windows 2016 version of powershell)
        # $session = Get-RDUserSession | Select-Object -Pattern "$badusername"
        # or 
        $sessionId = ((quser | Where-Object { $_ -match $badusername }) -split ' +')[2]
        logoff $sessionId
        Invoke-RDUserLogoff $sessionId
    }
}

Main
