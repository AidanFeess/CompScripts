# read the security event log for logons and logoffs output to a csv
$results = [System.Collections.Generic.List[object]]::new()
$result = Get-EventLog -LogName Security -InstanceId 4624, 4647 -Newest 10
$results = foreach($obj in $result) {
    [PSCustomObject]@{
    Time = $_.TimeGenerated
    # Machine = $_.ReplacementStrings[6]
    User = $_.ReplacementStrings[5]
    Access = $_.ReplacementStrings[10]
    # SourceAddr = $_.ReplacementStrings[18]
    }

    $results.AddRange((obj))
    
}

# TODO system that scans the csv to update the info with current results

$results | Select-Object Time, User, Access | Export-Csv -NoTypeInformation -Path .\Access_Log.csv

# logoff all users
# Invoke-CimMethod -ClassName Win32_Operatingsystem -MethodName Win32Shutdown -Arguments @{ Flags = 4 }

# logoff specfic users (from Windows 2016 version of powershell)
$sessions = Get-RDUserSession | Select-Object -Pattern "$badusername"
$sessionId = ((quser | Where-Object { $_ -match $userName }) -split ' +')[2]
Invoke-RDUserLogoff $sessionId
