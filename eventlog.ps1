# read the security event log for logons and logoffs output to a csv
$results = [System.Collections.Generic.List[object]]::new()
$result = Get-EventLog -LogName Security -InstanceId 4624, 4647 -Newest 10
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

# TODO system that scans the csv to update the info with current results
[Int]$lines = (Get-Content -Path .\Access_Log.csv).Length
$file = Get-Content -Path .\Access_Log.csv

foreach ($line in $lines) {
    $line = Select-Object -Property "$_.Time,$_.User"
    if ($line | Select-String -Pattern "$_.User" in $results) {
        continue
    } else {
        # remove the line from the csv
        Remove-Item $line
    }

$results | Select-Object Time, User, Access | Export-Csv -NoTypeInformation -Path .\Access_Log.csv

# get all processes running on the client along with the username associated (admin)
$proc = Get-Proccess -Inlcude Username | Select-Object -Property Username, Id

# logoff all users
# Invoke-CimMethod -ClassName Win32_Operatingsystem -MethodName Win32Shutdown -Arguments @{ Flags = 4 }

# logoff specfic users (from Windows 2016 version of powershell)
$sessions = Get-RDUserSession | Select-Object -Pattern "$badusername"
$sessionId = ((quser | Where-Object { $_ -match $userName }) -split ' +')[2]
Invoke-RDUserLogoff $sessionId
