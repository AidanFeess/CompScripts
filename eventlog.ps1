# read the security event log for logons and output to a csv
$result = Get-EventLog -LogName Security -InstanceId 4624 |
ForEach-Object {
    [PSCustomObject]@{
    Time = $_.TimeGenerated
    Machine = $_.ReplacementStrings[6]
    User = $_.ReplacementStrings[5]
    Access = $_.ReplacementStrings[10]
    SourceAddr = $_.ReplacementStrings[18]
    }
}

$result | Select-Object Time, Machine, User, Access, SourceAddr | Export-Csv -NoTypeInformation -Path .\Access_Log.csv
