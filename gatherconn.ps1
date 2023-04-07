# kill all Active TCP remote connections
$activeConnections = @(Get-NetTCPConnection -State Established | Select-Object -Property OwningProcess, LocalPort)