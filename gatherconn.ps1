# kill all Active TCP remote connections
$activeConnections = @(Get-NetTCPConnection -State Established | Select-Object -Property OwningProcess, LocalPort)

foreach ($x in $activeConnections) {
    if ($x.LocalPort -eq 22, 5900, 3389) {
        Stop-Process $x.OwningProcess
    }
}
