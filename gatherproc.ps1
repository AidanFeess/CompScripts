# gather the running process on a system with the username tagged to it

$owners = @{}
Get-WmiObject win32_process | Foreach-Object {$owners[$_.handle] = $_.getowner().user} -ErrorAction SilentlyContinue

get-process | Select-Object processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}} -ErrorAction SilentlyContinue
