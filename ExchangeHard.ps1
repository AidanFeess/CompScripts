# perform tasks to harden Exchange
function Main {
    param (
        $mode
    )
    
    Import-Module ExchangePowerShell

    if ($mode = "undo") {
        # do the hardening
    }

    if ($mode = "undo") {
        # do the unhardening
    }
}

Main
