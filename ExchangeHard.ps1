Import-Module ExchangePowerShell

# perform tasks to harden Exchange
function Main {
    param (
        $mode
    )

    $hardenExch = $(Write-Host "[?] Do you want to Harden Exchange (y): " -ForegroundColor Magenta -NoNewline; Read-Host)
    if ($hardenExch -eq ("y")) {
        # checking for services of exchange Exchange seems to work the best
        if (Get-Service | Select-Object -Property "Name" | Select-String -Pattern "Exchange") {
            ExchangeHard($mode)
        }
    }

    if ($mode = "undo") {
        # do the hardening
    }

    if ($mode = "undo") {
        # do the unhardening
    }
}

Main
