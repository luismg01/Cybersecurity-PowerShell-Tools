# File: Invoke-BasicADScanner.ps1
# Description: Escáner básico para identificar configuraciones potencialmente débiles en Active Directory.

function Invoke-BasicADScanner {
    param(
        [string]$OutputPath = ".\AD_Audit_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    )

    # Intentar importar el módulo de Active Directory y manejar errores
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Error "El módulo Active Directory no está disponible o no se pudo importar. Este script requiere los RSAT tools y privilegios adecuados."
        return
    }

    $Results = @()

    # 1. Cuentas de usuario que no expiran nunca (riesgo de contraseñas permanentes)
    Write-Host "[+] Escaneando cuentas con contraseñas que no expiran..." -ForegroundColor Yellow
    $NeverExpire = Get-ADUser -Filter * -Properties PasswordNeverExpires, Enabled, DistinguishedName | 
                   Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true } |
                   Select-Object Name, SamAccountName, DistinguishedName
    foreach ($User in $NeverExpire) {
        $Results += [PSCustomObject]@{
            Categoria      = "Contraseña_Nunca_Expira"
            Objeto         = $User.Name
            SamAccountName = $User.SamAccountName
            Detalle        = $User.DistinguishedName
            Riesgo         = "Medio"
        }
    }

    # 2. Cuentas deshabilitadas (pueden ser un vector de ataque si se reactivan)
    Write-Host "[+] Escaneando cuentas deshabilitadas..." -ForegroundColor Yellow
    try {
        $DisabledAccounts = Search-ADAccount -AccountDisabled -UsersOnly -ErrorAction Stop |
                            Select-Object Name, SamAccountName, DistinguishedName
    } catch {
        Write-Warning "Error al consultar cuentas deshabilitadas: $_"
        $DisabledAccounts = @()
    }
    foreach ($User in $DisabledAccounts) {
        $Results += [PSCustomObject]@{
            Categoria      = "Cuenta_Deshabilitada"
            Objeto         = $User.Name
            SamAccountName = $User.SamAccountName
            Detalle        = $User.DistinguishedName
            Riesgo         = "Bajo"
        }
    }

    # 3. Cuentas bloqueadas (puede indicar intentos de fuerza bruta)
    Write-Host "[+] Escaneando cuentas bloqueadas..." -ForegroundColor Yellow
    try {
        $LockedAccounts = Search-ADAccount -LockedOut -UsersOnly -ErrorAction Stop |
                          Select-Object Name, SamAccountName, DistinguishedName
    } catch {
        Write-Warning "Error al consultar cuentas bloqueadas: $_"
        $LockedAccounts = @()
    }
    foreach ($User in $LockedAccounts) {
        $Results += [PSCustomObject]@{
            Categoria      = "Cuenta_Bloqueada"
            Objeto         = $User.Name
            SamAccountName = $User.SamAccountName
            Detalle        = $User.DistinguishedName
            Riesgo         = "Informativo"
        }
    }

    # 4. Usuarios inactivos (cuentas huérfanas que deberían deshabilitarse)
    Write-Host "[+] Escaneando cuentas inactivas (últimos 90 días)..." -ForegroundColor Yellow
    try {
        $InactiveAccounts = Search-ADAccount -AccountInactive -TimeSpan (New-TimeSpan -Days 90) -UsersOnly -ErrorAction Stop |
                            Where-Object { $_.Enabled -eq $true } |
                            Select-Object Name, SamAccountName, LastLogonDate, DistinguishedName
    } catch {
        Write-Warning "Error al consultar cuentas inactivas: $_"
        $InactiveAccounts = @()
    }
    foreach ($User in $InactiveAccounts) {
        $Results += [PSCustomObject]@{
            Categoria      = "Cuenta_Inactiva"
            Objeto         = $User.Name
            SamAccountName = $User.SamAccountName
            Detalle        = "Último inicio de sesión: $($User.LastLogonDate)"
            Riesgo         = "Medio"
        }
    }

    # Asegurar que la carpeta de salida existe
    $outDir = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path -Path $outDir)) {
        try {
            New-Item -Path $outDir -ItemType Directory -Force | Out-Null
        } catch {
            Write-Warning "No se pudo crear el directorio de salida '$outDir'. Guardando en el directorio actual."
            $OutputPath = ".\AD_Audit_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        }
    }

    # Exportar resultados a CSV
    try {
        $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
        Write-Host "[!] Escaneo completado. Resultados guardados en: $OutputPath" -ForegroundColor Green
    } catch {
        Write-Error "Error al exportar los resultados a CSV: $_"
    }

    return $Results
}

# Ejecutar la función sólo si el script se ejecuta directamente (no al dot-source o importar)
if ($PSCommandPath -and $MyInvocation.MyCommand.Path -and ($PSCommandPath -eq $MyInvocation.MyCommand.Path)) {
    Invoke-BasicADScanner
}
