<#
.SYNOPSIS
    Extracts and analyzes critical Windows Security events for threat detection.

.DESCRIPTION
    Compatible with PowerShell 5.1. Retrieves events by IDs (default: broad list of detection-relevant IDs),
    tries to extract user and other relevant fields from the event XML, and supports CSV/JSON export.
    If initially no events match the requested IDs, the script will discover the top event IDs in the period
    and optionally auto-retry using the top N IDs (configurable).
#>

# --- Script-level parameters (these are the parameters you pass to the .ps1 file) ---
param(
    [int]$Days = 1,
    [string]$LogName = "Security",
    [int[]]$EventIDs = $null,
    [int]$MaxEvents = 1000,
    [string]$OutputPath = $null,
    [int]$TopNForDiscovery = 20,
    [int]$AutoRetryTopN = 5
)

function Get-CriticalSecurityEvents {
    [CmdletBinding()]
    param(
        [int]$Days = 1,
        [string]$LogName = "Security",
        [int[]]$EventIDs = $null,
        [int]$MaxEvents = 1000,
        [string]$OutputPath = $null,
        [int]$TopNForDiscovery = 20,
        [int]$AutoRetryTopN = 5
    )

    # --- Require elevated privileges to read the Security log ---
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Please run PowerShell as Administrator to read the 'Security' log."
        return
    }

    # --- Description map (detection-relevant event IDs) ---
    $EventIDMap = @{
        4624 = "Successful logon (Logon)"
        4625 = "Failed logon (Failure)"
        4634 = "Logoff"
        4648 = "Logon using explicit credentials"
        4672 = "Special privileges assigned to new logon"
        4688 = "Process creation"
        4689 = "Process termination"
        4697 = "Service installed"
        4698 = "Scheduled task created"
        4699 = "Scheduled task deleted"
        4702 = "Scheduled task updated"
        4719 = "System audit policy was changed"
        4720 = "User account created"
        4722 = "User account enabled"
        4723 = "Attempt to change password"
        4724 = "Password reset"
        4725 = "User account disabled"
        4726 = "User account deleted"
        4728 = "Member added to global group"
        4729 = "Member removed from global group"
        4732 = "Member added to privileged local group"
        4733 = "Member removed from privileged local group"
        4738 = "User account modified"
        4740 = "Account locked out"
        4768 = "Kerberos TGT request"
        4769 = "Kerberos Service ticket request"
        4771 = "Kerberos pre-authentication failure"
        4776 = "NTLM authentication"
        4798 = "User's local group membership enumerated"
        4799 = "Users enumerated in a local group"
        1102 = "Audit log cleared"
        4670 = "Permissions on an object were changed"
        5136 = "Directory Service object modified (DC)"
        5137 = "Directory Service object created"
        5138 = "Directory Service object deleted/undeleted"
        5145 = "Network share object accessed (SMB)"
        5156 = "Network traffic allowed (firewall) - possible lateral movement"
    }

    # If EventIDs not provided, use all keys from the map
    if ($null -eq $EventIDs -or $EventIDs.Count -eq 0) {
        $EventIDs = $EventIDMap.Keys
    }

    Write-Host "[+] Searching events in '$LogName' (IDs: $($EventIDs -join ', ')) from the last $Days day(s)..." -ForegroundColor Yellow

    $filter = @{
        LogName   = $LogName
        Id        = $EventIDs
        StartTime = (Get-Date).AddDays(-$Days)
    }

    try {
        # Read events with a maximum cap
        $Events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        Write-Warning "Error reading events for the requested filter: $_"
        $Events = @()
    }

    # If no events found, show top IDs and optionally retry with top AutoRetryTopN IDs
    if ($null -eq $Events -or $Events.Count -eq 0) {
        Write-Host "[!] No events found for the requested IDs in the specified period." -ForegroundColor Red
        Write-Host "[*] Displaying the most frequent event IDs in the period ($Days day(s)) to help you choose:" -ForegroundColor Yellow

        try {
            $top = Get-WinEvent -FilterHashtable @{LogName=$LogName; StartTime=(Get-Date).AddDays(-$Days)} -MaxEvents $MaxEvents -ErrorAction Stop |
                   Group-Object Id |
                   Sort-Object Count -Descending |
                   Select-Object -First $TopNForDiscovery @{n='Id';e={[int]$_.Name}}, Count

            if ($top) { $top | Format-Table -AutoSize } else { Write-Host "There are no events in the 'Security' log in the specified period." -ForegroundColor Red }
        } catch {
            Write-Warning "Could not list the top IDs: $_"
        }

        # Auto-retry using top N IDs (if any) to help the user — run only once to avoid loops
        if ($AutoRetryTopN -gt 0) {
            try {
                $retryList = Get-WinEvent -FilterHashtable @{LogName=$LogName; StartTime=(Get-Date).AddDays(-$Days)} -MaxEvents $MaxEvents -ErrorAction Stop |
                             Group-Object Id |
                             Sort-Object Count -Descending |
                             Select-Object -First $AutoRetryTopN @{n='Id';e={[int]$_.Name}}

                if ($retryList) {
                    $retryIDs = $retryList | ForEach-Object { $_.Id } 
                    Write-Host "[*] Auto-retrying collection using top $AutoRetryTopN IDs: $($retryIDs -join ', ')" -ForegroundColor Yellow
                    $filter.Id = $retryIDs
                    try {
                        $Events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
                    } catch {
                        Write-Warning "Auto-retry failed: $_"
                        $Events = @()
                    }
                }
            } catch {
                Write-Warning "Auto-retry discovery failed: $_"
            }
        }

        if ($null -eq $Events -or $Events.Count -eq 0) {
            Write-Host "[!] After auto-retry there are still no events to process. Exiting." -ForegroundColor Red
            return @()
        }
    }

    # Process events and extract important fields
    $Results = @()
    foreach ($ev in $Events) {
        $xml = $null
        try { $xml = [xml]$ev.ToXml() } catch {}

        # Try to extract user and other common fields from XML EventData
        $user = $null
        $accountDomain = $null
        $processName = $null
        $objectName = $null

        if ($xml) {
            $datas = $null
            try { $datas = $xml.Event.EventData.Data 2>$null } catch {}
            if ($datas) {
                # Possible fields for user/account
                $possibleUserNames = @('TargetUserName','TargetUser','SubjectUserName','AccountName','Account','UserName')
                foreach ($n in $possibleUserNames) {
                    $match = $datas | Where-Object { $_.Name -eq $n }
                    if ($match -and $match.'#text') { $user = $match.'#text'; break }
                }

                # Domain
                $possibleDomain = @('TargetDomainName','AccountDomain','DomainName','SubjectDomainName')
                foreach ($n in $possibleDomain) {
                    $match = $datas | Where-Object { $_.Name -eq $n }
                    if ($match -and $match.'#text') { $accountDomain = $match.'#text'; break }
                }

                # Process fields (e.g. 4688, 4689)
                $possibleProcess = @('NewProcessName','ProcessName','Process')
                foreach ($n in $possibleProcess) {
                    $match = $datas | Where-Object { $_.Name -eq $n }
                    if ($match -and $match.'#text') { $processName = $match.'#text'; break }
                }

                # Object name / resource
                $possibleObject = @('ObjectName','ResourceName','ShareName','Object')
                foreach ($n in $possibleObject) {
                    $match = $datas | Where-Object { $_.Name -eq $n }
                    if ($match -and $match.'#text') { $objectName = $match.'#text'; break }
                }
            }
        }

        # Fallback: regex from the message if XML did not yield a user
        if ($null -eq $user -and $ev.Message) {
            if ($ev.Message -match '((?i)Account Name|Nombre de usuario|Target User)\s*[:\-]\s*(\S+)') {
                $user = $matches[2]
            }
        }

        # Determine a simple result status
        $resultStatus = "INFORMATIONAL"
        switch ($ev.Id) {
            4625 { $resultStatus = "FAILURE" }
            1102 { $resultStatus = "AUDIT_LOG_CLEARED" }
            4740 { $resultStatus = "LOCKED_OUT" }
            4672 { $resultStatus = "HIGH_PRIVILEGES" }
            default { $resultStatus = "INFORMATIONAL" }
        }

        # Prepare a safe message preview
        $raw = ""
        if ($ev.Message) {
            $raw = $ev.Message -replace "`r`n", " | "
            if ($raw.Length -gt 400) {
                try { $raw = $raw.Substring(0,400) } catch {}
            }
        }

        $obj = [PSCustomObject]@{
            ID            = $ev.Id
            Description   = if ($EventIDMap.ContainsKey($ev.Id)) { $EventIDMap[$ev.Id] } else { "" }
            TimeCreated   = $ev.TimeCreated
            ComputerName  = $ev.MachineName
            UserName      = if ($user) { $user } else { '' }
            Domain        = if ($accountDomain) { $accountDomain } else { '' }
            Process       = if ($processName) { $processName } else { '' }
            Resource      = if ($objectName) { $objectName } else { '' }
            Result        = $resultStatus
            RawMessage    = $raw
            Channel       = $ev.LogName
            RecordId      = $ev.RecordId
        }

        $Results += $obj
    }

    # Display summary
    $count = $Results.Count
    Write-Host "[!] Found $count matching event(s)." -ForegroundColor Green

    # Export to file if requested (supports .csv and .json)
    if ($OutputPath) {
        try {
            $outDir = Split-Path -Path $OutputPath -Parent
            if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path -Path $outDir)) {
                New-Item -Path $outDir -ItemType Directory -Force | Out-Null
            }

            $ext = [System.IO.Path]::GetExtension($OutputPath).ToLower()
            if ($ext -eq ".json") {
                $Results | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
            } else {
                # Default to CSV
                $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
            }
            Write-Host "[+] Results exported to: $OutputPath" -ForegroundColor Green
        } catch {
            Write-Warning "Could not export results: $_"
        }
    }

    return $Results
}

# If the file is executed directly, invoke the function with parameters provided to the script.
# This ensures that parameters passed to the .ps1 file are forwarded to the inner function.
if ($PSCommandPath -and $MyInvocation.MyCommand.Path -and ($PSCommandPath -eq $MyInvocation.MyCommand.Path)) {
    # Forward script parameters to the function using the script-level variables
    Get-CriticalSecurityEvents -Days $Days -LogName $LogName -EventIDs $EventIDs -MaxEvents $MaxEvents -OutputPath $OutputPath -TopNForDiscovery $TopNForDiscovery -AutoRetryTopN $AutoRetryTopN
}