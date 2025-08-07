function Invoke-DomainsToIPs {
    param (
        [string]$InputFile,
        [string]$ParsedDir,
        [string]$OutputDir
    )

    if (-not (Test-Path $InputFile)) {
        Write-Log -Message "Domain list file not found: $InputFile" -Level "ERROR"
        return @()
    }

    $Domains = Get-Content $InputFile | Where-Object { $_.Trim().Length -gt 0 }
    $Results = @()
    $AllIPs  = @()

    Write-Log -Message "Starting domain resolution for $($Domains.Count) domains..." -Level "INFO"

    foreach ($domain in $Domains) {
        try {
            $addresses = [System.Net.Dns]::GetHostAddresses($domain.Trim())
            foreach ($addr in $addresses) {
                if ($addr.AddressFamily -eq 'InterNetwork') {
                    $Results += [PSCustomObject]@{
                        Domain = $domain
                        IP     = $addr.IPAddressToString
                    }
                    $AllIPs += $addr.IPAddressToString
                    Write-Log -Message "Resolved $domain to $($addr.IPAddressToString)" -Level "INFO"
                }
            }
        } catch {
            Write-Log -Message "Failed to resolve domain: $domain — $($_.Exception.Message)" -Level "WARN"
        }
    }

    if ($Results.Count -gt 0) {
        $resolvedPath = (Join-Path $ParsedDir 'resolved_domains.csv')
        $ipListPath = (Join-Path $OutputDir 'resolved_ips.list')

        $Results | Export-Csv -Path $resolvedPath -NoTypeInformation
        $AllIPs | Sort-Object -Unique | Out-File -Encoding ascii -FilePath $ipListPath
        
        Write-Log -Message "Saved resolved domains to $resolvedPath and IPs to $ipListPath" -Level "INFO"
        return $Results
    } else {
        Write-Log -Message "No domains were successfully resolved." -Level "WARN"
        return @()
    }
}
function Invoke-ReverseLookupOnIPs {
    param(
    [string]$InputFile,
    [string]$OutputDir,
    [string]$ParsedDir
    )

    if (-not (Test-Path $InputFile)) {
        Write-Log -Message "Input file not found: $InputFile" -Level "ERROR"
        return @()
    }

    $output = @()
    $hostnames = @()
    $ips = Get-Content $InputFile | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }

    Write-Log -Message "Found $($ips.Count) IP addresses for reverse DNS lookup." -Level "INFO"

    foreach ($ip in $ips) {
        try {
            $hostname = (& dig -x $ip +short).Trim().TrimEnd('.')
            if ($hostname) {
                $output += [PSCustomObject]@{
                    IP       = $ip
                    Hostname = $hostname
                }
                $hostnames += $hostname
                Write-Log -Message "Resolved $ip to $hostname" -Level "INFO"
            } 
        } catch {
            Write-Log -Message "Failed to resolve $ip" -Level "ERROR"
        }
    }

    if ($output.Count -gt 0) {
        $csvPath = (Join-Path $ParsedDir 'reverse_dns.csv')
        $output    | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log -Message "Saved reverse DNS data to $csvPath" -Level "INFO"
    } else {
        Write-Log -Message "No reverse DNS records found." -Level "WARN"
    }

    if ($hostnames.Count -gt 0) {
        $txtPath = (Join-Path $OutputDir 'reverse_dns.txt')
        $hostnames | Out-File -Encoding ascii -FilePath $txtPath
        Write-Log -Message "Saved hostnames to $txtPath" -Level "INFO"    
    } else {
        Write-Log -Message "No hostnames to write." -Level "WARN"
    }
    return $output
}
function Invoke-DNSRecordQuery {
    param(
        [string]$OutputDir,
        [string]$InputFile,
        [string]$ParsedDir,
        [string]$InputType,
        [string[]]$targets,
        $recordTypes = @("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
    )

    if (-not $targets) {
        if ($InputType -eq 'ip') {
            $path = Join-Path $OutputDir 'reverse_dns.txt'
            if (Test-Path $path) {
                $targets = Get-Content $path | Where-Object { $_.Trim().Length -gt 0 }
                Write-Log -Message "Loaded targets from reverse DNS file: $path" -Level "INFO"
            } else {
                Write-Log -Message "Reverse DNS file not found at $path" -Level "WARN"
            }
        }
        elseif ($InputType -eq 'domain') {
            $targets = Get-Content $InputFile | Where-Object { $_.Trim().Length -gt 0 }
            Write-Log -Message "Loaded domains from input file: $InputFile" -Level "INFO"
        } else {
            Write-Log -Message "Domain input file not found at $InputFile" -Level "WARN"
        }
    }

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Log -Message "No targets available to query — input missing or empty" -Level "ERROR"
        return @()
    }

    Write-Log -Message "Starting DNS record queries for $($targets.Count) targets..." -Level "INFO"
    $results = @()

    foreach ($target in $targets) {
        foreach ($type in $recordTypes) {
            try {
                $output = & dig $target $type +short
                if ($output) {
                    foreach ($line in $output) {
                        $results += [PSCustomObject]@{
                            Domain = $target
                            Type   = $type
                            Record = $line
                        }
                        Write-Log -Message "Resolved $type record for $target ➝ $line" -Level "INFO"
                    }
                }
            } catch {
                Write-Log -Message "Failed to query $type record for $target" -Level "ERROR"
            }
        }
    }

    if ($results.Count -gt 0) {
        $csvPath = Join-Path $ParsedDir 'dns_records.csv'
        $txtPath = Join-Path $OutputDir 'dns_records.txt'
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        $results | Out-File -Encoding ascii -FilePath $txtPath
        Write-Log -Message "Saved DNS records to CSV: $csvPath and TXT: $txtPath" -Level "INFO"
        return $results
    } else {
        Write-Log -Message "No DNS records were discovered." -Level "WARN"
        return @()
    }
}
function Invoke-dnsreconScan {
    param(
        [string]$OutputDir,
        [string]$ParsedDir,
        [string]$InputType,
        [string]$InputFile,
        [string[]]$targets,
        [string]$nameserver = "8.8.8.8"
    )

    if (-not $targets) {
        if ($InputType -eq 'ip') {
            $path = Join-Path $OutputDir 'reverse_dns.txt'
            if (Test-Path $path) {
                $targets = Get-Content $path | Where-Object { $_.Trim().Length -gt 0 }
                Write-Log -Message "Loaded IP-derived targets from: $path" -Level "INFO"
            } else {
                Write-Log -Message "Reverse DNS file not found at $path" -Level "WARN"
            }
        }
        elseif ($InputType -eq 'domain') {
            $targets = Get-Content $InputFile | Where-Object { $_.Trim().Length -gt 0 }
            Write-Log -Message "Loaded domain targets from: $InputFile" -Level "INFO"
        } else {
            Write-Log -Message "Domain input file not found: $InputFile" -Level "WARN"
        }
    }

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Log -Message "No domains provided or found — skipping dnsrecon scan" -Level "ERROR"
        return @()
    }

    foreach ($target in $targets) {
        $target = $target.Trim()
        $OutFile_json = Join-Path $OutputDir "dnsrecon_$target.json"
        $OutFile_csv  = Join-Path $ParsedDir "dnsrecon_$target.csv"
        Write-Log -Message "Running dnsrecon for $target" -Level "INFO"
        try {
            $Command = "dnsrecon -n $nameserver -d $target -j $OutFile_json -c $OutFile_csv"
            Invoke-Expression "$Command"
            Write-Log -Message "dnsrecon completed for $target — results saved to JSON and CSV" -Level "INFO"
        } catch {
            Write-Log -Message "dnsrecon failed for $target" -Level "ERROR"
        }
    }
}
function Invoke-ParseDnsRecon {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )
    $JsonPath = Join-Path $PSScriptRoot $OutputDir "dnsrecon_*.json"
    if (-not (Test-Path $JsonPath)) {
        Write-Log -Message "No dnsrecon JSON files found in $OutputDir" -Level "ERROR"
        return @()
    }

    $json = Get-Content $JsonPath -Raw | ConvertFrom-Json
    $records = $json | Where-Object { $_.type -ne "ScanInfo" }

    $parsed = @()

    foreach ($record in $records) {
        $parsed += [PSCustomObject]@{
            Domain  = $record.domain
            Type    = $record.type
            Name    = $record.name
            Address = $record.address
            MName   = $record.mname
        }
    }

    if ($parsed.Count -gt 0) {
        $csvOut = Join-Path $ParsedDir ("parsed_" + (Split-Path $JsonPath -Leaf).Replace(".json", ".csv"))
        $txtOut = Join-Path $OutputDir ("parsed_" + (Split-Path $JsonPath -Leaf).Replace(".json", ".txt"))

        Write-Log -Message "Exporting parsed records to $csvOut" -Level "INFO"
        $parsed | Export-Csv -Path $csvOut -NoTypeInformation
        
        Write-Log -Message "Saving parsed records to $txtOut" -Level "INFO"
        $parsed | Out-File -Encoding ascii -FilePath $txtOut
    } else {
        Write-Log -Message "No records found to export from $JsonPath" -Level "WARNING"
    }
    return $parsed
}
function Invoke-whois {
    param(
        [string]$InputFile,
        [string]$OutputDir,
        [string]$InputType,
        [string]$ParsedDir,
        [string[]]$targets
    )

    $results = @()

    $targets = Get-Content $InputFile | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }
    if ($targets.Count -eq 0) {
        Write-Log -Message "No valid IPs found in input — skipping WHOIS queries." -Level "WARNING"
        return
    }

    
    $OutFile_txt = Join-Path $OutputDir "whois.txt"
    $OutFile_csv = Join-Path $ParsedDir "whois.csv"

    foreach ($target in $targets) {
        Write-Log -Message "Running whois for $target..." -Level "INFO"
        try {
            $Raw = & whois $target
            Add-Content -Path $OutFile_txt -Value "`n=== $target ===`n$Raw"

            # Parse each line individually
            $entry = @{
                IP            = $target
                OrgName       = ''
                OrgID         = ''
                NetRange      = ''
                CIDR          = ''
                Country       = ''
                ContactEmail  = ''
                AbuseEmail    = ''
            }

            foreach ($line in $Raw -split "`n") {
                if ($line -match 'OrgId:\s*(.+)')           { $entry.OrgID         = $matches[1].Trim() }
                elseif ($line -match 'OrgName:\s*(.+)')     { $entry.OrgName       = $matches[1].Trim() }
                elseif ($line -match 'NetRange:\s*(.+)')    { $entry.NetRange      = $matches[1].Trim() }
                elseif ($line -match 'CIDR:\s*(.+)')        { $entry.CIDR          = $matches[1].Trim() }
                elseif ($line -match 'Country:\s*(.+)')     { $entry.Country       = $matches[1].Trim() }
                elseif ($line -match 'OrgTechEmail:\s*(.+)'){ $entry.ContactEmail  = $matches[1].Trim() }
                elseif ($line -match 'OrgAbuseEmail:\s*(.+)'){ $entry.AbuseEmail   = $matches[1].Trim() }
            }

            $results += [PSCustomObject]$entry
        } catch {
            Write-Log -Message "WHOIS lookup failed for $target — $($_.Exception.Message)" -Level "ERROR"
        }
    }
    if ($results.Count -gt 0) {
        Write-Log -Message "Exporting WHOIS results to $OutFile_csv" -Level "INFO"
        $results | Export-Csv -Path $OutFile_csv -NoTypeInformation
    } else {
        Write-Log -Message "No WHOIS results found." -Level "WARNING"
    }
}
