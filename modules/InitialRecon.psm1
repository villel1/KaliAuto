function Invoke-NmapPingSweep {
    param(
        [string]$InputFile,
        [string]$OutputDir
    )

    if (-not (Test-Path $InputFile)) {
        Write-Log -Message "Input file not found: $InputFile" -Level "ERROR"
        return @()
    }

    $liveHostsFile = Join-Path $OutputDir 'live_hosts.xml'
    $command = "nmap -sn -iL `"$InputFile`" -oX `"$liveHostsFile`""

    Write-Log -Message "Executing ping sweep with command: $command" -Level "INFO"

    try {
        Invoke-Expression $command
        Write-Log -Message "Ping sweep completed. Results saved to: $liveHostsFile" -Level "INFO"
        return $liveHostsFile
    } catch {
        Write-Log -Message "Ping sweep failed: $($_.Exception.Message)" -Level "ERROR"
        return @()
    }
}
function Invoke-hostsParser {
    param(
        [string]$OutputDir,
        [string]$ParsedDir
    )

    $liveHostsFile = Join-Path $OutputDir 'live_hosts.xml'
    Write-Log -Message "Extracting live hosts from Nmap output..." -Level "INFO"

    if (-not (Test-Path $liveHostsFile)) {
        Write-Log -Message "No XML file found at $liveHostsFile. Skipping host parsing." -Level "ERROR"
        return @()
    }

    [xml]$xml = Get-Content $liveHostsFile

    if ($xml.nmaprun.host.count -eq 0) {
        Write-Log -Message "No live hosts found in Nmap output. Skipping Masscan." -Level "WARN"
        return @()
    }

    $liveHostsClean = @()
    foreach ($nmapHost in $xml.nmaprun.host) {
        $addr = $nmapHost.address.addr
        if ($addr) {
            $cleanIP = $addr.Trim() -replace "`r?`n", ''
            $liveHostsClean += $cleanIP
            Write-Log -Message "Found live host: $cleanIP" -Level "INFO"
        }
    }

    if ($liveHostsClean.Count -gt 0) {
        $liveHostsClean | Out-File -Encoding ascii -FilePath (Join-Path $OutputDir 'live_hosts.txt')
        $liveHostsClean | ForEach-Object { [PSCustomObject]@{ IP = $_ } } | Export-Csv -Path (Join-Path $ParsedDir 'live_hosts.csv') -NoTypeInformation
        Write-Log -Message "Saved live hosts to $txtPath and $csvPath" -Level "INFO"
        return $liveHostsClean
    } else {
        Write-Log -Message "No valid IP addresses extracted from Nmap output." -Level "WARN"
    }
}
function Invoke-Masscan {
    param(
        [string]$OutputDir,
        [string[]]$targets,
        [string]$PortRange = "1-65535",
        [string]$Rate = '1000'
    )

    Write-Log -Message "Preparing to run Masscan..." -Level "INFO"
    
    $masscanOutputFile = Join-Path $OutputDir 'masscan_output.xml'
    
    if (-not $targets) {
        $targets = (Join-Path $OutputDir 'live_hosts.txt')
        Write-Log -Message "Target list not provided. Defaulting to: $targets" -Level "WARN"
    }

    if (-not (Test-Path $targets)) {
        Write-Log -Message "Masscan input file not found at path: $targets" -Level "ERROR"
        return @()
    }

    $command = "sudo masscan -p$PortRange --rate=$Rate -iL $targets -oX $masscanOutputFile"
    Write-Log -Message "Executing command: $command" -Level "INFO"
    Invoke-Expression $command

    Write-Log -Message "Masscan scan complete. Output saved to $masscanOutputFile" -Level "INFO"
    return $masscanOutputFile
}
function Invoke-masscanParser {
    param(
        [string]$OutputDir,
        [string]$ParsedDir
        )

     Write-Log -Message "Parsing Masscan output..." -Level "INFO"
    
    $masscanOutputFile = Join-Path $OutputDir 'masscan_output.xml'

    if (-not (Test-Path $masscanOutputFile)) {
    Write-Log -Message "No XML file found at $masscanOutputFile. Parsing aborted." -Level "ERROR"
    return @()
    }
    [xml]$xml = Get-Content $masscanOutputFile
    $results = @()
    $IPPortFile = @()

    if ($xml.nmaprun.host.count -eq 0) {
        Write-Log -Message "No open ports found in the Masscan XML output." -Level "WARN"
        return $results
    }
    foreach ($hostNode in $xml.nmaprun.host) {
        $ip = $hostNode.address.addr
        foreach ($port in $hostNode.ports.port) {
            $results += [PSCustomObject]@{
                IP = [string]$ip
                Port = [int]$port.portid
                Protocol = [string]$port.protocol
            }
            $IPPortFile += "${ip}:$($port.portid)"
            Write-Log -Message "Discovered ${ip}:${port.portid} (${port.protocol})" -Level "INFO"
        }
    }

    if ($results.Count -gt 0) {
        $results | Sort-Object IP, Port | Format-List | Out-File -Encoding ascii -Filepath (Join-Path $OutputDir 'masscan_results.txt')
        $results | Export-Csv -Path (Join-Path $ParsedDir 'masscan_results.csv') -NoTypeInformation 
        
        Write-Log -Message "Saved structured Masscan results to $resultsFile and CSV to $csvFile" -Level "INFO"
    }

    if ($IPPortFile.Count -gt 0) {    
        $IPPortFile | Sort-Object | Out-File (Join-Path $OutputDir 'ip_ports.list') -Encoding ascii
        Write-Log -Message "Saved structured Masscan results to $resultsFile and CSV to $csvFile" -Level "INFO"
    }
    return $results
}