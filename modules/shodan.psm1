function Invoke-ShodanScan {
    param(
        [string]$InputFile,
        [string]$OutputDir,
        [string]$ParsedDir,
        [string[]]$targets,
        [string]$ApiKey
    )

    $results = @()
    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    if ($targets.Count -eq 0) {
        Write-Log -Message "No valid IPs found in input — skipping Shodan queries." -Level "WARNING"
        return
    }

    $OutFile_txt = Join-Path $OutputDir "shodan_raw.txt"
    $OutFile_csv = Join-Path $ParsedDir "shodan.csv"

    foreach ($target in $targets) {
        Write-Log -Message "Querying Shodan for $target..." -Level "INFO"
        $url = "https://api.shodan.io/shodan/host/$target?key=$ApiKey"

        try {
            $response = Invoke-RestMethod -Uri $url -Method Get
            Add-Content -Path $OutFile_txt -Value "`n=== $target ===`n$(ConvertTo-Json $response -Depth 5)"

            $entry = @{
                IP         = $response.ip_str
                Org        = $response.org
                ISP        = $response.isp
                OS         = $response.os
                Ports      = ($response.ports -join ",")
                Hostnames  = ($response.hostnames -join ",")
                Country    = $response.country_name
                City       = $response.city
                Vulns      = ($response.vulns -join ",")
            }

            $results += [PSCustomObject]$entry
        } catch {
            Write-Log -Message "Shodan query failed for $target — $($_.Exception.Message)" -Level "ERROR"
        }
    }

    if ($results.Count -gt 0) {
        Write-Log -Message "Exporting Shodan results to $OutFile_csv" -Level "INFO"
        $results | Export-Csv -Path $OutFile_csv -NoTypeInformation
    } else {
        Write-Log -Message "No Shodan results found." -Level "WARNING"
    }
}