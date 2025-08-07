function Invoke-NmapSNMP {
    param (
        [string]$OutputDir,
        [string[]]$targets,
        [string]$Scripts = "snmp-* and not snmp-brute",
        [string]$scriptArgs = "snmpcommunity=public"
    )

    $rdpPorts = @(21)

    Write-Log -Message "Starting SNMP scan routine..." -Level "INFO"

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        Write-Log -Message "Evaluating target ${ip}:$port" -Level "INFO"

        if (-not ($rdpPorts -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port - port not in scan list." -Level "INFO"
            continue
        }

        $outfile = Join-Path $OutputDir "nmap_snmp_${ip}_$port.xml"
        Write-Log -Message "Running Nmap SNMP scan on ${ip}:$port" -Level "INFO"

        try {
            nmap -Pn -sV -p $port --script $Scripts --script-args $scriptArgs  ${ip} -oX $outfile
            Write-Log -Message "Scan completed for ${ip}:$port - output saved to $outfile" -Level "INFO"
        } catch {
            Write-Log -Message "Nmap scan failed for {$ip}:$port - $($_.Exception.Message)" -Level "ERROR"
        }
    }
    Write-Log -Message "SNMP scan routine completed." -Level "INFO"
}
function Invoke-NmapSNMPParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Write-Log -Message "Starting SNMP scan parser routine..." -Level "INFO"

    $ParsedResults = @()

    Get-ChildItem $OutputDir -Filter "nmap_snmp_*.xml" | ForEach-Object {
        try {
            [xml]$xml = Get-Content $_.FullName -Raw
            $hostNode     = $xml.nmaprun.host
            if (-not $hostNode) { return }

            $ipaddress = $hostNode.address.addr
            $ports     = $hostNode.ports.port

            foreach ($port in $ports) {
                $portid   = $port.portid
                $protocol = $port.protocol
                $state    = $port.state.state

                $service = $port.service

                $serviceName     = $service.name
                $serviceProduct  = if ($service.product -is [System.Array]) { $service.product -join ", " } else { $service.product }
                $serviceHostname = if ($service.hostname -is [System.Array]) { $service.hostname -join ", " } else { $service.hostname }
                $serviceOS       = $service.ostype
                $serviceMethod   = $service.method
                $serviceConf     = $service.conf
                $serviceCPE      = if ($service.cpe -is [System.Array]) { $service.cpe -join ", " } else { $service.cpe }

                $scripts = $port.script

                foreach ($script in $scripts) {
                    $scriptId = $script.id
                    $rawOutput = $script.output

                    $formattedOutput = if ($rawOutput.'#text') {
                        $rawOutput.'#text'
                    } elseif ($rawOutput -is [System.Array]) {
                        $rawOutput | ForEach-Object { $_.InnerText } -join " | "
                    } elseif ($rawOutput.InnerText) {
                        $rawOutput.InnerText
                    } else {
                        $rawOutput.ToString()
                    }

                    $formattedOutput = $formattedOutput -replace "`r`n|\n|\r", " | "

                    $ParsedResults += [PSCustomObject]@{
                        IP              = $ipaddress
                        Port            = $portid
                        Protocol        = $protocol
                        State           = $state
                        ServiceName     = $serviceName
                        Product         = $serviceProduct
                        Hostname        = $serviceHostname
                        OS              = $serviceOS
                        DetectionMethod = $serviceMethod
                        Confidence      = $serviceConf
                        CPE             = $serviceCPE
                        Script          = $scriptId
                        Output          = $formattedOutput
                    }
                }
            }
            Write-Log -Message "Parsed SNMP data from ${ipaddress}:$($portid)" -Level "INFO"
        }
        catch {
            Write-Log -Message "Failed to parse $($_.Name): $($_.Exception.Message)" -Level "ERROR"
        }
    }
    $ParsedResults | ForEach-Object {
        foreach ($property in $_.PSObject.Properties) {
            if (-not $property.Value -or [string]::IsNullOrWhiteSpace($property.Value)) {
                $property.Value = "N/A"
            }
        }
    }
    if ($ParsedResults.Count -gt 0) {
        $csvPath = (Join-Path $ParsedDir 'nmap_snmp.csv')
        $ParsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported SNMP results to $csvPath" -Level "INFO"
    } else {
        Write-Log -Message "No SNMP scan results found in $OutputDir" -Level "WARNING"
    }
    Write-Log -Message "SNMP scan parser routine completed." -Level "INFO"
}