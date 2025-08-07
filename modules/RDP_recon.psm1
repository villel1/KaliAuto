function Invoke-NmapRDPScan {
    param (
        [string]$OutputDir,
        [string[]]$targets,
        [string]$Scripts = "rdp-enum-encryption,rdesktop-vuln-cve2012-2526,rdesktop-vuln-cve2012-2527,rdesktop-vuln-cve2012-2528,rdesktop-vuln-cve2012-2529,rdesktop-vuln-cve2012-2530,rdesktop-vuln-cve2012-2531,rdesktop-vuln-cve2012-2532,rdesktop-vuln-cve2012-2533,rdesktop-vuln-cve2012-2534,rdesktop-vuln-cve2012-2535,rdesktop-vuln-cve2012-2536,rdesktop-vuln-cve2012-2537,rdesktop-vuln-cve2012-2538,rdesktop-vuln-cve2012-2539,rdesktop-vuln-cve2013-0156,rdesktop-vuln-cve2013-0157,rdesktop-vuln-cve2013-0158,rdesktop-vuln-cve2013-0159,rdesktop-vuln-cve2013-0160,rdesktop-vuln-cve2013-0161,rdesktop-vuln-cve2013-0162,rdesktop-vuln-cve2013-0163"
    )

    $rdpPorts = @(3389)
    Write-Log -Message "Starting Nmap RDP scan routine..." -Level "INFO"

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($rdpPorts -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port — not an RDP port" -Level "DEBUG"
            continue
        }

        $outfile = Join-Path $OutputDir "nmap_rdp_${ip}_$port.xml"

        Write-Verbose "Running Nmap RDP scan on ${ip}:$port" -Verbose
        try {
            nmap -Pn -sV -p $port --script $Scripts  ${ip} -oX $outfile
            Write-Log -Message "Nmap scan complete for ${ip}:$port. Output: $outfile" -Level "INFO"
        } catch {
            Write-Log -Message "Nmap failed for ${ip}:$port — $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

function Invoke-NmapRDPParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Write-Log -Message "Starting Nmap RDP parser routine for $OutputDir." -Level "INFO"

    $ParsedResults = @()

    Get-ChildItem $OutputDir -Filter "nmap_rdp_*.xml" | ForEach-Object {
        try {
            [xml]$xml = Get-Content $_.FullName -Raw
            $hostNode     = $xml.nmaprun.host
            if (-not $hostNode) { 
                Write-Log -Message "No host node found in $($_.Name) — skipping file." -Level "WARNING"
                return 
            }

            $ipaddress = $hostNode.address.addr
            Write-Log -Message "Parsing scan results for $ipaddress." -Level "INFO"

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
        $csvPath = (Join-Path $ParsedDir 'nmap_RDP.csv') 
        $ParsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "No RDP scan results found — export skipped." -Level "WARNING"
    } else {
        Write-Verbose "No RDP nmap scan results found." -Verbose
    }
    Write-Log -Message "Invoke-NmapRDPParser routine complete." -Level "INFO"
}

