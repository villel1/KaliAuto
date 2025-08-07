function Invoke-NmapFTP {
    param (
        [string]$OutputDir,
        [string[]]$targets,
        [string]$Scripts = "ftp-syst,ftp-anon",
        [string]$scriptArgs = "anon=1,brute.userfile=users.txt,brute.passfile=passwords.txt,ftp-anon.maxlist=100,ftp-anon.verbose=1"
    )

    $rdpPorts = @(21)

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($rdpPorts -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port — not a known FTP port." -Level "WARNING"
            continue
        }

        $outfile = Join-Path $OutputDir "nmap_ftp_${ip}_$port.xml"

        Write-Log -Message "Running Nmap FTP scan on ${ip}:$port." -Level "INFO"
        try {
            nmap -Pn -sV -p $port --script $Scripts --script-args $scriptArgs  ${ip} -oX $outfile
            Write-Log -Message "Nmap FTP scan completed for ${ip}:$port — results saved to $outfile." -Level "INFO"
        } catch {
            Write-Log -Message "Nmap FTP scan failed for ${ip}:$port — $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

function Invoke-NmapFTPParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    $ParsedResults = @()

    Write-Log -Message "Starting FTP scan results parsing from $OutputDir." -Level "INFO"

    Get-ChildItem $OutputDir -Filter "nmap_ftp_*.xml" | ForEach-Object {
        try {
            [xml]$xml = Get-Content $_.FullName -Raw
            $hostNode     = $xml.nmaprun.host
            if (-not $hostNode) { 
                return 
            }

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
            Write-Log -Message "Parsed FTP scan results for $ipaddress." -Level "INFO"
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
        $csvPath = (Join-Path $ParsedDir 'nmap_FTP.csv')
        $ParsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported parsed FTP scan results to $csvPath." -Level "INFO"
    } else {
        Write-Log -Message "No FTP scan results found to parse." -Level "WARNING"
    }
}