function Invoke-SSHnmap {
    param (
        [string]$OutputDir,
        [string]$scripts = "ssh-hostkey,sshv1,ssh2-enum-algos,ssh-auth-methods,ssh-brute",
        [string[]]$targets
    )

    Write-Log -Message "Starting SSH scan routine..." -Level "INFO"

    $sshPorts = @(22, 2222)

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($sshPorts -contains $port)) {
            continue
        }

        $outfile = Join-Path $OutputDir "nmap_ssh_${ip}_$port.xml"
        Write-Log -Message "Running Nmap SSH scan on ${ip}:$port" -Level "INFO"

        try {
            nmap -Pn -sV -p $port --script $Scripts $ip -oX $outfile
            Write-Log -Message "Scan completed for ${ip}:$port - output saved to $outfile" -Level "INFO"
        } catch {
            Write-Log -Message "Nmap scan failed for ${ip}:$port - $($_.Exception.Message)" -Level "ERROR"
        }
    }
    Write-Log -Message "SSH scan routine completed." -Level "INFO"
}
function Invoke-NmapSSHParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Write-Log -Message "Starting SSH scan parser routine..." -Level "INFO"

    $ParsedResults = @()

    Get-ChildItem $OutputDir -Filter "nmap_SSH_*.xml" | ForEach-Object {
        try {
            [xml]$xml = Get-Content $_.FullName -Raw
            $hostNode     = $xml.nmaprun.host
            if (-not $hostNode) { 
                return 
            }

            $ipaddress = $hostNode.address.addr
            $ports     = $hostNode.ports.port

            Write-Log -Message "Parsing SSH scan result for ${ipaddress}" -Level "INFO"

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
                    Write-Log -Message "Parsed ${scriptId} output from ${ipaddress}:${portid}" -Level "INFO"
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
        $csvPath = (Join-Path $ParsedDir 'nmap_SSH.csv')
        $ParsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported SSH scan results to $csvPath" -Level "INFO"
    } else {
        Write-Log -Message "No SSH scan results found in $OutputDir" -Level "WARNING"
    }
    Write-Log -Message "SSH scan parser routine completed." -Level "INFO"
}