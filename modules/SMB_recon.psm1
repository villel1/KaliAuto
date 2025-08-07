function Invoke-enum4linux {
    param (
        [string]$OutputDir,
        [string[]]$targets
    )

    $SMBports = @(445,139)

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($SMBports -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port — non-SMB port" -Level "WARNING"
            continue
        }

        $outfile = Join-Path $OutputDir "enum4linux_${ip}_$port.txt"
        Write-Log -Message "Executing enum4linux against ${ip}:$port" -Level "INFO"

        try {
            enum4linux -a $ip | Out-File $outfile -Encoding ascii
            Write-Log -Message "enum4linux output saved to $outfile" -Level "INFO"
        } catch {
            Write-Log -Message "enum4linux failed for ${ip}:$port — $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

function Invoke-enum4linuxParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    $targets = Get-ChildItem -Path $OutputDir -Filter "enum4linux_*.txt"
    $ParsedResults = @()

    foreach ($target in $targets) {
        try {
            $content = Get-Content $target.FullName -Raw

            $ip = if ($content -match "Target\s+\.*\s+([\d\.]+)") { $matches[1] }
            $domain = if ($content -match "Got domain/workgroup name:\s+(\S+)") { $matches[1] }
            $mac = if ($content -match "MAC Address\s+=\s+([0-9A-Fa-f\-:]+)") { $matches[1] }
            $usernames = if ($content -match "Known Usernames\s+\.\.+\s+(.*)") { $matches[1] -split ",\s*" }
            $sessionError = if ($content -match "Server doesn't allow session.*") { $matches[0] }

            $ParsedResults += [PSCustomObject]@{
                IP     = $ip
                Domain        = $domain
                MACAddress    = $mac
                Usernames     = if ($usernames) { $usernames -join ", " } else { "None" }
                SessionStatus = if ($sessionError) { $sessionError } else { "Session allowed or not tested" }
                SourceFile    = $target.Name
            }
        }
        catch {
            Write-Log -Message "Failed to parse $($target.Name): $($_.Exception.Message)" -Level "ERROR"
        }
    }
    if ($ParsedResults.Count -gt 0) {
        $csvPath = (Join-Path $ParsedDir 'enum4linux.csv')
        $ParsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported enum4linux results to $csvPath." -Level "INFO"
    } else {
        Write-Log -Message "No enum4linux results found in $OutputDir" -Level "WARNING"
    }
}

function Invoke-SMBNmap {
    param (
        [string]$OutputDir,
        [string[]]$targets,
        [string]$Scripts = "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln-ms17-010"
    )

    $SMBports = @(445,139)

    Write-Log -Message "Starting Invoke-SMBNmap scan routine..." -Level "INFO"

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        Write-Log -Message "Processing target: {$ip}:$port" -Level "INFO"

        if (-not ($SMBports -contains $port)) {
            Write-Log -Message "Skipping target {$ip}:$port — unsupported SMB port" -Level "WARNING"
            continue
        }

        $outfile = Join-Path $OutputDir "nmap_SMB_${ip}_$port.xml"
        Write-Log -Message "Launching SMB scan against {$ip}:$port with scripts: $Scripts" -Level "INFO"

        try {
            nmap -Pn -sV -p $port --script $Scripts $ip -oX $outfile
            Write-Log -Message "Scan successful for ${ip}:$port — results saved to $outfile" -Level "INFO"
        } catch {
            Write-Log -Message "Scan failed for ${ip}:$port — $($_.Exception.Message)" -Level "ERROR"
        }
    }
    Write-Log -Message "SMB Nmap scan routine completed across all targets." -Level "INFO"
}

function Invoke-NmapSMBParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    $ParsedResults = @()

    Write-Log -Message "Starting Nmap SMB parser routine in $OutputDir" -Level "INFO"

    Get-ChildItem $OutputDir -Filter "nmap_SMB_*.xml" | ForEach-Object {
        try {
            [xml]$xml = Get-Content $_.FullName -Raw
            $hostNode     = $xml.nmaprun.host
            if (-not $hostNode) { 
                Write-Log -Message "No <host> node found in $($_.Name), skipping..." -Level "WARNING"
                return 
            }

            $ipaddress = $hostNode.address.addr
            $ports     = $hostNode.ports.port
            Write-Log -Message "Parsing host $ipaddress from file $($_.Name)" -Level "INFO"

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
                        Confidence       = $serviceConf
                        CPE             = $serviceCPE
                        Script          = $scriptId
                        Output          = $formattedOutput
                    }
                    Write-Log -Message "Extracted $scriptId from ${ipaddress}:${portid}" -Level "DEBUG"
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
        $csvPath = (Join-Path $ParsedDir 'nmap_SMB.csv')
        $ParsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported parsed results to $csvPath" -Level "INFO"
    } else {
        Write-Log -Message "No SMB Nmap scan results found in $OutputDir" -Level "WARN"
    }
}