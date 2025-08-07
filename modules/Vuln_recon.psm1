function Invoke-NmapVuln {
    param (
        [string]$OutputDir,
        [string[]]$targets,
        [string]$Scripts = "vuln"
    )

    Write-Log -Message "Starting Nmap vulnerability scan routine..." -Level "INFO"

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        $outfile = Join-Path $OutputDir "nmap_vuln_${ip}:$port.xml"
        Write-Log -Message "Running Nmap vulnerability scan on ${ip}:${port}" -Level "INFO"
        try {
            nmap -Pn -sV -p $port --script $Scripts ${ip} -oX $outfile
            Write-Log -Message "Nmap scan complete for ${ip}:${port}, results saved to ${outfile}" -Level "INFO"
        } catch {
            Write-Log -Message "Nmap scan failed for ${ip}:${port}: $($_.Exception.Message)" -Level "ERROR"
        }
    }
    Write-Log -Message "Nmap vulnerability scan routine completed." -Level "INFO"
}
function Invoke-NmapVulnParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Write-Log -Message "Starting vulnerability scan parser routine..." -Level "INFO"

    $ParsedResults = @()

    Get-ChildItem $OutputDir -Filter "nmap_vuln_*.xml" | ForEach-Object {
        try {
            [xml]$xml = Get-Content $_.FullName -Raw
            $hostNode     = $xml.nmaprun.host
            if (-not $hostNode) { return }

            $ipaddress = $hostNode.address.addr
            $ports     = $hostNode.ports.port

            Write-Log -Message "Parsing vulnerability scan result for ${ipaddress}" -Level "INFO"

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
        $csvPath = (Join-Path $ParsedDir 'nmap_vuln.csv')
        $ParsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported vulnerability scan results to $csvPath" -Level "INFO"
    } else {
        Write-Log -Message "No vulnerability scan results found in $OutputDir" -Level "WARNING"
    }
    Write-Log -Message "Vulnerability scan parser routine completed." -Level "INFO"
}
function Invoke-CrackMapExec {
    param (
        [string]$OutputDir,
        [string[]]$targets
    )

    $CMEPorts = @(22, 2222, 2200, 3389, 445, 139)

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($CMEPorts -contains $port)) {
            continue
        }

        $protocol = switch ($port) {
            22 { 'ssh' }
            2222 { 'ssh' }
            2200 { 'ssh' }
            3389 { 'rdp' }
            445 { '445' }
            139 { '139' }
        }

        $outfile = Join-Path $OutputDir "cme_${ip}_$port.xml"

        Write-Verbose "Running CrackMapExec SSH scan on ${ip}:$port" -Verbose
        try {
            crackmapexec $protocol $ip | Out-File $outfile -Encoding ascii
        } catch {
            Write-Verbose "CrackMapExec failed for ${ip}:$port" -Verbose
        }
    }
}
function Invoke-CMEParserSMB {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    $ParsedResults = @()

    Get-ChildItem $OutputDir -Filter "cme_*.txt" | ForEach-Object {
        try {
            $lines = Get-Content $_.FullName
            foreach ($line in $lines) {
                if ($line -match '^SMB\s+(\S+)\s+(\d+)\s+(\S+)\s+

\[\*\]

\s+Windows\s+([\d\.]+\s+Build\s+\d+)\s+\(name:(.*?)\)\s+\(domain:(.*?)\)\s+\(signing:(.*?)\)\s+\(SMBv1:(.*?)\)') {
                    $ParsedResults += [PSCustomObject]@{
                        IP           = $matches[1]
                        Port         = $matches[2]
                        Hostname     = $matches[3]
                        OSVersion    = $matches[4]
                        Name         = $matches[5]
                        Domain       = $matches[6]
                        SMBSigning   = $matches[7]
                        SMBv1Support = $matches[8]
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to parse $($_.Name): $_"
        }
    }

    if ($ParsedResults.Count -gt 0) {
        $ParsedResults | Export-Csv -Path (Join-Path $ParsedDir 'cme_smb_results.csv') -NoTypeInformation -Encoding UTF8
    } else {
        Write-Verbose "No CME SMB results found." -Verbose
    }
}
function Invoke-CMEParserSSH {
    param (
        [string]$InputFile,
        [string]$ParsedDir
    )

    $SSHResults = @()

    Get-Content $InputFile | ForEach-Object {
        $line = $_
        # Matches CME SSH output lines with valid login
        if ($line -match '^SSH\s+(\S+)\s+(\d+)\s+(\S+)\s+

\[+\]

\s+Valid\s+Creds\s+(\S+):(\S+)') {
            $SSHResults += [PSCustomObject]@{
                IP         = $matches[1]
                Port       = $matches[2]
                Hostname   = $matches[3]
                Username   = $matches[4]
                Password   = $matches[5]
                Protocol   = "SSH"
            }
        }
    }

    if ($SSHResults.Count -gt 0) {
        $outPath = Join-Path $ParsedDir 'cme_ssh_results.csv'
        $SSHResults | Export-Csv -Path $outPath -NoTypeInformation -Encoding UTF8
    }
}
function Invoke-CMEParserRDP {
    param (
        [string]$InputFile,
        [string]$ParsedDir
    )

    $RDPResults = @()

    Get-Content $InputFile | ForEach-Object {
        $line = $_
        # Matches CME RDP output that might include protocol support or creds
        if ($line -match '^RDP\s+(\S+)\s+(\d+)\s+(\S+)\s+

\[+\]

\s+(.*?)$') {
            $RDPResults += [PSCustomObject]@{
                IP       = $matches[1]
                Port     = $matches[2]
                Hostname = $matches[3]
                Detail   = $matches[4]
                Protocol = "RDP"
            }
        }
    }

    if ($RDPResults.Count -gt 0) {
        $outPath = Join-Path $ParsedDir 'cme_rdp_results.csv'
        $RDPResults | Export-Csv -Path $outPath -NoTypeInformation -Encoding UTF8
    }
}
