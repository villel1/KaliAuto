function Invoke-SMTPnmap {
    param (
        [string]$OutputDir,
        [string]$Scripts = "smtp-enum-users,ssl-cert,ssl-enum-ciphers,smtp-open-relay,smtp-commands,smtp-vuln-cve2011-1720",
        [string[]]$targets
    )

    $SMTPports = @(25,465,587)

    Write-Log -Message "Starting Invoke-SMTPnmap scan routine..." -Level "INFO"

    if (-not $targets) {
        
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }
    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        Write-Log -Message "Processing target: {$ip}:$port" -Level "INFO"

        if (-not ($SMTPports -contains $port)) {
            Write-Log -Message "Skipping target {$ip}:$port — unsupported SMTP port" -Level "WARNING"
            continue
        }
        $outfile = Join-Path $OutputDir "nmap_smtp_${ip}_$port.xml"

        Write-Log -Message "Running Nmap SMTP scan on ${ip}:$port" -Level "INFO"
        
        try {
            nmap -Pn -sV -p $port --script $Scripts $ip -oX $outfile
        } catch {
            Write-Log -Message "Nmap failed for ${ip}:$port" -Level "ERROR"
        }
    }
}
function Invoke-NmapSMTPParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    $ParsedResults = @()

    Write-Log -Message "Starting Invoke-NmapSMTPParser routine..." -Level "INFO"

    Get-ChildItem $OutputDir -Filter "nmap_smtp_*.xml" | ForEach-Object {
        try {
            [xml]$xml = Get-Content $_.FullName -Raw
            $hostNode     = $xml.nmaprun.host
            if (-not $hostNode) {
                Write-Log -Message "No <host> node found in $($_.Name) — skipping file." -Level "WARNING" 
                return 
            }

            $ipaddress = $hostNode.address.addr
            $ports     = $hostNode.ports.port
            Write-Log -Message "No <host> node found in $($_.Name) — skipping file." -Level "WARNING"

            foreach ($port in $ports) {
                $portid   = $port.portid
                $protocol = $port.protocol
                $state    = $port.state.state

                $service = $port.service
                $serviceName     = $service.name
                $serviceProduct  = $service.product
                $serviceHostname = $service.hostname
                $serviceOS       = $service.ostype
                $serviceMethod   = $service.method
                $serviceConf     = $service.conf
                $serviceCPE      = $service.cpe

                $scripts = $port.script

                foreach ($script in $scripts) {
                    $scriptId = $script.id
                    $rawOutput = $script.output

                    $formattedOutput = if ($rawOutput.'#text') {
                        $rawOutput.'#text'
                    } elseif ($rawOutput.InnerXml) {
                        $rawOutput.InnerXml
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
                    Write-Log -Message "Parsed script '${scriptId}' from ${ipaddress}:$portid" -Level "DEBUG"
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
        $csvPath = (Join-Path $ParsedDir 'nmap_smtp.csv')
        $ParsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported parsed SMTP results to $csvPath" -Level "INFO"
    } else {
        Write-Log -Message "No SMTP Nmap scan results found in $OutputDir" -Level "WARNING"
    }
    Write-Log -Message "Invoke-NmapSMTPParser routine completed." -Level "INFO"
}
function Invoke-Swaks {
    param (
        [string]$OutputDir,
        [string[]]$targets
    )

    $SMTPports = @(25,465,587)

    Write-Log -Message "Starting Invoke-Swaks routine..." -Level "INFO"

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($SMTPports -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port — not a recognized SMTP port." -Level "DEBUG"
            continue
        }

        $outfile = Join-Path $OutputDir "swaks_smtp_${ip}_$port.txt"
        Write-Log -Message "Running Swaks SMTP test on ${ip}:$port" -Level "INFO"

        try {
            swaks --to test@$ip --from test@$ip --server $ip --data 'Subject: Test Email\n\nThis is a test email.' | Out-File $outfile -Encoding ascii
            Write-Log -Message "Swaks test completed for ${ip}:$port. Output saved to $outfile" -Level "INFO"
        } catch {
            Write-Log -Message "Swaks failed for ${ip}:$port — $($_.Exception.Message)" -Level "ERROR"
        }
    }
    Write-Log -Message "Invoke-Swaks routine finished." -Level "INFO"
}
function Invoke-SwaksParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    $ParsedResults = @()

    Write-Log -Message "Starting Invoke-SwaksParser routine..." -Level "INFO"

    Get-ChildItem $OutputDir -Filter "swaks_smtp_*.txt" | ForEach-Object {
        try {
            $content = Get-Content $_.FullName -Raw

            $ip = if ($content -match "Trying\s+([\d\.]+):25") { $matches[1] }

            # Fallback to IP from filename if not found in content
            if (-not $ip) {
                $baseName = $_.BaseName
                $ip = ($baseName -split "_")[2]
            }

            $banner = if ($content -match "<-  220\s+(.*)") { $matches[1].Trim() }
            $hostname = if ($banner -match "^(\S+)") { $matches[1] }
            $mailSoftware = if ($banner -match "ESMTP\s+(.*)") { $matches[1] } else { $banner }

            $extensions = @()
            if ($content -match "(?s)EHLO.*?(<-  250.*?)(?=\n ->|\Z)") {
                $ehloBlock = $matches[1] -split "`n"
                $extensions = $ehloBlock | ForEach-Object {
                    ($_ -replace "<-  250[- ]", "").Trim()
                }
            }

            $starttls = if ($extensions -contains "STARTTLS") { "Yes" } else { "No" }
            $sizeSupport = if ($extensions -match "SIZE") { "Yes" } else { "No" }
            $authSupport = if ($extensions -match "AUTH") { "Yes" } else { "No" }
            $helpSupport = if ($extensions -match "HELP") { "Yes" } else { "No" }

            $mailFromResponse = if ($content -match "<\*\* (.*)") { $matches[1].Trim() }

            $relayRisk = if ($mailFromResponse -match "auth required|authentication required|must authenticate") {                "Low"
            } else {
                "Potential Relay Risk"
            }

            $ParsedResults += [PSCustomObject]@{
                IP         = if ($ip) { $ip } else { "N/A" }
                Hostname          = if ($hostname) { $hostname } else { "N/A" }
                MailSoftware      = if ($mailSoftware) { $mailSoftware } else { "N/A" }
                STARTTLS_Support  = $starttls
                SIZE_Support      = $sizeSupport
                AUTH_Support      = $authSupport
                HELP_Support      = $helpSupport
                SMTP_Extensions   = if ($extensions.Count -gt 0) { ($extensions -join ", ") } else { "N/A" }
                MAILFROM_Response = if ($mailFromResponse) { $mailFromResponse } else { "N/A" }
                RelayRisk         = $relayRisk
            }
            Write-Log -Message "Parsed Swaks output from ${ip}" -Level "DEBUG"
        } catch {
            Write-Log -Message "Failed to parse $($_.Name): $($_.Exception.Message)" -Level "ERROR"
        }
    }
    if ($ParsedResults.Count -gt 0) {
        $csvPath = Join-Path $ParsedDir 'swaks.csv'
        $ParsedResults | Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported Swaks results to $csvPath" -Level "INFO"
    } else {
        Write-Log -Message "No Swaks results found in $OutputDir" -Level "WARNING"
    }
    Write-Log -Message "Invoke-SwaksParser routine completed." -Level "INFO"
}