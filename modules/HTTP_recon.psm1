function Invoke-CurlScan {
    param (
        [string]$OutputDir,
        [string[]]$targets
    )

    # Define allowed web service ports
    $WebPorts = @(80, 443, 8080, 8443, 8000)

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        # Filter: only scan web-related ports
        if (-not ($WebPorts -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port — not a recognized web service port." -Level "WARNING"
            continue
        }

        # Determine protocol
        $protocol = switch ($port) {
            443     { 'https' }
            8443    { 'https' }
            default { 'http' }
        }

        $url     = "${protocol}://${ip}:$port"
        $outfile = Join-Path $OutputDir "curl_${protocol}_${ip}_${port}.txt"

        Write-Log -Message "Running curl on $url." -Level "INFO"

        try {
            curl --max-time 600 -sSik $url | Out-File $outfile -Encoding ascii
            Write-Log -Message "Curl scan successful for $url — output saved to $outfile." -Level "INFO"
        } catch {
            Write-Log -Message "Curl scan failed for $url — $($_.Exception.Message)" -Level "ERROR"
        }
    }
    Write-Log -Message "Completed Invoke-CurlScan execution." -Level "INFO"
}
function Invoke-CurlParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    $ParsedResults = @()

    Write-Log -Message "Starting Curl response parsing in $OutputDir." -Level "INFO"

    Get-ChildItem $OutputDir -Filter "curl_*.txt" | ForEach-Object {
        $filePath = $_.FullName
        $source   = $_.Name

        $ip = if ($source -match 'curl_(?:http|https)_([\d\.]+)_\d+\.txt') { $matches[1] } else { 'Unknown' }

        Write-Log -Message "Parsing Curl output file: $source." -Level "INFO"

        try {
            $lines     = Get-Content $filePath
            $responses = @()
            $buffer    = @()

            foreach ($line in $lines) {
                if ($line -match '^HTTP/\d') {
                    if ($buffer.Count -gt 0) {
                        $responses += ,@($buffer)
                        $buffer = @()
                    }
                }
                $buffer += $line
            }
            if ($buffer.Count -gt 0) {
                $responses += ,@($buffer)
            }

            foreach ($response in $responses) {
                $status     = ($response | Where-Object { $_ -match '^HTTP/\d' }) | Select-Object -First 1
                $server     = ($response | Where-Object { $_ -match '^server:' }) -replace '^server:\s*', '' -join ' | '
                $poweredBy  = ($response | Where-Object { $_ -match '^x-powered-by:' }) -replace '^x-powered-by:\s*', '' -join ' | '
                $titleLine  = ($response | Where-Object { $_ -match '<title>.*</title>' }) -replace '.*<title>(.*?)</title>.*', '$1' -join ' | '
                $location   = ($response | Where-Object { $_ -match '^location:' }) -replace '^location:\s*', '' -join ' | '
                $cookies    = ($response | Where-Object { $_ -match '^set-cookie:' }) -join ' | '
                $contentSec = ($response | Where-Object { $_ -match '^content-security-policy:' }) -replace '^content-security-policy:\s*', '' -join ' | '

                $fullResponse = $response -join "`n"

                $entry = [PSCustomObject]@{
                    IP               = $ip
                    HTTP_Status      = $status
                    Server           = $server
                    PoweredBy        = $poweredBy
                    Title            = $titleLine
                    RedirectLocation = $location
                    SetCookies       = $cookies
                    CSP_Header       = $contentSec
                    FullResponse     = $fullResponse
                }

                $ParsedResults += $entry
            }

            Write-Log -Message "Parsed ${responses.Count} HTTP responses from $source." -Level "INFO"
        }
        catch {
            Write-Log -Message "Failed to parse $source — $($_.Exception.Message)" -Level "ERROR"
        }
    }

    if ($ParsedResults.Count -gt 0) {
        $csvPath = Join-Path $ParsedDir 'curl.csv'
        $ParsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported parsed Curl data to $csvPath." -Level "INFO"
    } else {
        Write-Log -Message "No Curl responses parsed — skipping export." -Level "WARNING"
    }

    Write-Log -Message "Finished parsing Curl scan results." -Level "INFO"
}
function Invoke-SSLScan {
    param (
        [string]$OutputDir,
        [string[]]$targets
    )

    $SSLPorts = @(443, 8443)

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($SSLPorts -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port — not an SSL service port." -Level "WARNING"
            continue
        }

        $outfile = Join-Path $OutputDir "sslscan_${ip}_${port}.xml"

        Write-Log -Message "Running SSLScan on ${ip}:$port" -Level "INFO"
        try {
            sslscan --show-certificate --xml=$outfile $ip
            Write-Log -Message "SSLScan completed for ${ip}:$port — results saved to $outfile." -Level "INFO"
        } catch {
            Write-Log -Message "SSLScan failed for ${ip}:$port — $($_.Exception.Message)" -Level "ERROR"
        }
    }
}
function Invoke-SSLScanParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    $BaseName        = "SSLScan"
    $ParsedCerts     = @()
    $ParsedCiphers   = @()
    $ParsedGroups    = @()
    $ParsedProtocols = @()
    $ParsedFlags     = @()

    Write-Log -Message "Starting SSLScanParser for directory: $OutputDir" -Level "INFO"

    Get-ChildItem $OutputDir -Filter "sslscan_*.xml" | ForEach-Object {
        [xml]$xml = Get-Content $_.FullName -Raw
        $ssl = $xml.document.ssltest
        if (-not $ssl) { 
            Write-Log -Message "No valid SSL test data in $($_.Name), skipping." -Level "WARNING"
            return 
        }

        $IP  = $ssl.host
        Write-Log -Message "Parsing SSLScan data for $IP" -Level "INFO"

        # --- Certificates Table ---
        foreach ($cert in $ssl.certificates.certificate) {
            $ParsedCerts += [PSCustomObject]@{
                IP             = $IP
                Subject        = $cert.subject.'#cdata-section'
                Issuer         = $cert.issuer.'#cdata-section'
                AltNames       = [string]($cert.altnames.'#cdata-section' -join ', ')
                NotBefore      = $cert.'not-valid-before'
                NotAfter       = $cert.'not-valid-after'
                SelfSigned     = [string]$cert.'self-signed'
                SignatureAlgo  = $cert.'signature-algorithm'
                KeyType        = $cert.pk.type
                KeyBits        = $cert.pk.bits
            }
        }

        # --- Ciphers Table ---
        foreach ($cipher in $ssl.cipher) {
            $ParsedCiphers += [PSCustomObject]@{
                IP           = $IP
                SSLVersion   = $cipher.sslversion
                Cipher       = $cipher.cipher
                Bits         = $cipher.bits
                Status       = $cipher.status
                Strength     = $cipher.strength
                Curve        = ($cipher.curve -join ', ')
                ECDHEBits    = ($cipher.ecdhebits -join ', ')
                DHEBits      = ($cipher.dhebits -join ', ')
            }
        }

        # --- Groups Table ---
        foreach ($g in $ssl.group) {
            $ParsedGroups += [PSCustomObject]@{
                IP         = $IP
                SSLVersion = $g.sslversion
                Group      = $g.name
                Bits       = $g.bits
                GroupID    = $g.id
            }
        }

        # --- Protocols Table ---
        foreach ($proto in $ssl.protocol) {
            $ParsedProtocols += [PSCustomObject]@{
                IP         = $IP
                SSLVersion = ($proto.type + $proto.version) -replace '\s', ''
                Supported  = $proto.enabled
            }
        }

        # --- Vulnerabilities / Features ---
        $ParsedFlags += [PSCustomObject]@{
            IP            = $IP
            Heartbleed    = if ($ssl.heartbleed.vulnerable)    { $ssl.heartbleed.vulnerable[0] }    else { "0" }
            Fallback      = if ($ssl.fallback.supported)       { $ssl.fallback.supported[0] }       else { "0" }
            Compression   = if ($ssl.compression.supported)    { $ssl.compression.supported[0] }    else { "0" }
            Renegotiation = if ($ssl.renegotiation.supported)  { $ssl.renegotiation.supported[0] }  else { "0" }
        }
    }

    # Export all
    if ($ParsedCerts.Count -gt 0) {
        $ParsedCerts      | Export-Csv "$ParsedDir/${BaseName}_Certificates.csv" -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported ${BaseName}_Certificates.csv" -Level "INFO"
    } else {
        Write-Log -Message "No SSL Certificates found." -Level "WARNING"e
    }

    if ($ParsedCiphers.Count -gt 0) {
        $ParsedCiphers    | Export-Csv "$ParsedDir/${BaseName}_Ciphers.csv"      -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported ${BaseName}_Ciphers.csv" -Level "INFO"
    } else {
        Write-Log -Message "No SSL Ciphers found." -Level "WARNING"
    }

    if ($ParsedGroups.Count -gt 0) {
        $ParsedGroups     | Export-Csv "$ParsedDir/${BaseName}_Groups.csv"       -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported ${BaseName}_Groups.csv" -Level "INFO"
    } else {
        Write-Log -Message "No SSL Groups found." -Level "WARNING"
    }

    if ($ParsedProtocols.Count -gt 0) {
        $ParsedProtocols  | Export-Csv "$ParsedDir/${BaseName}_Protocols.csv"    -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported ${BaseName}_Protocols.csv" -Level "INFO"
    } else {
        Write-Log -Message "No SSL Protocols found." -Level "WARNING"
    }

    if ($ParsedFlags.Count -gt 0) {
        $ParsedFlags      | Export-Csv "$ParsedDir/${BaseName}_Flags.csv"        -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported ${BaseName}_Flags.csv" -Level "INFO"
    } else {
        Write-Log -Message "No SSL flags found." -Level "WARNING"
    }
    Write-Log -Message "Invoke-SSLScanParser complete." -Level "INFO"
}
function Invoke-NmapHTTP {
    param (
        [string]$OutputDir,
        [string]$Scripts = "http-title,http-methods,http-server-header,http-security-headers,http-cookie-flags,http-enum",
        [string[]]$targets
    )

    $WebPorts = @(80, 443, 8080, 8443, 8000)

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($WebPorts -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port — not a common web service port." -Level "WARNING"
            continue
        }

        $outfile = Join-Path $OutputDir "nmap_http_${ip}_$port.xml"

        Write-Log -Message "Running Nmap HTTP scan on ${ip}:$port" -Level "INFO"
        try {
            nmap -Pn -sV -p $port --script $Scripts $ip -oX $outfile
            Write-Log -Message "Running Nmap HTTP scan on ${ip}:$port" -Level "INFO"
        } catch {
            Write-Log -Message "Nmap failed for ${ip}:$port — $($_.Exception.Message)" -Level "ERROR"
        }
    }
    Write-Log -Message "Invoke-NmapHTTP finished." -Level "INFO"
}
function Invoke-NmapHTTPParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    $ParsedResults = @()
    Write-Log -Message "Starting Nmap HTTP XML parsing from $OutputDir." -Level "INFO"

    Get-ChildItem $OutputDir -Filter "nmap_http_*.xml" | ForEach-Object {
        try {
            [xml]$xml = Get-Content $_.FullName -Raw
            $hostNode     = $xml.nmaprun.host
            if (-not $hostNode) { 
                Write-Log -Message "Missing host data in $($_.Name), skipping file." -Level "WARNING"
                return 
            }

            $ipaddress = $hostNode.address.addr
            Write-Log -Message "Parsing Nmap HTTP results for $ipaddress." -Level "INFO"

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
        $ParsedResults | Export-Csv -Path (Join-Path $ParsedDir 'nmap_HTTP.csv') -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported parsed Nmap HTTP data to nmap_HTTP.csv." -Level "INFO"
    } else {
        Write-Log -Message "No HTTP Nmap results parsed — CSV not generated." -Level "WARNING"
    }
    Write-Log -Message "Invoke-NmapHTTPParser complete." -Level "INFO"
}
function Invoke-whatweb {
    param (
        [string]$OutputDir,
        [string[]]$targets
    )
    $WebPorts = @(80, 443, 8080, 8443, 8000)
    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($WebPorts -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port — not a web service port." -Level "WARNING"
            continue
        }

        $protocol = switch ($port) {
            443 {'https'}
            8443 {'https'}
            default {'http'}
        }

        $url = "${protocol}://${ip}:$port"
        $outfile = Join-Path $OutputDir "whatweb_${ip}_${port}.json"

        Write-Log -Message "Running WhatWeb scan on $url." -Level "INFO"
        try {
            whatweb -a 3 --log-json=$outfile $url
            Write-Log -Message "WhatWeb scan complete for $url — saved to $outfile." -Level "INFO"
        } catch {
            Write-Log -Message "WhatWeb scan failed for $url — $($_.Exception.Message)" -Level "ERROR"
        }
    }
    Write-Log -Message "Invoke-whatweb finished processing all targets." -Level "INFO"
}
function Invoke-whatwebParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Write-Log -Message "Starting WhatWeb parser..." -Level "INFO"

    $ParsedResults = @()

    Get-ChildItem $OutputDir -Filter "whatweb_*.json" | ForEach-Object {
        $filePath = $_.FullName
        $raw      = Get-Content $filePath -Raw

        if ([string]::IsNullOrWhiteSpace($raw) -or $raw -eq "[]") {
            Write-Log -Message "Skipping empty file: $($_.Name)" -Level "WARNING"
            return
        }

        try {
            $json = $raw | ConvertFrom-Json
            if ($json.Count -eq 0) { 
                Write-Log -Message "Skipping file with no entries: $($_.Name)" -Level "WARNING"
                return 
            }
            $entry = $json[0]
        } catch {
            Write-Log -Message "Failed to parse $($_.Name): $($_.Exception.Message)" -Level "ERROR"
            return
        }

        $ip = ($_.BaseName -split "_")[1]

        $data = [PSCustomObject]@{
            IP        = $ip
            Status        = $entry.http_status
            Server        = if ($entry.plugins."HTTPServer") { $entry.plugins."HTTPServer".string | Select-Object -First 1 } else { "" }
            WebTitle      = if ($entry.plugins.Title) { $entry.plugins.Title.string | Select-Object -First 1 } else { "" }
            PoweredBy     = if ($entry.plugins."X-Powered-By") { $entry.plugins."X-Powered-By".string | Select-Object -First 1 } else { "" }
            ServerVersion = if ($entry.plugins."Microsoft-IIS") { $entry.plugins."Microsoft-IIS".version | Select-Object -First 1 } else { "" }
            Country       = if ($entry.plugins.Country) { $entry.plugins.Country.string | Select-Object -First 1 } else { "" }
        }

        Write-Log -Message "Parsed results for $ip added." -Level "INFO"
        $ParsedResults += $data
    }

    if ($ParsedResults.Count -gt 0) {
        $csvPath = Join-Path $ParsedDir 'whatweb.csv'
        $ParsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported parsed data to $csvPath." -Level "INFO"
    } else {
        Write-Log -Message "No valid WhatWeb results found — export skipped." -Level "WARNING"
    }
    Write-Log -Message "Invoke-whatwebParser completed." -Level "INFO"
}
function Invoke-Nikto {
    param (
        [string]$OutputDir,
        [string[]]$targets
    )

    Write-Log -Message "Starting Nikto scan routine..." -Level "INFO"

    $WebPorts = @(80, 443, 8080, 8443, 8000)

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($WebPorts -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port — not a web port." -Level "WARNING"
            continue
        }

        $protocol = switch ($port) {
            443     { 'https' }
            8443    { 'https' }
            default { 'http' }
        }

        $url = "${protocol}://${ip}:$port"
        $outfile = Join-Path $OutputDir "Nikto_${ip}_$port.json"

        Write-Log -Message "Running Nikto scan on $url" -Level "INFO"
        try {
            timeout 15m nikto -h $url -ssl -Tuning x6 -o $outfile -Format json
            Write-Log -Message "Nikto scan completed for $url — results saved to $outfile." -Level "INFO"
        } catch {
            Write-Log -Message "Nikto scan failed for ${ip}:$port — $($_.Exception.Message)" -Level "ERROR"
        }
    }
    Write-Log -Message "Invoke-Nikto routine finished processing all targets." -Level "INFO"
}
function Invoke-NiktoParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Write-Log -Message "Starting Nikto parser routine..." -Level "INFO"

    $ParsedResults = @()

    Get-ChildItem $OutputDir -Filter "nikto_*.json" | ForEach-Object {
        try {
            $json = Get-Content $_.FullName -Raw | ConvertFrom-Json

            if (-not $json.vulnerabilities) { 
                Write-Log -Message "No vulnerabilities found in $($_.Name) — skipping." -Level "WARNING"
                return 
            }

            $hostNode     = $json.host
            $ip       = $json.ip
            $port     = $json.port
            $banner   = $json.banner
            $findings = $json.vulnerabilities

            foreach ($vuln in $findings) {
                $ParsedResults += [PSCustomObject]@{
                    Host       = $hostNode
                    IP         = $ip
                    Port       = $port
                    Banner     = $banner
                    ID         = $vuln.id
                    Method     = $vuln.method
                    URL        = $vuln.url
                    Message    = $vuln.msg
                    References = $vuln.references
                }
            }
            Write-Log -Message "Parsed vulnerabilities for ${ip}:$port successfully." -Level "INFO"
        }
        catch {
            Write-Log -Message "Failed to parse $($_.Name): $($_.Exception.Message)" -Level "ERROR"
        }
    }

    if ($ParsedResults.Count -gt 0) {
        $csvPath = Join-Path $ParsedDir 'nikto_results.csv'
        $ParsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    } else {
        Write-Log -Message "No Nikto vulnerabilities found — nothing exported." -Level "WARNING"
    }
    Write-Log -Message "Invoke-NiktoParser routine completed." -Level "INFO"
}
function Invoke-SSLyze {
    param (
        [string]$OutputDir,
        [string[]]$targets
    )

    Write-Log -Message "Starting SSLyze scan routine..." -Level "INFO"

    $WebPorts = @(80, 443, 8080, 8443, 8000)

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($target in $targets) {
        $parts = $target.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($WebPorts -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port — not a web port." -Level "WARNING"
            continue
        } 

        $outfile = Join-Path $OutputDir "sslyze_${ip}_$port.json"

        Write-Log -Message "Skipping ${ip}:$port — not a web port." -Level "WARNING"
        try {
            sslyze --certinfo ${ip}:$port --json_out $outfile
            Write-Log -Message "SSLyze scan completed for ${ip}:$port — results saved to $outfile." -Level "INFO"
        } catch {
            Write-Log -Message "SSLyze scan failed for ${ip}:$port — $($_.Exception.Message)" -Level "ERROR"
        }
    }
    Write-Log -Message "Invoke-SSLyze routine completed." -Level "INFO"
}
function Invoke-SSlyzeParser {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Write-Log -Message "Starting SSLyze parser routine for directory: $OutputDir" -Level "INFO"

    $certs = @()
    $protocols = @()
    $vulns = @()

    Get-ChildItem $OutputDir -Filter "sslyze_*.json" | ForEach-Object {
        try {
            $raw = Get-Content $_.FullName -Raw
            $rawClean = $raw -replace '"rsa_n":\s*\d+(,)?', ''
            $json = $rawClean | ConvertFrom-Json

            foreach ($scan in $json.server_scan_results) {
                $result = $scan.scan_result
                $hostname = $result.certificate_info.result.hostname_used_for_server_name_indication

                # CERTIFICATE
                foreach ($deploy in $result.certificate_info.result.certificate_deployments) {
                    $cert = $deploy.received_certificate_chain[0]
                    $certs += [PSCustomObject]@{
                        Hostname     = $hostname
                        Subject      = $cert.subject
                        Issuer       = $cert.issuer
                        ValidFrom    = $cert.not_valid_before
                        ValidTo      = $cert.not_valid_after
                        Algorithm    = $cert.public_key.algorithm
                        KeySize      = $cert.public_key.key_size
                        SerialNumber = $cert.serial_number
                    }
                }

                # PROTOCOLS
                $protocols += [PSCustomObject]@{
                    Hostname   = $hostname
                    SSLv2      = $result.ssl_2_0_cipher_suites.status
                    SSLv3      = $result.ssl_3_0_cipher_suites.status
                    TLSv1_0    = $result.tls_1_0_cipher_suites.status
                    TLSv1_1    = $result.tls_1_1_cipher_suites.status
                    TLSv1_2    = $result.tls_1_2_cipher_suites.status
                    TLSv1_3    = $result.tls_1_3_cipher_suites.status
                }

                # VULNERABILITIES
                $vulns += [PSCustomObject]@{
                    Hostname       = $hostname
                    Heartbleed     = $result.heartbleed.status
                    ROBOT          = $result.robot.status
                    Renegotiation  = $result.session_renegotiation.status
                    Resumption     = $result.session_resumption.status
                    FallbackSCSV   = $result.tls_fallback_scsv.status
                    OpenSSL_CCS    = $result.openssl_ccs_injection.status
                    TLS_Compression = $result.tls_compression.status
                    TLS_1_3_Early_Data = $result.tls_1_3_early_data.status
                }
            }
            Write-Log -Message "Parsed SSLyze results from $($_.Name)" -Level "INFO"
        }
        catch {
            Write-Log -Message "Failed to parse $($_.Name): $($_.Exception.Message)" -Level "ERROR"
        }
    }

    # EXPORTS
    if ($certs.Count -gt 0) {
        $csvFile = (Join-Path $ParsedDir 'sslyze_certificates.csv')
        $certs | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported SSLyze certificates to $csvFile." -Level "INFO"
    } else {
        Write-Log -Message "No SSLyze certificates found — skipping export." -Level "WARNING"
    }
    if ($protocols.Count -gt 0) {
        $csvFile = (Join-Path $ParsedDir 'sslyze_protocols.csv')
        $protocols | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported SSLyze protocols to $csvFile." -Level "INFO"
    } else {
        Write-Log -Message "No SSLyze protocols found — skipping export." -Level "WARNING"
    }
    if ($vulns.Count -gt 0) {
        $csvFile = (Join-Path $ParsedDir 'sslyze_vulnerabilities.csv')
        $vulns | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Exported SSLyze vulnerabilities to $csvFile." -Level "INFO"
    } else {
        Write-Log -Message "No SSLyze vulnerabilities found — skipping export." -Level "WARNING"
    }
    Write-Log -Message "Invoke-SSlyzeParser routine completed." -Level "INFO"
}