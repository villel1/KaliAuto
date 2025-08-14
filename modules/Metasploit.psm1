function Invoke-MetasploitScan {
    param (
        [string]$InputType,
        [string]$InputFile,
        [string]$OutputDir = "$PSScriptRoot/../output",
        [string]$rcPath = "$PSScriptRoot/../rcFiles",
        [string[]]$targets = $null,
        [int[]]$Ports,
        [string]$Module,
        [Parameter(Mandatory=$true)][string]$ScanName
    )

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir "ip_ports.list")
    }

    foreach ($entry in $targets) {
        $parts = $entry.Split(":")
        $ip    = $parts[0]
        $port  = [int]$parts[1]

        if (-not ($Ports -contains $port)) {
            Write-Log -Message "Skipping ${ip}:$port — not a target port for $ScanName." -Level "DEBUG"
            continue
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logPath = Join-Path $OutputDir "${ScanName}_${ip}_$timestamp.txt"
        if (-not (Test-Path $rcPath)) {
            New-Item -ItemType Directory -Path $rcPath | Out-Null
        }

        $rcContent = @"
use $Module
set RHOSTS $ip
run
exit
"@

        try {
            $rcContent | Set-Content $rcPath
            Write-Log -Message "Created RC file for $ip at $rcPath" -Level "INFO"
        } catch {
            Write-Log -Message "Failed to create RC file for ${ip}: $_" -Level "ERROR"
            continue
        }

        Write-Log -Message "Running $ScanName scan on $ip..." -Level "INFO"
        try {
            msfconsole -q -r $rcPath | Tee-Object -FilePath $logPath
            Write-Log -Message "$ScanName scan complete for $ip — output saved to $logPath" -Level "INFO"
        } catch {
            Write-Log -Message "Metasploit execution failed for ${ip}: $_" -Level "ERROR"
        }
    }

    Write-Log -Message "Completed Invoke-MetasploitScan execution for $ScanName." -Level "INFO"
}
function Invoke-HTTPVersionParse {
    param(
        [string]$OutputDir,
        [string]$ParsedDir,
        [string[]]$targets
    )

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Log -Message "No target IPs provided for HTTP version parsing." -Level "ERROR"
        return @()
    }

    Write-Log -Message "Starting HTTP version parsing for $($targets.Count) targets..." -Level "INFO"
    $results = @()

    foreach ($target in $targets) {
        $pattern = "http_version_$($target)_*.txt"
        $files = Get-ChildItem -Path $OutputDir -Filter $pattern -ErrorAction SilentlyContinue

        if (-not $files -or $files.Count -eq 0) {
            Write-Log -Message "No output files found for target $target." -Level "WARN"
            continue
        }

        foreach ($file in $files) {
            $content = Get-Content $file -Raw

            if ($file.Name -match "http_version_(\d{1,3}(?:\.\d{1,3}){3})_(\d{8}_\d{6})\.txt") {
                $ip = $matches[1]
                $timestamp = $matches[2]

                $status = if ($content -match "

\[\*\]

 Auxiliary module execution completed") {
                    "Completed"
                } else {
                    "Unknown"
                }

                $banner = ""
                $redirect = ""
                $port = ""

                if ($content -match "

\[\+\]

 (\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s+([^\(]+)\s+\(\s*([^\)]+)\s*\)") {
                    $port     = $matches[2]
                    $banner   = $matches[3].Trim()
                    $redirect = $matches[4].Trim()
                    Write-Log -Message "Found HTTP banner for ${ip}:$port ➝ $banner ($redirect)" -Level "INFO"
                }

                $results += [PSCustomObject]@{
                    IP        = $ip
                    Port      = $port
                    Timestamp = $timestamp
                    Module    = "http_version"
                    Status    = $status
                    Banner    = $banner
                    Redirect  = $redirect
                }
            } else {
                Write-Log -Message "Filename format unexpected: $($file.Name)" -Level "WARN"
            }
        }
    }

    if ($results.Count -gt 0) {
        $csvPath = Join-Path $ParsedDir 'http_version.csv'
        $txtPath = Join-Path $OutputDir 'http_version.txt'
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        $results | Out-File -Encoding ascii -FilePath $txtPath
        Write-Log -Message "Saved HTTP version results to CSV: $csvPath and TXT: $txtPath" -Level "INFO"
        return $results
    } else {
        Write-Log -Message "No HTTP version results were parsed." -Level "WARN"
        return @()
    }
}
function Invoke-HTTPEnumParse {
    param(
        [string]$OutputDir,
        [string]$ParsedDir,
        [string[]]$targets
    )

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Log -Message "No target IPs provided for HTTP enum parsing." -Level "ERROR"
        return @()
    }

    Write-Log -Message "Starting HTTP enum parsing for $($targets.Count) targets..." -Level "INFO"
    $results = @()

    foreach ($target in $targets) {
        $pattern = "http_enum_$($target)_*.txt"
        $files = Get-ChildItem -Path $OutputDir -Filter $pattern -ErrorAction SilentlyContinue

        if (-not $files -or $files.Count -eq 0) {
            Write-Log -Message "No output files found for target $target." -Level "WARN"
            continue
        }

        foreach ($file in $files) {
            $content = Get-Content $file -Raw

            if ($file.Name -match "http_enum_(\d{1,3}(?:\.\d{1,3}){3})_(\d{8}_\d{6})\.txt") {
                $ip = $matches[1]
                $timestamp = $matches[2]

                $status = "Unknown"
                $moduleLoad = "Unknown"
                $execution = "Unknown"

                if ($content -match "

\[-\]

 Failed to load module: auxiliary/scanner/http/http_enum") {
                    $moduleLoad = "Failed"
                } elseif ($content -match "use auxiliary/scanner/http/http_enum") {
                    $moduleLoad = "Loaded"
                }

                if ($content -match "

\[-\]

 Unknown command: run") {
                    $execution = "Failed"
                } elseif ($content -match "run") {
                    $execution = "Attempted"
                }

                if ($content -match "

\[-\]

 No results from search") {
                    $status = "No Results"
                }

                $results += [PSCustomObject]@{
                    IP          = $ip
                    Timestamp   = $timestamp
                    Module      = "http_enum"
                    ModuleLoad  = $moduleLoad
                    Execution   = $execution
                    Status      = $status
                }

                Write-Log -Message "Parsed HTTP enum result for $ip ➝ ModuleLoad: $moduleLoad, Execution: $execution, Status: $status" -Level "INFO"
            } else {
                Write-Log -Message "Filename format unexpected: $($file.Name)" -Level "WARN"
            }
        }
    }

    if ($results.Count -gt 0) {
        $csvPath = Join-Path $ParsedDir 'http_enum.csv'
        $txtPath = Join-Path $OutputDir 'http_enum.txt'
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        $results | Out-File -Encoding ascii -FilePath $txtPath
        Write-Log -Message "Saved HTTP enum results to CSV: $csvPath and TXT: $txtPath" -Level "INFO"
        return $results
    } else {
        Write-Log -Message "No HTTP enum results were parsed." -Level "WARN"
        return @()
    }
}
function Invoke-SMTPEnumParse {
    param(
        [string]$OutputDir,
        [string]$ParsedDir,
        [string[]]$targets
    )

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Log -Message "No target IPs provided for SMTP enum parsing." -Level "ERROR"
        return @()
    }

    Write-Log -Message "Starting SMTP enum parsing for $($targets.Count) targets..." -Level "INFO"
    $results = @()

    foreach ($target in $targets) {
        $pattern = "smtp_enum_$($target)_*.txt"
        $files = Get-ChildItem -Path $OutputDir -Filter $pattern -ErrorAction SilentlyContinue

        if (-not $files -or $files.Count -eq 0) {
            Write-Log -Message "No output files found for target $target." -Level "WARN"
            continue
        }

        foreach ($file in $files) {
            $content = Get-Content $file -Raw

            if ($file.Name -match "smtp_enum_(\d{1,3}(?:\.\d{1,3}){3})_(\d{8}_\d{6})\.txt") {
                $ip = $matches[1]
                $timestamp = $matches[2]

                $module = if ($content -match "use auxiliary/scanner/smtp/smtp_enum") {
                    "smtp_enum"
                } elseif ($content -match "use auxiliary/scanner/smtp/smtp_version") {
                    "smtp_version"
                } else {
                    "unknown"
                }

                $banner = ""
                $enumStatus = ""
                $port = "25"
                $scanStatus = if ($content -match "

\[\*\]

 Auxiliary module execution completed") {
                    "Completed"
                } else {
                    "Unknown"
                }

                if ($content -match "Banner:\s+(.+?)\r?\n") {
                    $banner = $matches[1].Trim()
                } elseif ($content -match "SMTP\s+220\s+(.+?)\x0d\x0a") {
                    $banner = "220 " + $matches[1].Trim()
                }

                if ($content -match "could not be enumerated \((.+?)\)") {
                    $enumStatus = "Could not enumerate: " + $matches[1].Trim()
                }

                $results += [PSCustomObject]@{
                    IP          = $ip
                    Port        = $port
                    Timestamp   = $timestamp
                    Module      = $module
                    Status      = $scanStatus
                    Banner      = $banner
                    EnumStatus  = $enumStatus
                }

                Write-Log -Message "Parsed SMTP result for $ip ➝ $module, Banner: '$banner', EnumStatus: '$enumStatus'" -Level "INFO"
            } else {
                Write-Log -Message "Filename format unexpected: $($file.Name)" -Level "WARN"
            }
        }
    }

    if ($results.Count -gt 0) {
        $csvPath = Join-Path $ParsedDir 'smtp_enum.csv'
        $txtPath = Join-Path $OutputDir 'smtp_enum.txt'
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        $results | Out-File -Encoding ascii -FilePath $txtPath
        Write-Log -Message "Saved SMTP enum results to CSV: $csvPath and TXT: $txtPath" -Level "INFO"
        return $results
    } else {
        Write-Log -Message "No SMTP enum results were parsed." -Level "WARN"
        return @()
    }
}
function Invoke-SMTPVersionParse {
    param(
        [string]$OutputDir,
        [string]$ParsedDir,
        [string[]]$targets
    )

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Log -Message "No target IPs provided for SMTP version parsing." -Level "ERROR"
        return @()
    }

    Write-Log -Message "Starting SMTP version parsing for $($targets.Count) targets..." -Level "INFO"
    $results = @()

    foreach ($target in $targets) {
        $pattern = "smtp_version_$($target)_*.txt"
        $files = Get-ChildItem -Path $OutputDir -Filter $pattern -ErrorAction SilentlyContinue

        if (-not $files -or $files.Count -eq 0) {
            Write-Log -Message "No output files found for target $target." -Level "WARN"
            continue
        }

        foreach ($file in $files) {
            $content = Get-Content $file -Raw

            if ($file.Name -match "smtp_version_(\d{1,3}(?:\.\d{1,3}){3})_(\d{8}_\d{6})\.txt") {
                $ip = $matches[1]
                $timestamp = $matches[2]
                $port = "25"
                $module = "smtp_version"
                $status = if ($content -match "

\[\*\]

 Auxiliary module execution completed") {
                    "Completed"
                } else {
                    "Unknown"
                }

                $banner = ""
                if ($content -match "SMTP\s+220\s+(.+?)\\x0d\\x0a") {
                    $banner = "220 " + $matches[1].Trim()
                }

                $results += [PSCustomObject]@{
                    IP        = $ip
                    Port      = $port
                    Timestamp = $timestamp
                    Module    = $module
                    Status    = $status
                    Banner    = $banner
                }

                Write-Log -Message "Parsed SMTP version result for $ip ➝ Banner: '$banner'" -Level "INFO"
            } else {
                Write-Log -Message "Filename format unexpected: $($file.Name)" -Level "WARN"
            }
        }
    }

    if ($results.Count -gt 0) {
        $csvPath = Join-Path $ParsedDir 'smtp_version.csv'
        $txtPath = Join-Path $OutputDir 'smtp_version.txt'
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        $results | Out-File -Encoding ascii -FilePath $txtPath
        Write-Log -Message "Saved SMTP version results to CSV: $csvPath and TXT: $txtPath" -Level "INFO"
        return $results
    } else {
        Write-Log -Message "No SMTP version results were parsed." -Level "WARN"
        return @()
    }
}
function Invoke-SSHEnumParse {
    param(
        [string]$OutputDir,
        [string]$ParsedDir,
        [string[]]$targets
    )

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Log -Message "No target IPs provided for SSH enum parsing." -Level "ERROR"
        return @()
    }

    Write-Log -Message "Starting SSH enum parsing for $($targets.Count) targets..." -Level "INFO"
    $results = @()

    foreach ($target in $targets) {
        $pattern = "ssh_enum_$($target)_*.txt"
        $files = Get-ChildItem -Path $OutputDir -Filter $pattern -ErrorAction SilentlyContinue

        if (-not $files -or $files.Count -eq 0) {
            Write-Log -Message "No output files found for target $target." -Level "WARN"
            continue
        }

        foreach ($file in $files) {
            $content = Get-Content $file -Raw

            if ($file.Name -match "ssh_enum_(\d{1,3}(?:\.\d{1,3}){3})_(\d{8}_\d{6})\.txt") {
                $ip = $matches[1]
                $timestamp = $matches[2]
                $port = "22"
                $module = "ssh_version"
                $status = if ($content -match "

\[\*\]

 Auxiliary module execution completed") {
                    "Completed"
                } else {
                    "Unknown"
                }

                $version = ""
                if ($content -match "SSH server version:\s+(SSH-[^\r\n]+)") {
                    $version = $matches[1].Trim()
                }

                $results += [PSCustomObject]@{
                    IP        = $ip
                    Port      = $port
                    Timestamp = $timestamp
                    Module    = $module
                    Status    = $status
                    Version   = $version
                }

                Write-Log -Message "Parsed SSH version result for $ip ➝ Version: '$version'" -Level "INFO"
            } else {
                Write-Log -Message "Filename format unexpected: $($file.Name)" -Level "WARN"
            }
        }
    }

    if ($results.Count -gt 0) {
        $csvPath = Join-Path $ParsedDir 'ssh_enum.csv'
        $txtPath = Join-Path $OutputDir 'ssh_enum.txt'
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        $results | Out-File -Encoding ascii -FilePath $txtPath
        Write-Log -Message "Saved SSH enum results to CSV: $csvPath and TXT: $txtPath" -Level "INFO"
        return $results
    } else {
        Write-Log -Message "No SSH enum results were parsed." -Level "WARN"
        return @()
    }
}
