function Invoke-theHarvesterScan {
    param(
        [string]$OutputDir,
        [string]$InputType,
        [string]$InputFile,
        [string[]]$targets,
        [string]$source = "all",
        [int]$limit = 100
    )

    if (-not $targets) {
        if ($InputType -eq 'domain') {
            if (Test-Path $InputFile) {
                $targets = Get-Content $InputFile | Where-Object { $_.Trim().Length -gt 0 }
                Write-Log -Message "Loaded domain targets from: $InputFile" -Level "INFO"
            } else {
                Write-Log -Message "Domain input file not found: $InputFile" -Level "WARNING"
            }
        } else {
            $targets = Get-Content (Join-Path $OutputDir 'reverse_dns.txt')
        }
    }

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Log -Message "No domains provided or found — skipping theHarvester scan" -Level "ERROR"
        return @()
    }

    foreach ($target in $targets) {
        $target = $target.Trim()
        $OutFile_base = Join-Path $OutputDir "theHarvester_$target"

        Write-Log -Message "Running theHarvester for $target using source '$source'" -Level "INFO"
        try {
            $Command = "theHarvester -d $target -b $source -l $limit -f $OutFile_base -s -n"
            Invoke-Expression "$Command"
            Write-Log -Message "theHarvester completed for $target — results saved to HTML and JSON" -Level "INFO"
        } catch {
            Write-Log -Message "theHarvester failed for $target — $($_.Exception.Message)" -Level "ERROR"
        }
    }
}
function Invoke-theHarvesterParser {
    param (
        [string]$ParsedDir,
        [string]$OutputDir
    )

    # Create output directory if needed
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }

    $xmlFiles = Get-ChildItem -Path $OutputDir -Filter "theHarvester_*.xml"
    $parsedResults = @()

    foreach ($file in $xmlFiles) {
        try {
            [xml]$xmlData = Get-Content $file.FullName
            $domain = ($file.BaseName -replace '^theHarvester_', '')

            foreach ($email in $xmlData.theHarvester.emails.email) {
                $parsedResults += [PSCustomObject]@{
                    Domain     = $domain
                    Type       = "Email"
                    Value      = $email
                    SourceFile = $file.Name
                }
            }

            foreach ($hostNode in $xmlData.theHarvester.hosts.host) {
                $parsedResults += [PSCustomObject]@{
                    Domain     = $domain
                    Type       = "Host"
                    Value      = $hostNode
                    SourceFile = $file.Name
                }
            }

            foreach ($ip in $xmlData.theHarvester.ips.ip) {
                $parsedResults += [PSCustomObject]@{
                    Domain     = $domain
                    Type       = "IP"
                    Value      = $ip
                    SourceFile = $file.Name
                }
            }

            Write-Log -Message "Parsed theHarvester XML: $($file.Name)" -Level "INFO"
        } catch {
            Write-Log -Message "Failed to parse $($file.Name): $($_.Exception.Message)" -Level "ERROR"
        }
    }

    $csvPath = Join-Path $ParsedDir "theHarvester_summary.csv"
    $parsedResults | Export-Csv -Path $csvPath -NoTypeInformation -Force
    Write-Log -Message "Saved parsed theHarvester results to $csvPath" -Level "INFO"
}
