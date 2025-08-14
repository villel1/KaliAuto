function Invoke-theHarvesterScan {
    param(
        [string]$OutputDir,
        [string]$ParsedDir,
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
        $OutFile_base = Join-Path $ParsedDir "theHarvester_$target"

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
