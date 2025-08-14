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
                Write-Log -Message "Domain input file not found: $InputFile" -Level "WARN"
            }
        } else {
            Write-Log -Message "Unsupported input type for theHarvester: $InputType" -Level "ERROR"
            return @()
        }
    }

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Log -Message "No domains provided or found — skipping theHarvester scan" -Level "ERROR"
        return @()
    }

    foreach ($target in $targets) {
        $target = $target.Trim()
        $OutFile_html = Join-Path $OutputDir "theHarvester_$target.html"
        $OutFile_json = Join-Path $ParsedDir "theHarvester_$target.json"

        Write-Log -Message "Running theHarvester for $target using source '$source'" -Level "INFO"
        try {
            $Command = "theHarvester -d $target -b $source -l $limit -f $OutFile_html -s -n -j $OutFile_json"
            Invoke-Expression "$Command"
            Write-Log -Message "theHarvester completed for $target — results saved to HTML and JSON" -Level "INFO"
        } catch {
            Write-Log -Message "theHarvester failed for $target — $($_.Exception.Message)" -Level "ERROR"
        }
    }
}
