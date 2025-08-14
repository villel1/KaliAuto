function Invoke-ReconNGScan {
    param (
        [string]$InputType,
        [string]$InputFile,
        [string]$OutputDir = "$PSScriptRoot/../output",
        [string]$rcPath = "$PSScriptRoot/../rcFiles",
        [string]$Module,
        [string[]]$targets,
        [string]$OptionName = "SOURCE",
        [Parameter(Mandatory=$true)][string]$ScanName
    )

    if (-not $targets) {
        $targets = Get-Content (Join-Path $OutputDir 'reverse_dns.txt')
    }

    foreach ($target in $targets) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logPath = Join-Path $OutputDir "${ScanName}_${target}_$timestamp.txt"

        if (-not (Test-Path $rcPath)) {
            New-Item -ItemType Directory -Path $rcPath | Out-Null
        }

        $rcContent = @"
workspaces create ${ScanName}_${target}
add domains $target
modules load $Module
options set $OptionName $target
run
exit
"@

        try {
            $rcContent | Set-Content $rcFile
            Write-Log -Message "Created RC file for $target at $rcFile" -Level "INFO"
        } catch {
            Write-Log -Message "Failed to create RC file for ${target}: $_" -Level "ERROR"
            continue
        }

        Write-Log -Message "Running $ScanName scan on $target..." -Level "INFO"
        try {
            recon-ng -r $rcFile | Tee-Object -FilePath $logPath
            Write-Log -Message "$ScanName scan complete for $target — output saved to $logPath" -Level "INFO"
        } catch {
            Write-Log -Message "Recon-ng execution failed for ${target}: $_" -Level "ERROR"
        }
    }

    Write-Log -Message "Completed Invoke-ReconNGScan execution for $ScanName." -Level "INFO"
}