function Invoke-ShodanScan {
    param(
        [string]$OutputDir,
        [string]$InputType,
        [string]$InputFile,
        [string[]]$targets
    )

    $ParsedDir = Join-Path $OutputDir "parsed"
    if (-not (Test-Path $ParsedDir)) {
        New-Item -ItemType Directory -Path $ParsedDir | Out-Null
    }

    if (-not $targets) {
        if ($InputType -eq 'domain' -and (Test-Path $InputFile)) {
            $targets = Get-Content $InputFile | Where-Object { $_.Trim().Length -gt 0 }
            Write-Log -Message "Loaded domain targets from: $InputFile" -Level "INFO"
        } elseif (Test-Path (Join-Path $OutputDir 'reverse_dns.txt')) {
            $targets = Get-Content (Join-Path $OutputDir 'reverse_dns.txt')
        } else {
            Write-Log -Message "No valid input source found" -Level "ERROR"
            return @()
        }
    }

    foreach ($target in $targets) {
        $target = $target.Trim()
        $OutFile = Join-Path $ParsedDir "Shodan_$($target.Replace('.', '_')).json"

        try {
            $PythonCmd = "python -c `"import subprocess; subprocess.run(['shodan', 'host', '$target', '--format', 'json'], capture_output=True, text=True)`" > `"$OutFile`""
            Invoke-Expression $PythonCmd
            Write-Log -Message "Shodan completed for $target" -Level "INFO"
        } catch {
            Write-Log -Message "Shodan failed for $target — $($_.Exception.Message)" -Level "ERROR"
        }
    }
}