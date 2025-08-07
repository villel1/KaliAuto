#region startup
param (
    [string]$InputFile,
    [ValidateSet("ip", "domain")]
    [string]$InputType = "ip",
    [string]$OutputDir,
    [string]$ParsedDir,
    [string]$PluginDir = (Join-Path $PSScriptRoot '../modules'),
    [string]$ConfigPath = (Join-Path $PSScriptRoot '../config.json'),
    [switch]$Help
)

# help message
if ($Help) {
    Write-Host "`nUsage:"
    Write-Host "  .\main.ps1 [-InputFile <path>] [-InputType ip|domain] [-OutputDir <path>] [-ParsedDir <path>] [-PluginDir <path>] [-ConfigPath <path>] [-Help]"
    Write-Host "`nDefaults:"
    Write-Host "  InputType  = ip"
    Write-Host "  InputFile  = ../targets/ips.list"
    Write-Host "  OutputDir  = ../output"
    Write-Host "  ParsedDir  = ../parsedOutput"
    Write-Host "  PluginDir  = ../modules"
    Write-Host "  ConfigPath = ../modules_config.json"
    exit
}

# load config.json file
if (-not (Test-Path $ConfigPath)) {
    Write-Error "Config file not found: $ConfigPath"
    exit
}
$config = Get-Content $ConfigPath | ConvertFrom-Json

# Set defaults
if (-not $InputFile)  { $InputFile  = (Join-Path $PSScriptRoot '../targets/ips.list') }
if (-not $OutputDir)  { $OutputDir  = (Join-Path $PSScriptRoot '../output') }
if (-not $ParsedDir)  { $ParsedDir  = (Join-Path $PSScriptRoot '../parsedOutput') }

# check for output directories and create if they don’t exist
foreach ($dir in @($OutputDir, $ParsedDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}

# Validate input file
if (-not (Test-Path $InputFile)) {
    Write-Warning "Input file not found: $InputFile"
    exit
}
#endregion

#region modules
# Load all available plugins
Get-ChildItem $PluginDir -Filter "*.psm1" | ForEach-Object {
    try {
        Import-Module $_.FullName -Force -ErrorAction Stop
    } catch {
        Write-Warning "Failed to import: $($_.Name)"
    }
}
#endregion

#region recon
$logSummary = @()

# Run helper for input type
switch ($InputType) {
    'ip'     { Invoke-ReverseLookupOnIPs -InputFile $InputFile -OutputDir $OutputDir -ParsedDir $ParsedDir }
    'domain' { Invoke-DomainsToIPs      -InputFile $InputFile -OutputDir $OutputDir -ParsedDir $ParsedDir }
}

# Run all enabled modules
foreach ($entry in $config.PSObject.Properties) {
    if ($entry.Name -like 'run_*' -and $entry.Value -eq $true) {
        $functionName = "Invoke-$($entry.Name -replace '^run_','')"
        $status = "SKIPPED"

        if (Get-Command $functionName -ErrorAction SilentlyContinue) {
            try {
                & $functionName -InputFile $InputFile -OutputDir $OutputDir -ParsedDir $ParsedDir -InputType $InputType
                $status = "RUN"
            } catch {
                Write-Warning "Error executing ${functionName}: $_"
            }
        } else {
            Write-Warning "Function not found: $functionName"
        }

        $logSummary += "$functionName`: $status"
    }
}

# Save scan summary
$logSummary | Out-File "$OutputDir\scan_summary.log" -Force
#endregion