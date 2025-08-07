# filepath: modules/logging.psm1
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO",
        [string]$LogFile = "$PSScriptRoot/../output/framework.log"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp][$Level] $Message"
    Write-Verbose $logEntry -Verbose
    Add-Content -Path $LogFile -Value $logEntry
}
Export-ModuleMember -Function Write-Log