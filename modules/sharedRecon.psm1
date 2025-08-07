function Invoke-InitialRecon {
    param(
        [string]$InputFile,
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Invoke-NmapPingSweep -InputFile $InputFile -OutputDir $OutputDir
    Invoke-hostsParser    -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-Masscan        -OutputDir $OutputDir -PortRange "1-65535" -Rate "1000"
    Invoke-masscanParser  -OutputDir $OutputDir -ParsedDir $ParsedDir
}
function Invoke-DNSrecon {
    param(
        [string]$InputFile,
        [string]$OutputDir,
        [string]$ParsedDir,
        [string]$InputType
    )

    Invoke-DNSRecordQuery -InputFile $InputFile -OutputDir $OutputDir -ParsedDir $ParsedDir -InputType $InputType
    Invoke-dnsreconScan -InputFile $InputFile -OutputDir $OutputDir -ParsedDir $ParsedDir -InputType $InputType
    Invoke-ParseDnsRecon -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-whois -InputFile $InputFile -OutputDir $OutputDir -ParsedDir $ParsedDir -InputType $InputType
}
function Invoke-HTTPrecon {
    param(
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Invoke-CurlScan -OutputDir $OutputDir
    Invoke-CurlParser -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-SSLScan -OutputDir $OutputDir
    Invoke-SSLScanParser -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-NmapHTTP -OutputDir $OutputDir
    Invoke-NmapHTTPParser -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-whatweb -OutputDir $OutputDir
    Invoke-whatwebParser -OutputDir $OutputDir -ParsedDir $ParsedDir
}
function Invoke-SSHrecon {
    param(
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Invoke-SSHnmap -OutputDir $OutputDir
    Invoke-SSHnmapParser -OutputDir $OutputDir -ParsedDir $ParsedDir
}
function Invoke-SMBrecon {
    param(
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Invoke-enum4linux -OutputDir $OutputDir 
    Invoke-enum4linuxParser -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-SMBNmap -OutputDir $OutputDir
    Invoke-NmapSMBParser -OutputDir $OutputDir -ParsedDir $ParsedDir
}
function Invoke-SMTPrecon {
    param(
        [string]$OutputDir,
        [string]$ParsedDir
    )
    Invoke-SMTPnmap -OutputDir $OutputDir 
    Invoke-NmapSMTPParser -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-Swaks -OutputDir $OutputDir
    Invoke-SwaksParser -OutputDir $OutputDir -ParsedDir $ParsedDir
}

function Invoke-SNMPrecon {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )
    Invoke-NmapSNMP -OutputDir $OutputDir
    Invoke-NmapSNMPParser -OutputDir $OutputDir -ParsedDir $ParsedDir
}

function Invoke-FTPrecon {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )
    Invoke-NmapFTP -OutputDir $OutputDir
    Invoke-NmapFTPParser -OutputDir $OutputDir -ParsedDir $ParsedDir
}

function Invoke-Vulnrecon {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )
    Invoke-NmapVuln -OutputDir $OutputDir
    Invoke-NmapVulnParser -OutputDir $OutputDir -ParsedDir $Parsed
    Invoke-CrackMapExec -OutputDir $OutputDir
    Invoke-CMEParserSMB -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-CMEParserSSH -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-CMEParserRDP -OutputDir $OutputDir -ParsedDir $ParsedDir
}

function Invoke-RDPrecon {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )
    Invoke-NmapRDPScan -OutputDir $OutputDir
    Invoke-NmapRDPParser -OutputDir $OutputDir -ParsedDir $ParsedDir
}