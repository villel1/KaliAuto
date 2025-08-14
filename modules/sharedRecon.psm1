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
function Invoke-Metasploit {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )

    # SSH
    Invoke-MetasploitScan -Ports @(22) -Module "auxiliary/scanner/ssh/ssh_version" -ScanName "ssh_enum" -OutputDir $OutputDir

    # FTP
    Invoke-MetasploitScan -Ports @(21) -Module "auxiliary/scanner/ftp/ftp_version" -ScanName "ftp_version" -OutputDir $OutputDir
    Invoke-MetasploitScan -Ports @(21) -Module "auxiliary/scanner/ftp/ftp_anonymous" -ScanName "ftp_anonymous" -OutputDir $OutputDir

    # SMTP
    Invoke-MetasploitScan -Ports @(25) -Module "auxiliary/scanner/smtp/smtp_version" -ScanName "smtp_version" -OutputDir $OutputDir
    Invoke-MetasploitScan -Ports @(25) -Module "auxiliary/scanner/smtp/smtp_enum" -ScanName "smtp_enum" -OutputDir $OutputDir

    # HTTP
    Invoke-MetasploitScan -Ports @(80,443) -Module "auxiliary/scanner/http/http_version" -ScanName "http_version" -OutputDir $OutputDir
    Invoke-MetasploitScan -Ports @(80,443) -Module "auxiliary/scanner/http/http_enum" -ScanName "http_enum" -OutputDir $OutputDir

    # POP3
    Invoke-MetasploitScan -Ports @(110) -Module "auxiliary/scanner/pop3/pop3_version" -ScanName "pop3_version" -OutputDir $OutputDir
    Invoke-MetasploitScan -Ports @(110) -Module "auxiliary/scanner/pop3/pop3_enum" -ScanName "pop3_enum" -OutputDir $OutputDir

    # IMAP
    Invoke-MetasploitScan -Ports @(143) -Module "auxiliary/scanner/imap/imap_version" -ScanName "imap_version" -OutputDir $OutputDir
    Invoke-MetasploitScan -Ports @(143) -Module "auxiliary/scanner/imap/imap_enum" -ScanName "imap_enum" -OutputDir $OutputDir

    # SNMP
    Invoke-MetasploitScan -Ports @(161) -Module "auxiliary/scanner/snmp/snmp_enum" -ScanName "snmp_enum" -OutputDir $OutputDir
    Invoke-MetasploitScan -Ports @(161) -Module "auxiliary/scanner/snmp/snmp_login" -ScanName "snmp_login" -OutputDir $OutputDir

    # MySQL
    Invoke-MetasploitScan -Ports @(3306) -Module "auxiliary/scanner/mysql/mysql_version" -ScanName "mysql_version" -OutputDir $OutputDir
    Invoke-MetasploitScan -Ports @(3306) -Module "auxiliary/scanner/mysql/mysql_enum" -ScanName "mysql_enum" -OutputDir $OutputDir

    # SMB
    Invoke-MetasploitScan -Ports @(445) -Module "auxiliary/scanner/smb/smb_enumshares" -ScanName "smb_enumshares" -OutputDir $OutputDir
    Invoke-MetasploitScan -Ports @(445) -Module "auxiliary/scanner/smb/smb_enumusers" -ScanName "smb_enumusers" -OutputDir $OutputDir
    Invoke-MetasploitScan -Ports @(445) -Module "auxiliary/scanner/smb/smb_version" -ScanName "smb_version" -OutputDir $OutputDir


    # Parsers
    Invoke-HTTPVersionParse -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-HTTPEnumParse -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-SMTPEnumParse -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-SMTPVersionParse -OutputDir $OutputDir -ParsedDir $ParsedDir
    Invoke-SSHEnumParse -OutputDir $OutputDir -ParsedDir $ParsedDir
}
function Invoke-ReconNG {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )
    Invoke-ReconNGScan -Module "recon/domains-hosts/netcraft" -ScanName "netcraft" -OutputDir $OutputDir
    Invoke-ReconNGScan -Module "recon/domains-hosts/brute_hosts" -ScanName "brute_hosts" -OutputDir $OutputDir
    Invoke-ReconNGScan -Module "recon/domains-hosts/ssl_san" -ScanName "ssl_san" -OutputDir $OutputDir
    Invoke-ReconNGScan -Module "recon/domains-hosts/whois" -ScanName "whois_lookup" -OutputDir $OutputDir
    Invoke-ReconNGScan -Module "recon/domains-contacts/whois_pocs" -ScanName "whois_contacts" -OutputDir $OutputDir
    Invoke-ReconNGScan -Module "recon/hosts-hosts/resolve" -ScanName "dns_resolve" -OutputDir $OutputDir
    Invoke-ReconNGScan -Module "recon/hosts-hosts/reverse_resolve" -ScanName "reverse_dns" -OutputDir $OutputDir
    Invoke-ReconNGScan -Module "recon/hosts-hosts/shodan_hostname" -ScanName "shodan_enrich" -OutputDir $OutputDir
    Invoke-ReconNGScan -Module "recon/domains-contacts/hunter_io" -ScanName "hunter_contacts" -OutputDir $OutputDir
}
function Invoke-theHarvester {
    param (
        [string]$OutputDir,
        [string]$ParsedDir
    )
    Invoke-theHarvesterScan -OutputDir $OutputDir -ParsedDir $ParsedDir -InputType $InputType -targets $targets -source "all" -limit 100
}

function Invoke-Shodan {
    param(
        [string]$OutputDir,
        [string]$ParsedDir
    )

    Invoke-ShodanScan -OutputDir $OutputDir -ParsedDir $ParsedDir -targets $targets -ApiKey $ApiKey
}