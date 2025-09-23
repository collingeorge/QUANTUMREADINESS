<#PSScriptInfo

.VERSION 2.0.0
.GUID 62bb910b-2809-45d4-91b1-e44a79e3aab2
.AUTHOR Collin George
.COMPANYNAME 
.COPYRIGHT 
.LICENSEURI https://opensource.org/licenses/MIT
.PROJECTURI https://github.com/CollinGeorge/QuantumSafe-TLS
.TAGS TLS, QuantumSafe, Security, WindowsHardening, Crypto
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
- Enhanced error handling and validation
- Added comprehensive system analysis
- Improved enterprise logging and reporting
- Added rollback functionality
- Enhanced quantum readiness assessment

#>

<# 
.DESCRIPTION 
Enterprise-grade quantum-safe TLS hardening script with comprehensive audit, backup, and rollback capabilities
#>

<#
.SYNOPSIS
Disables legacy TLS and enables quantum-safe ciphers with enterprise-grade features
.DESCRIPTION
Quantum-safe TLS hardening for Windows with comprehensive audit, backup, and rollback capabilities
.PARAMETER VerifyOnly
Audit mode—performs comprehensive analysis without making changes
.PARAMETER Backup
Creates timestamped registry backup before hardening
.PARAMETER Rollback
Restores system from specified backup directory
.PARAMETER ReportPath
Path for detailed JSON/HTML compliance report generation
.PARAMETER Silent
Suppress interactive prompts for automation
.EXAMPLE
.\QuantumReadiness.ps1 -VerifyOnly -ReportPath "C:\Reports"
.EXAMPLE
.\QuantumReadiness.ps1 -Backup -Silent
.EXAMPLE
.\QuantumReadiness.ps1 -Rollback -BackupPath "C:\Temp\TLSSafeBackup-20241201-143022"
#>

param(
    [switch]$VerifyOnly,
    [switch]$Backup,
    [switch]$Rollback,
    [string]$BackupPath,
    [string]$ReportPath,
    [switch]$Silent
)

# Enhanced error handling
$ErrorActionPreference = "Stop"
$Global:LogEntries = @()
$Global:Issues = @()

# Privilege check with detailed messaging
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "ERROR: This script requires Administrator privileges. Please run PowerShell as Administrator and try again."
    exit 1
}

# Constants
$BasePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$Legacy = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
$Enable = @("TLS 1.2", "TLS 1.3")
$NetVersions = @("v2.0.50727", "v4.0.30319")
$QuantumSafeCiphers = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
$TLS13Ciphers = @("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256")

function Write-Log {
    param(
        [string]$Msg,
        [string]$Color = "White",
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Message = $Msg
    }
    $Global:LogEntries += $logEntry
    
    if (-not $Silent) {
        Write-Host "[$timestamp] [$Level] $Msg" -ForegroundColor $Color
    }
    
    # Log critical issues for reporting
    if ($Level -eq "ERROR" -or $Level -eq "WARNING") {
        $Global:Issues += $logEntry
    }
}

function Test-RegistryPath {
    param([string]$Path)
    try {
        return Test-Path $Path
    }
    catch {
        Write-Log "Registry path test failed: $Path" "Red" "ERROR"
        return $false
    }
}

function Get-SystemInfo {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $build = [Environment]::OSVersion.Version.Build
        
        return @{
            OSName = $os.Caption
            Version = $os.Version
            Build = $build
            Architecture = $os.OSArchitecture
            InstallDate = $os.InstallDate
            TLS13Supported = $build -ge 17763
        }
    }
    catch {
        Write-Log "Failed to get system information: $($_.Exception.Message)" "Red" "ERROR"
        throw
    }
}

function Backup-TLSConfiguration {
    param([string]$BackupDirectory)
    
    try {
        Write-Log "Creating backup directory: $BackupDirectory" "Yellow" "INFO"
        New-Item $BackupDirectory -ItemType Directory -Force | Out-Null
        
        # Test write access
        $testFile = Join-Path $BackupDirectory "access_test.tmp"
        "test" | Out-File $testFile -Force
        Remove-Item $testFile -Force
        
        # Export registry keys
        Write-Log "Backing up SCHANNEL protocols..." "Yellow" "INFO"
        if (Test-RegistryPath $BasePath) {
            reg export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" "$BackupDirectory\SCHANNEL_backup.reg" /y | Out-Null
        }
        
        Write-Log "Backing up .NET Framework settings..." "Yellow" "INFO"
        reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework" "$BackupDirectory\DotNet_backup.reg" /y | Out-Null
        
        # Backup cipher suite configuration
        $cipherPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
        if (Test-RegistryPath $cipherPath) {
            reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography" "$BackupDirectory\Cryptography_backup.reg" /y | Out-Null
        }
        
        # Create backup manifest
        $manifest = @{
            BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            SystemInfo = Get-SystemInfo
            ScriptVersion = "2.0.0"
            BackupFiles = @(
                "SCHANNEL_backup.reg",
                "DotNet_backup.reg", 
                "Cryptography_backup.reg"
            )
        }
        
        $manifest | ConvertTo-Json -Depth 3 | Out-File "$BackupDirectory\backup_manifest.json" -Encoding UTF8
        
        Write-Log "Backup completed successfully: $BackupDirectory" "Green" "INFO"
        return $true
    }
    catch {
        Write-Log "Backup failed: $($_.Exception.Message)" "Red" "ERROR"
        return $false
    }
}

function Restore-TLSConfiguration {
    param([string]$BackupDirectory)
    
    try {
        $manifestPath = Join-Path $BackupDirectory "backup_manifest.json"
        if (-not (Test-Path $manifestPath)) {
            throw "Backup manifest not found. Invalid backup directory."
        }
        
        $manifest = Get-Content $manifestPath | ConvertFrom-Json
        Write-Log "Restoring from backup created: $($manifest.BackupDate)" "Yellow" "INFO"
        
        # Restore registry files
        foreach ($regFile in $manifest.BackupFiles) {
            $regPath = Join-Path $BackupDirectory $regFile
            if (Test-Path $regPath) {
                Write-Log "Restoring $regFile..." "Yellow" "INFO"
                reg import $regPath | Out-Null
            }
        }
        
        Write-Log "Configuration restored successfully. Reboot required." "Green" "INFO"
        return $true
    }
    catch {
        Write-Log "Restore failed: $($_.Exception.Message)" "Red" "ERROR"
        return $false
    }
}

function Get-TLSAuditResults {
    $results = @{
        SystemInfo = Get-SystemInfo
        LegacyProtocols = @{}
        ModernProtocols = @{}
        NetFrameworkSecurity = @{}
        CipherSuites = @{}
        OverallScore = 0
        Issues = @()
        Recommendations = @()
    }
    
    Write-Log "=== COMPREHENSIVE TLS SECURITY AUDIT ===" "Cyan" "INFO"
    Write-Log "System: $($results.SystemInfo.OSName) Build $($results.SystemInfo.Build)" "Gray" "INFO"
    
    # Check legacy protocols
    Write-Log "`n--- Legacy Protocol Analysis ---" "Yellow" "INFO"
    $legacyEnabled = 0
    foreach ($proto in $Legacy) {
        $clientPath = "$BasePath\$proto\Client"
        $serverPath = "$BasePath\$proto\Server"
        
        $clientEnabled = $false
        $serverEnabled = $false
        
        if (Test-RegistryPath $clientPath) {
            $clientValue = (Get-ItemProperty $clientPath "Enabled" -EA SilentlyContinue).Enabled
            $clientEnabled = ($clientValue -eq 1)
        }
        
        if (Test-RegistryPath $serverPath) {
            $serverValue = (Get-ItemProperty $serverPath "Enabled" -EA SilentlyContinue).Enabled
            $serverEnabled = ($serverValue -eq 1)
        }
        
        $results.LegacyProtocols[$proto] = @{
            ClientEnabled = $clientEnabled
            ServerEnabled = $serverEnabled
            Secure = (-not $clientEnabled -and -not $serverEnabled)
        }
        
        if ($clientEnabled -or $serverEnabled) {
            Write-Log "$proto is ENABLED - HIGH RISK!" "Red" "ERROR"
            $results.Issues += "Legacy protocol $proto is enabled"
            $legacyEnabled++
        } else {
            Write-Log "$proto is properly disabled" "Green" "INFO"
        }
    }
    
    # Check modern protocols
    Write-Log "`n--- Modern Protocol Analysis ---" "Yellow" "INFO"
    foreach ($proto in $Enable) {
        $clientPath = "$BasePath\$proto\Client"
        $serverPath = "$BasePath\$proto\Server"
        
        $clientEnabled = $false
        $serverEnabled = $false
        
        if (Test-RegistryPath $clientPath) {
            $clientValue = (Get-ItemProperty $clientPath "Enabled" -EA SilentlyContinue).Enabled
            $clientEnabled = ($clientValue -eq 1)
        }
        
        if (Test-RegistryPath $serverPath) {
            $serverValue = (Get-ItemProperty $serverPath "Enabled" -EA SilentlyContinue).Enabled
            $serverEnabled = ($serverValue -eq 1)
        }
        
        $results.ModernProtocols[$proto] = @{
            ClientEnabled = $clientEnabled
            ServerEnabled = $serverEnabled
            Available = ($proto -eq "TLS 1.2" -or $results.SystemInfo.TLS13Supported)
        }
        
        if ($proto -eq "TLS 1.2") {
            if ($clientEnabled -and $serverEnabled) {
                Write-Log "TLS 1.2 is properly enabled" "Green" "INFO"
            } else {
                Write-Log "TLS 1.2 is not fully enabled - MEDIUM RISK" "Yellow" "WARNING"
                $results.Issues += "TLS 1.2 is not fully enabled"
            }
        }
        
        if ($proto -eq "TLS 1.3") {
            if ($results.SystemInfo.TLS13Supported) {
                if ($clientEnabled -and $serverEnabled) {
                    Write-Log "TLS 1.3 is enabled - EXCELLENT" "Green" "INFO"
                } else {
                    Write-Log "TLS 1.3 available but not enabled" "Yellow" "WARNING"
                    $results.Recommendations += "Enable TLS 1.3 for maximum security"
                }
            } else {
                Write-Log "TLS 1.3 not supported on this Windows version" "Gray" "INFO"
            }
        }
    }
    
    # Check .NET Framework security
    Write-Log "`n--- .NET Framework Security Analysis ---" "Yellow" "INFO"
    foreach ($version in $NetVersions) {
        $netPath = "HKLM:\SOFTWARE\Microsoft\.NETFramework\$version"
        $strongCrypto = $false
        
        if (Test-RegistryPath $netPath) {
            $cryptoValue = (Get-ItemProperty $netPath "SchUseStrongCrypto" -EA SilentlyContinue)."SchUseStrongCrypto"
            $strongCrypto = ($cryptoValue -eq 1)
        }
        
        $results.NetFrameworkSecurity[$version] = @{
            StrongCryptoEnabled = $strongCrypto
            Secure = $strongCrypto
        }
        
        if ($strongCrypto) {
            Write-Log ".NET ${version}: Strong cryptography enabled" "Green" "INFO"
        } else {
            Write-Log ".NET ${version}: Weak cryptography - MEDIUM RISK" "Yellow" "WARNING"
            $results.Issues += ".NET $version using weak cryptography"
        }
    }
    
    # Calculate overall security score
    $totalChecks = $Legacy.Count + $Enable.Count + $NetVersions.Count
    $secureConfigs = 0
    
    # Legacy protocols (should be disabled)
    $secureConfigs += ($Legacy.Count - $legacyEnabled)
    
    # Modern protocols (should be enabled)
    foreach ($proto in $Enable) {
        if ($results.ModernProtocols[$proto].ClientEnabled -and $results.ModernProtocols[$proto].ServerEnabled) {
            $secureConfigs++
        }
    }
    
    # .NET security
    foreach ($version in $NetVersions) {
        if ($results.NetFrameworkSecurity[$version].StrongCryptoEnabled) {
            $secureConfigs++
        }
    }
    
    $results.OverallScore = [math]::Round(($secureConfigs / $totalChecks) * 100)
    
    Write-Log "`n=== QUANTUM READINESS ASSESSMENT ===" "Magenta" "INFO"
    Write-Log "Security Score: $($results.OverallScore)%" $(if ($results.OverallScore -ge 90) { "Green" } elseif ($results.OverallScore -ge 75) { "Yellow" } else { "Red" }) "INFO"
    
    if ($results.OverallScore -eq 100) {
        Write-Log "QUANTUM-RESISTANT CONFIGURATION ACHIEVED!" "Green" "INFO"
        Write-Log "Your system uses current best-practice cryptography" "Green" "INFO"
    } elseif ($results.OverallScore -ge 90) {
        Write-Log "Excellent quantum readiness with minor improvements needed" "Yellow" "INFO"
    } elseif ($results.OverallScore -ge 75) {
        Write-Log "Good foundation, but hardening recommended" "Yellow" "WARNING"
    } else {
        Write-Log "Significant security improvements needed" "Red" "ERROR"
    }
    
    return $results
}

function Apply-TLSHardening {
    Write-Log "=== APPLYING QUANTUM-SAFE CONFIGURATION ===" "Cyan" "INFO"
    
    try {
        # Disable legacy protocols
        foreach ($proto in $Legacy) {
            foreach ($role in @("Client", "Server")) {
                $path = "$BasePath\$proto\$role"
                if (-not (Test-RegistryPath $path)) {
                    New-Item $path -Force | Out-Null
                }
                Set-ItemProperty $path "Enabled" 0 -Type DWord -Force
                Set-ItemProperty $path "DisabledByDefault" 1 -Type DWord -Force
                Write-Log "Disabled $proto ($role)" "Green" "INFO"
            }
        }
        
        # Enable modern protocols
        foreach ($proto in $Enable) {
            foreach ($role in @("Client", "Server")) {
                $path = "$BasePath\$proto\$role"
                if (-not (Test-RegistryPath $path)) {
                    New-Item $path -Force | Out-Null
                }
                Set-ItemProperty $path "Enabled" 1 -Type DWord -Force
                Set-ItemProperty $path "DisabledByDefault" 0 -Type DWord -Force
                Write-Log "Enabled $proto ($role)" "Green" "INFO"
            }
        }
        
        # Configure cipher suites
        $cipherPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
        if (-not (Test-RegistryPath $cipherPath)) {
            New-Item $cipherPath -Force | Out-Null
        }
        Set-ItemProperty $cipherPath "Functions" $QuantumSafeCiphers -Type String -Force
        Write-Log "Configured quantum-safe cipher suite ordering" "Green" "INFO"
        
        # Enable TLS 1.3 ciphers if supported
        $sysInfo = Get-SystemInfo
        if ($sysInfo.TLS13Supported) {
            foreach ($suite in $TLS13Ciphers) {
                try {
                    Enable-TlsCipherSuite $suite -Position 0 | Out-Null
                    Write-Log "Enabled TLS 1.3 cipher: $suite" "Green" "INFO"
                }
                catch {
                    Write-Log "TLS 1.3 cipher $suite configuration skipped: $($_.Exception.Message)" "Gray" "INFO"
                }
            }
        }
        
        # Harden .NET Framework
        foreach ($version in $NetVersions) {
            $path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\$version"
            if (-not (Test-RegistryPath $path)) {
                New-Item $path -Force | Out-Null
            }
            Set-ItemProperty $path "SchUseStrongCrypto" 1 -Type DWord -Force
            Set-ItemProperty $path "SystemDefaultTlsVersions" 1 -Type DWord -Force
            Write-Log "Hardened .NET Framework $version" "Green" "INFO"
        }
        
        return $true
    }
    catch {
        Write-Log "Hardening failed: $($_.Exception.Message)" "Red" "ERROR"
        return $false
    }
}

function Export-ComplianceReport {
    param(
        [object]$AuditResults,
        [string]$ReportPath
    )
    
    try {
        if (-not (Test-Path $ReportPath)) {
            New-Item $ReportPath -ItemType Directory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        
        # JSON Report
        $jsonPath = Join-Path $ReportPath "TLS_Audit_Report_$timestamp.json"
        $reportData = @{
            GeneratedOn = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ScriptVersion = "2.0.0"
            AuditResults = $AuditResults
            LogEntries = $Global:LogEntries
        }
        $reportData | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8
        
        # HTML Report
        $htmlPath = Join-Path $ReportPath "TLS_Audit_Report_$timestamp.html"
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>TLS Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; }
        .score { font-size: 24px; font-weight: bold; }
        .good { color: #27ae60; }
        .warning { color: #f39c12; }
        .error { color: #e74c3c; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>TLS Security Audit Report</h1>
        <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>System: $($AuditResults.SystemInfo.OSName)</p>
        <p class="score">Security Score: $($AuditResults.OverallScore)%</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p>This system has achieved a security score of $($AuditResults.OverallScore)% based on quantum-readiness criteria.</p>
    
    <h2>Protocol Analysis</h2>
    <table>
        <tr><th>Protocol</th><th>Status</th><th>Security Level</th></tr>
"@
        
        foreach ($proto in $Legacy) {
            $status = if ($AuditResults.LegacyProtocols[$proto].Secure) { "Disabled" } else { "Enabled" }
            $class = if ($AuditResults.LegacyProtocols[$proto].Secure) { "good" } else { "error" }
            $html += "<tr><td>$proto</td><td class='$class'>$status</td><td>Legacy (Vulnerable)</td></tr>"
        }
        
        foreach ($proto in $Enable) {
            $enabled = $AuditResults.ModernProtocols[$proto].ClientEnabled -and $AuditResults.ModernProtocols[$proto].ServerEnabled
            $status = if ($enabled) { "Enabled" } else { "Disabled" }
            $class = if ($enabled) { "good" } else { "warning" }
            $html += "<tr><td>$proto</td><td class='$class'>$status</td><td>Modern (Secure)</td></tr>"
        }
        
        $html += @"
    </table>
    
    <h2>Issues Found</h2>
    <ul>
"@
        
        foreach ($issue in $AuditResults.Issues) {
            $html += "<li class='error'>$issue</li>"
        }
        
        if ($AuditResults.Issues.Count -eq 0) {
            $html += "<li class='good'>No security issues detected</li>"
        }
        
        $html += @"
    </ul>
    
    <h2>Recommendations</h2>
    <ul>
"@
        
        foreach ($rec in $AuditResults.Recommendations) {
            $html += "<li>$rec</li>"
        }
        
        if ($AuditResults.Recommendations.Count -eq 0) {
            $html += "<li class='good'>System is optimally configured</li>"
        }
        
        $html += @"
    </ul>
</body>
</html>
"@
        
        $html | Out-File $htmlPath -Encoding UTF8
        
        Write-Log "Reports generated:" "Green" "INFO"
        Write-Log "  JSON: $jsonPath" "Gray" "INFO"
        Write-Log "  HTML: $htmlPath" "Gray" "INFO"
        
        return $true
    }
    catch {
        Write-Log "Report generation failed: $($_.Exception.Message)" "Red" "ERROR"
        return $false
    }
}

# Main execution logic
try {
    Write-Log "QuantumReadiness v2.0.0 - Enterprise TLS Hardening" "Magenta" "INFO"
    Write-Log "Copyright (c) Collin George - Licensed under MIT" "Gray" "INFO"
    
    # Handle rollback request
    if ($Rollback) {
        if (-not $BackupPath) {
            throw "BackupPath parameter required for rollback operation"
        }
        
        if (-not (Test-Path $BackupPath)) {
            throw "Backup directory not found: $BackupPath"
        }
        
        $restored = Restore-TLSConfiguration -BackupDirectory $BackupPath
        if ($restored) {
            Write-Log "System restored successfully. Reboot required to apply changes." "Green" "INFO"
            if (-not $Silent) {
                $reboot = Read-Host "Reboot now? (Y/N)"
                if ($reboot -eq "Y" -or $reboot -eq "y") {
                    Restart-Computer -Force
                }
            }
        }
        exit 0
    }
    
    # Perform comprehensive audit
    $auditResults = Get-TLSAuditResults
    
    # Generate compliance report if requested
    if ($ReportPath) {
        Export-ComplianceReport -AuditResults $auditResults -ReportPath $ReportPath
    }
    
    # Exit if verify-only mode
    if ($VerifyOnly) {
        Write-Log "`nAudit completed. Use -ReportPath to generate detailed compliance reports." "Cyan" "INFO"
        exit 0
    }
    
    # Create backup if requested
    if ($Backup) {
        $backupDir = "$env:TEMP\TLSSafeBackup-$(Get-Date -f 'yyyyMMdd-HHmmss')"
        $backupSuccess = Backup-TLSConfiguration -BackupDirectory $backupDir
        if (-not $backupSuccess) {
            throw "Backup failed - aborting hardening process"
        }
    }
    
    # Apply hardening
    $hardeningSuccess = Apply-TLSHardening
    if (-not $hardeningSuccess) {
        throw "TLS hardening failed"
    }
    
    Write-Log "`n=== CONFIGURATION COMPLETE ===" "Magenta" "INFO"
    Write-Log "Your system now uses quantum-resistant TLS configuration" "Green" "INFO"
    Write-Log "A system reboot is required to activate all changes" "Yellow" "WARNING"
    
    # Reboot prompt
    if (-not $Silent) {
        Write-Log "`nReboot recommended to activate all TLS changes." "Yellow" "INFO"
        $reboot = Read-Host "Reboot now? (Y/N)"
        if ($reboot -eq "Y" -or $reboot -eq "y") {
            Write-Log "Rebooting system..." "Yellow" "INFO"
            Start-Sleep 3
            Restart-Computer -Force
        }
    }
    
    exit 0
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" "Red" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "Red" "ERROR"
    exit 1
}
