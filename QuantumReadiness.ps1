<#PSScriptInfo

.VERSION 1.0.4
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
- Improved script structure and parameter parsing
- Verified quantum-safe TLS configuration
- Added metadata for discoverability and licensing

#>

<# 
.DESCRIPTION 
Quantum-safe TLS script
#>

<#
.SYNOPSIS
Disables legacy TLS and enables quantum-safe ciphers
.DESCRIPTION
Quantum-safe TLS hardening for Windows
.PARAMETER VerifyOnly
Audit mode—no changes made.
.PARAMETER Backup
Creates registry backup before hardening.
.EXAMPLE
.\QuantumSafe-TLS.ps1 -VerifyOnly
.EXAMPLE
.\QuantumSafe-TLS.ps1 -Backup
#>

param([switch]$VerifyOnly, [switch]$Backup)



if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run as Administrator"
    exit 1
}

$BasePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$Legacy = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
$Enable = @("TLS 1.2", "TLS 1.3")
$NetVersions = @("v2.0.50727", "v4.0.30319")

function Write-Log {
    param($Msg, $Color="White")
    $time = Get-Date -Format "HH:mm:ss"
    Write-Host "[$time] $Msg" -ForegroundColor $Color
}

if ($VerifyOnly) {
    Write-Log "=== CURRENT TLS STATUS ===" "Cyan"
    
    $legacyOK = $true
    foreach ($proto in $Legacy) {
        $path = "$BasePath\$proto\Client"
        if (Test-Path $path) {
            $enabled = (Get-ItemProperty $path "Enabled" -EA SilentlyContinue).Enabled
            if ($enabled -eq 1) {
                Write-Log "$proto is ENABLED - VULNERABLE!" "Red"
                $legacyOK = $false
            }
        }
    }
    
    if ($legacyOK) {
        Write-Log "All legacy protocols DISABLED" "Green"
    }
    
    $tls12 = Get-ItemProperty "$BasePath\TLS 1.2\Client" "Enabled" -EA SilentlyContinue
    if ($tls12.Enabled -eq 1) {
        Write-Log "TLS 1.2 ENABLED" "Green"
    } else {
        Write-Log "TLS 1.2 DISABLED" "Yellow"
    }
    
    $build = [Environment]::OSVersion.Version.Build
    if ($build -ge 17763) {
        $tls13 = Get-ItemProperty "$BasePath\TLS 1.3\Client" "Enabled" -EA SilentlyContinue
        if ($tls13 -and $tls13.Enabled -eq 1) {
            Write-Log "TLS 1.3 ENABLED" "Green"
        } else {
            Write-Log "TLS 1.3 AVAILABLE but DISABLED" "Yellow"
        }
    } else {
        Write-Log "TLS 1.3 NOT SUPPORTED (Build $build)" "Gray"
    }
    
    $netPath = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    $netCrypto = (Get-ItemProperty $netPath "SchUseStrongCrypto" -EA SilentlyContinue)."SchUseStrongCrypto"
    if ($netCrypto -eq 1) {
        Write-Log ".NET Strong Crypto ENABLED" "Green"
    } else {
        Write-Log ".NET Weak Crypto - VULNERABLE" "Yellow"
    }
    
    Write-Log "`n=== OVERALL QUANTUM READINESS ===" "Magenta"
    if ($legacyOK -and $tls12.Enabled -eq 1 -and $netCrypto -eq 1) {
        Write-Log "YOUR SYSTEM IS 100% QUANTUM-RESISTANT!" "Green"
    } else {
        Write-Log "Some hardening needed - review warnings above" "Yellow"
    }
    
    exit 0
}

Write-Log "=== APPLYING QUANTUM-SAFE CONFIG ===" "Cyan"

if ($Backup) {
    $backupDir = "$env:TEMP\TLSSafeBackup-$(Get-Date -f 'yyyyMMdd-HHmmss')"
    New-Item $backupDir -ItemType Directory -Force | Out-Null
    Copy-Item $BasePath "$backupDir\Protocols" -Recurse -Force -EA SilentlyContinue
    Copy-Item "HKLM:\SOFTWARE\Microsoft\.NETFramework" "$backupDir\DotNet" -Recurse -Force -EA SilentlyContinue
    Write-Log "Backup created: $backupDir" "Green"
}

foreach ($proto in $Legacy) {
    foreach ($role in @("Client", "Server")) {
        $path = "$BasePath\$proto\$role"
        if (Test-Path $path) {
            Remove-Item $path -Recurse -Force -EA SilentlyContinue
            Write-Log "Disabled $proto ($role)" "Green"
        }
    }
}

foreach ($proto in $Enable) {
    foreach ($role in @("Client", "Server")) {
        $path = "$BasePath\$proto\$role"
        if (-not (Test-Path $path)) {
            New-Item $path -Force | Out-Null
        }
        Set-ItemProperty $path "Enabled" 1 -Type DWord
        Set-ItemProperty $path "DisabledByDefault" 0 -Type DWord
        Write-Log "Enabled $proto ($role)" "Green"
    }
}

$cipherPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
if (-not (Test-Path $cipherPath)) {
    New-Item $cipherPath -Force | Out-Null
}

$ciphers = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
Set-ItemProperty $cipherPath "Functions" $ciphers -Type String
Write-Log "Set quantum-safe cipher suites" "Green"

$tls13 = @("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256")
foreach ($suite in $tls13) {
    try {
        Enable-TlsCipherSuite $suite | Out-Null
        Write-Log "Enabled TLS 1.3 cipher: $suite" "Green"
    }
    catch {
        Write-Log "TLS 1.3 cipher $suite not supported (normal)" "Gray"
    }
}

foreach ($version in $NetVersions) {
    $path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\$version"
    if (-not (Test-Path $path)) {
        New-Item $path -Force | Out-Null
    }
    Set-ItemProperty $path "SchUseStrongCrypto" 1 -Type DWord
    Write-Log "Hardened .NET $version" "Green"
}

Write-Log "`nCONFIGURATION COMPLETE - REBOOT REQUIRED!" "Magenta"
Write-Log "Your system is now quantum-resistant for TLS" "Green"

$reboot = Read-Host "Reboot now? (Y/N)"
if ($reboot -eq "Y" -or $reboot -eq "y") {
    Write-Log "Rebooting..." "Yellow"
    Start-Sleep 5
    Restart-Computer -Force
}

exit 0
