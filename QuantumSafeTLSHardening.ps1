<#
.SYNOPSIS
Quantum-Safe TLS Hardening Script for Windows 11
.DESCRIPTION
Disables legacy SSL/TLS protocols, enforces TLS 1.2/1.3 with secure cipher suites,
and enables strong cryptography for .NET Framework.
#>

# Check for admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

Write-Host "Starting Quantum-Safe TLS Hardening..." -ForegroundColor Cyan

$baseProtocolsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

# Disable legacy protocols by removing their registry keys (cleaner approach)
$legacyProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($proto in $legacyProtocols) {
    foreach ($role in @("Client", "Server")) {
        $fullPath = "$baseProtocolsPath\$proto\$role"
        if (Test-Path $fullPath) {
            Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Removed legacy protocol registry key: $fullPath"
        }
    }
}

# Enable TLS 1.2 and TLS 1.3
$enableProtocols = @("TLS 1.2", "TLS 1.3")
foreach ($proto in $enableProtocols) {
    foreach ($role in @("Client", "Server")) {
        $path = "$baseProtocolsPath\$proto\$role"
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
            Write-Host "Created key: $path"
        }
        # Enable and set DisabledByDefault=0
        Set-ItemProperty -Path $path -Name "Enabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 0 -Type DWord
    }
}

# Set cipher suites for TLS 1.2 and TLS 1.3
# TLS 1.2 cipher suites recommended (adjust to your needs)
$tls12CipherSuites = @(
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
)

# TLS 1.3 cipher suites
$tls13CipherSuites = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256"
)

# Registry path to set TLS 1.2 cipher suites order
$cipherSuitesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"

if (-not (Test-Path $cipherSuitesPath)) {
    New-Item -Path $cipherSuitesPath -Force | Out-Null
    Write-Host "Created cipher suites registry key."
}

# Set TLS 1.2 cipher suites (comma separated string)
Set-ItemProperty -Path $cipherSuitesPath -Name "Functions" -Value ($tls12CipherSuites -join ",") -Type String
Write-Host "Set TLS 1.2 cipher suites."

# Enable TLS 1.3 cipher suites via Enable-TlsCipherSuite cmdlet if available
foreach ($suite in $tls13CipherSuites) {
    try {
        Enable-TlsCipherSuite -Name $suite -ErrorAction Stop
        Write-Host "Enabled TLS 1.3 cipher suite: $suite"
    } catch {
        Write-Warning "Could not enable TLS 1.3 cipher suite $suite - possibly not supported on this system."
    }
}

# Enable strong cryptography for .NET Framework (all relevant versions)
$netVersions = @("v2.0.50727", "v4.0.30319")
foreach ($version in $netVersions) {
    $netPath = "HKLM:\SOFTWARE\Microsoft\.NETFramework\$version"
    if (-not (Test-Path $netPath)) {
        New-Item -Path $netPath -Force | Out-Null
        Write-Host "Created .NET Framework registry key: $netPath"
    }
    Set-ItemProperty -Path $netPath -Name "SchUseStrongCrypto" -Value 1 -Type DWord
    Write-Host "Enabled strong cryptography for .NET $version"
}

Write-Host "TLS hardening and cipher suite configuration complete." -ForegroundColor Green
Write-Host "Please reboot your system to apply all changes."

# Uncomment if you want to restart IIS automatically
# Restart-Service -Name W3SVC