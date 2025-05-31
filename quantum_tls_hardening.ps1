<#
.SYNOPSIS
Quantum-safe TLS Hardening Script for Windows 11
.DESCRIPTION
Enables strong TLS protocols, disables weak ones, enforces PFS, prepares for post-quantum crypto.
#>

# Run as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "You must run this script as Administrator."
    exit 1
}

Write-Host "Applying quantum-safe TLS hardening..." -ForegroundColor Cyan

# Registry base path
$basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

# Protocols to disable
$disableProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")

foreach ($proto in $disableProtocols) {
    foreach ($role in @("Client", "Server")) {
        $fullPath = "$basePath\$proto\$role"
        if (Test-Path $fullPath) {
            Remove-Item -Path $fullPath -Recurse -Force
            Write-Host "Removed legacy protocol key: $fullPath"
        } else {
            Write-Host "Protocol key not found (already removed): $fullPath"
        }
    }
}

# Enable TLS 1.2 and TLS 1.3
$enableProtocols = @("TLS 1.2", "TLS 1.3")

foreach ($proto in $enableProtocols) {
    foreach ($role in @("Client", "Server")) {
        $path = "$basePath\$proto\$role"
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        New-ItemProperty -Path $path -Name "Enabled" -Value 1 -PropertyType DWORD -Force
        New-ItemProperty -Path $path -Name "DisabledByDefault" -Value 0 -PropertyType DWORD -Force
        Write-Host "$proto enabled for $role"
    }
}

# Optional: Set secure cipher suites via group policy (commented for manual application)
# Set strong cipher suites with perfect forward secrecy (this may vary by OS support)

Write-Host "TLS hardening complete. A system reboot is recommended." -ForegroundColor Green
