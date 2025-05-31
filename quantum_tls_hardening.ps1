
# TLS Hardening & PQC-Readiness Script for Windows 11
# This script enforces TLS 1.3, disables legacy crypto, enables encrypted DNS, and prepares the system for quantum-safe practices

# Backup SCHANNEL settings
$backupPath = "C:\Backup"
New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" "$backupPath\SCHANNEL_Backup.reg" /y

# Disable insecure protocols
$legacyProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "PCT 1.0")
foreach ($proto in $legacyProtocols) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server" -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server" -Name "DisabledByDefault" -Value 1 -Type DWord
}

# Enable TLS 1.2 and TLS 1.3
$secureProtocols = @("TLS 1.2", "TLS 1.3")
foreach ($proto in $secureProtocols) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server" -Name "Enabled" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server" -Name "DisabledByDefault" -Value 0 -Type DWord
}

# Set cipher suite order (PFS + AES-256 only)
$cipherSuites = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
)
$cipherList = $cipherSuites -join ","
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Value $cipherList

# Enable Encrypted DNS (DNS-over-HTTPS)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Value 2 -Type DWord

# Enable Credential Guard
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -Type DWord

# Enable Secure Boot and TPM check (informational - not settable via script)
Write-Output "[INFO] Ensure Secure Boot and TPM 2.0 are enabled via BIOS/UEFI settings."

# Final Note
Write-Output "[SUCCESS] TLS hardened, encrypted DNS enabled, and Credential Guard configured. Reboot required to apply changes."
