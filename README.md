# Windows 11 TLS Hardening & Quantum-Safe Preparation Script

This project provides a PowerShell script and a Group Policy registry file that:

- Disables weak legacy TLS/SSL protocols (SSL 2.0/3.0, TLS 1.0/1.1)
- Enables only TLS 1.2 and TLS 1.3 with strong cipher suites enforcing Perfect Forward Secrecy (PFS)
- Activates DNS-over-HTTPS for encrypted DNS queries
- Enables Windows Credential Guard for enhanced credential security
- Lays groundwork for future quantum-safe cryptographic adoption

## Why Harden TLS on Windows 11?

Windows supports legacy crypto protocols that pose security risks and enable traffic interception. Perfect Forward Secrecy ensures session keys cannot be retroactively compromised, and encrypted DNS protects DNS queries from eavesdropping. Preparing for quantum-safe cryptography means your systems will be more resilient against future quantum computer attacks.

## Features

- Legacy Protocols Disabled: SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 turned off
- TLS 1.2 & 1.3 Enabled: Only secure and modern protocols allowed
- Cipher Suites Curated: AES-256 and ECDHE-based ciphers for PFS
- Encrypted DNS Enabled: Uses DNS-over-HTTPS (DoH)
- Credential Guard Enabled: Protects secrets with virtualization-based security
- Quantum-Ready: Prepares Windows for post-quantum TLS upgrades

## Usage

### PowerShell Script

```powershell
# Run PowerShell as Administrator
.\quantum_tls_hardening.ps1
```

- The script backs up existing SCHANNEL settings
- Applies new TLS and cipher suite policies
- Enables DNS-over-HTTPS and Credential Guard
- Requires reboot to apply changes

### Group Policy Registry File

```powershell
reg import quantum_tls_gpo.reg
```

- Import on target machines
- Reboot to activate policies

## Troubleshooting

**SmartApp Control Blocking Scripts or Registry Files**

Windows 11's SmartApp Control may block running unsigned PowerShell scripts or importing .reg files to protect your system.

### If you encounter blocking issues:

Unblock the file:

- Right-click the file → Properties → Check Unblock → Apply

Run PowerShell script with elevated permissions:

- Open PowerShell as Administrator

Temporarily bypass execution policy:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\quantum_tls_hardening.ps1
```

Import registry files manually:

- Right-click the .reg file → Merge, or open Registry Editor as Administrator and import manually.

Disable SmartApp Control temporarily (not recommended):

- Go to Windows Security → App & browser control → Smart App Control → Toggle Off

Use PowerShell to apply registry keys directly:

- Convert .reg contents into PowerShell commands to apply registry changes without using .reg files
- Manually add registry keys using regedit if file import is blocked
- Digitally sign your scripts or registry files for trusted execution

## Requirements

- Windows 11 24h2
- Admin privileges
- PowerShell 5.0+ (built-in)

## Contribute

Have a trustworthy threat feed to recommend? Submit a pull request or open an issue.

## License

MIT License

## Support

Need help with .reg, .bat, .exe, or GPO/Intune deployment? Open an issue or PR and assistance will be provided.

*Stay secure today, prepare for tomorrow.*
