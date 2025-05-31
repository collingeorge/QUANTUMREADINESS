# QUANTUMREADINESS

# Windows 11 TLS Hardening & Quantum-Safe Preparation Script

![Windows Logo](https://upload.wikimedia.org/wikipedia/commons/5/5f/Windows_logo_-_2021.svg)

> Harden Windows 11 TLS settings, enforce Perfect Forward Secrecy, and prepare for quantum-safe cryptography.

---

## Overview

This project provides a **PowerShell script** and a **Group Policy registry file** that:

- Disables weak legacy TLS/SSL protocols (SSL 2.0/3.0, TLS 1.0/1.1)
- Enables only TLS 1.2 and TLS 1.3 with strong cipher suites enforcing Perfect Forward Secrecy (PFS)
- Activates DNS-over-HTTPS for encrypted DNS queries
- Enables Windows Credential Guard for enhanced credential security
- Lays groundwork for future quantum-safe cryptographic adoption

---

## Why Harden TLS on Windows 11?

Windows supports legacy crypto protocols that pose security risks and enable traffic interception. Perfect Forward Secrecy ensures session keys cannot be retroactively compromised, and encrypted DNS protects DNS queries from eavesdropping. Preparing for quantum-safe cryptography means your systems will be more resilient against future quantum computer attacks.

---

## Features

- **Legacy Protocols Disabled:** SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 turned off
- **TLS 1.2 & 1.3 Enabled:** Only secure and modern protocols allowed
- **Cipher Suites Curated:** AES-256 and ECDHE-based ciphers for PFS
- **Encrypted DNS Enabled:** Uses DNS-over-HTTPS (DoH)
- **Credential Guard Enabled:** Protects secrets with virtualization-based security
- **Quantum-Ready:** Prepares Windows for post-quantum TLS upgrades

---

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

```powershell
reg import quantum_tls_gpo.reg
```
- Import on target machines
- Reboot to activate policies

## Important Notes
- Secure Boot and TPM 2.0 must be enabled manually via BIOS/UEFI.
- Current cipher suites use classical algorithms with PFS — quantum-safe algorithms are not yet supported natively by Windows.
- For fully quantum-safe TLS, use hybrid TLS stacks via reverse proxies (e.g., NGINX + OpenQuantumSafe).
- This script builds a solid foundation for current and near-future cryptographic standards.

## License
MIT License — Feel free to use, modify, and distribute.

## Credits
- Inspired by jbratu’s IIS Perfect Forward Secrecy setup script
- Enhanced and extended by ChatGPT (OpenAI)
