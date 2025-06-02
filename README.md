# QUANTUMREADINESS

## Overview

This repository provides tools and scripts to harden Windows TLS/SSL configurations to prepare for the upcoming era of quantum computing. The core component is a PowerShell script that:

- Disables legacy and insecure SSL/TLS protocols (SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1).
- Enables and enforces TLS 1.2 and TLS 1.3 protocols with a curated list of strong cipher suites.
- Applies recommended cipher suite ordering for TLS 1.2 and enables secure TLS 1.3 cipher suites.
- Enables strong cryptography in .NET Framework versions for improved security.
- Ensures system-wide configuration to improve resistance against future quantum attacks on traditional cryptographic algorithms.

---

## Why This Matters

Quantum computers, once fully operational, will have the ability to break many classical cryptographic algorithms currently used to secure internet communications. Preparing systems today to use quantum-resistant or quantum-ready protocols and configurations is crucial to:

- Prevent data breaches caused by cryptographic vulnerabilities.
- Maintain compliance with evolving security standards.
- Protect sensitive data and infrastructure from future quantum threats.

This script hardens your Windows system’s TLS stack by disabling outdated protocols and enabling the strongest available cipher suites, laying a solid foundation for future quantum-safe upgrades.

---

## Features of the Quantum-Safe TLS Hardening Script

- **Disables Legacy Protocols:** Removes support for SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 to eliminate known vulnerabilities.
- **Enables TLS 1.2 and TLS 1.3:** Activates the most secure versions of the TLS protocol.
- **Sets Recommended Cipher Suites:** Applies a carefully curated and ordered list of cipher suites optimized for security and performance.
- **Enables Strong .NET Cryptography:** Configures .NET Framework to use strong cryptographic algorithms for applications dependent on it.
- **Admin Rights Check:** Ensures the script runs with necessary privileges to modify system registry settings.
- **Clear Logging:** Provides console output to track configuration changes and status.

---

## Usage

1. **Run PowerShell as Administrator** to ensure the script has the required permissions.
2. Save the script as `QuantumSafeTLSHardening.ps1`.
3. Execute the script:

    ```powershell
    Set-ExecutionPolicy RemoteSigned -Scope Process
    .\QuantumReadiness.ps1
    ```

4. **Reboot your system** to apply all changes.

---
## Limitations and Future Directions
- This script enforces best-in-class classical TLS security currently available on Windows 11 but does not implement true post-quantum cryptographic algorithms yet.
- For full quantum resistance, integration of post-quantum TLS libraries (e.g., Open Quantum Safe OpenSSL variants) or vendor support is required.
- Keep your Windows updates current as Microsoft may add improved quantum-safe features in the future.

---

## Future Work

- Integration with quantum-safe cipher suites and protocols as they become available on Windows.
- Automated detection and reporting of current TLS configuration status.
- Support for additional Windows versions and server roles.

---

## References

- [Microsoft TLS Best Practices](https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Open Quantum Safe Project](https://openquantumsafe.org)

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
