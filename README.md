# QuantumSafe-TLS: Windows TLS Hardening for Post-Quantum Security

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell)](https://learn.microsoft.com/en-us/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Windows](https://img.shields.io/badge/Windows-10/11-green?logo=windows)](https://learn.microsoft.com/en-us/windows/)

**QuantumSafe-TLS** is a PowerShell script that hardens Windows systems against quantum computing threats by disabling vulnerable TLS/SSL protocols, enforcing quantum-safe cipher suites, and enabling strong cryptography for .NET applications. It provides audit, hardening, and backup capabilities for enterprise deployment.

## Why Quantum-Safe TLS?

Quantum computers threaten current encryption:
- **Shor's Algorithm** (2030-2035): Breaks RSA/ECDH key exchange
- **Harvest Now, Decrypt Later**: State actors store encrypted traffic for future decryption
- **Grover's Algorithm**: Reduces AES-128 to AES-64 effective strength

This script ensures your TLS stack uses:
- **ECDHE** for ephemeral, Shor-resistant key exchange
- **AES-256-GCM** for symmetric crypto (Grover-resistant)
- **TLS 1.3** for authenticated encryption without legacy fallbacks

## Features

- ✅ **Audit Mode**: `-VerifyOnly` scans current TLS posture
- ✅ **Hardening**: Disables SSL 2.0/3.0, TLS 1.0/1.1; enables TLS 1.2/1.3
- ✅ **Quantum-Safe Ciphers**: Configures NIST SP 800-52r2 compliant suites
- ✅ **.NET Hardening**: Enables strong crypto for legacy applications
- ✅ **Backup**: `-Backup` creates registry snapshots before changes
- ✅ **Color-Coded Logging**: Real-time status with timestamps
- ✅ **Reboot Integration**: Safe reboot prompt after configuration

---

## Why This Matters

Quantum computers, once fully operational, will have the ability to break many classical cryptographic algorithms currently used to secure internet communications. Preparing systems today to use quantum-resistant or quantum-ready protocols and configurations is crucial to:

- Prevent data breaches caused by cryptographic vulnerabilities.
- Maintain compliance with evolving security standards.
- Protect sensitive data and infrastructure from future quantum threats.

This script hardens your Windows system’s TLS stack by disabling outdated protocols and enabling the strongest available cipher suites, laying a solid foundation for future quantum-safe upgrades.

---

## Features of the Quantum-Safe TLS Hardening Script

- Disables Legacy Protocols: Removes support for SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 to eliminate known vulnerabilities like POODLE and BEAST.
- Enables TLS 1.2 and TLS 1.3: Activates the most secure protocol versions with forward secrecy and authenticated encryption.
- Sets Recommended Cipher Suites: Applies NIST-compliant, ordered list of quantum-safe suites (e.g., TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) for optimal security/performance.
- Enables Strong .NET Cryptography: Configures .NET Framework (v2.0 and v4.0) to use AES-256 and SHA-384, preventing weak fallback algorithms.
- Admin Rights Check: Verifies elevated privileges for registry modifications.
- Clear Logging: Timestamped, color-coded console output to track changes and verification status.

---

## Usage

### Install from PS Gallery:

1. **Run PowerShell as Administrator** to ensure the script has the required permissions.
2. Install PowerShell Module

   ```powershell
   Install-Script QuantumSafe-TLS -Scope CurrentUser
   ```
3. Run the Script

   ```powershell
   # Full execution & Backup (hardens + prompts reboot)
   QuantumSafe-TLS -Backup
   ```
4. Verify Status

   ```powershell
   # Audit current configuration (no changes)
   QuantumSafe-TLS -VerifyOnly
   ```

### From Github:

1. **Run PowerShell as Administrator** to ensure the script has the required permissions.
2. Save the script as `QuantumReadiness.ps1`.
3. Execute the script:

    ```powershell
    # Audit current configuration (no changes)
    .\QuantumReadiness.ps1 -VerifyOnly

    # Apply hardening with backup
    .\QuantumReadiness.ps1 -Backup

    # Full execution (hardens + prompts reboot)
    .\QuantumReadiness.ps1
    ```

4. **Reboot your system** to apply all changes.

## Example Output (VerifyOnly):
```powershell
text[16:00:01] === CURRENT TLS STATUS ===
[16:00:01] All legacy protocols DISABLED
[16:00:01] TLS 1.2 ENABLED
[16:00:01] TLS 1.3 ENABLED
[16:00:01] .NET Strong Crypto ENABLED
[16:00:01] === OVERALL QUANTUM READINESS ===
[16:00:01] YOUR SYSTEM IS 100% QUANTUM-RESISTANT!
```

---

## Limitations and Future Directions

This script enforces best-in-class classical TLS security on Windows 10/11 but does not implement true post-quantum key exchange (e.g., Kyber/Dilithium)—awaiting Microsoft integration.
TLS 1.3 cipher suites may not be fully supported on Windows 10 builds < 1809.
Keep Windows updated, as Microsoft may add enhanced quantum-safe features in future releases.

## Future Work

Certificate Audit: Scan for SHA-1/1024-bit certificates vulnerable to Grover's algorithm.
HSTS Enforcement: Automatic configuration for web servers (IIS/Apache).
Compliance Reporting: JSON/HTML exports for GPO/Intune deployments.
Post-Quantum Integration: Support for OQS-OpenSSL when available on Windows.
Multi-Version Support: Enhanced compatibility for Windows Server 2019+.

## References

- [Microsoft TLS Best Practices](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Open Quantum Safe Project](https://openquantumsafe.org/)

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/collingeorge/QUANTUMREADINESS/blob/main/LICENSE) file for details.

## Contribute

Have suggestions for cipher suites or hardening features? Submit a pull request or open an issue.

## Support

Need help with .reg exports, .bat wrappers, GPO deployment, or Intune integration? Open an issue or PR—assistance provided.

## Credits

Created with the assistance of Grok by xAI for code refinement, quantum threat analysis, and documentation. Original concept developed with OpenAI and ChatGPT
