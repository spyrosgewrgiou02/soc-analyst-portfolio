# Lab 002: Malicious AutoIt Analysis

- **Platform:** LetsDefend
- **Focus:** Static Analysis, PE Header Examination, and AutoIt Deobfuscation
- **Date completed:** 21/10/2026

## Scenario
Our organization's SOC detected suspicious activity related to an AutoIt script (`sample.zip`, password: `infected`). The goal is to perform static analysis on the executable using tools like Detect It Easy (DIE) and script deobfuscation to extract Indicators of Compromise (IOCs) without executing the malware.

## Investigation
1. **File Hashing:** Extracted the sample using HashCalc to obtain the unique MD5 file hash for tracking.
2. **PE & Entropy Analysis:** Opened the sample in Detect It Easy (DIE) to check file entropy (evaluating byte predictability and potential packing/encryption) and inspected PE headers to locate section virtual addresses and entry point coordinates.
3. **Script Deobfuscation:** Used PowerShell and `autoit-ripper.exe` to extract the compiled AutoIt bytecode into a readable `.au3` script (`script.au3`).
4. **Code Review:** Inspected the script to uncover hardcoded C2 domains, hex-encoded Windows paths, and imported DLL function calls.

## Findings
- **MD5 Hash:** `5e53b40cf972f4eb08990999ce17c5c8`
- **Total Entropy:** `6.58565` (indicating high byte complexity/potential compression)
- **`.text` Section Virtual Address:** `0x1000`
- **Entry Point Address:** `0x42800a`
- **Malicious Domain:** `office-cleaner-commander.com` (extracted via `InetRead`)
- **Decoded File Path:** `:\Windows\System32\` (decoded from hex string `0x3A5C57696E646F77735C53797374656D33325C`)
- **Target DLL:** `user32.dll` (called via script functions for user-interaction/window handling)

## Conclusion
**True Positive.** The sample is a malicious AutoIt-wrapped executable designed to invoke system components, reference local Windows directories, and beacon out to an external command-and-control (C2) domain (`office-cleaner-commander.com`) to download secondary payloads (`Pay.txt`).

## Recommended response
- Block the C2 domain (`office-cleaner-commander.com`) at the firewall/web proxy level.
- Isolate any host flagged executing this sample or showing outbound traffic to the identified domain.
- Submit file hashes and domain IOCs to the SIEM for retroactive hunting.

## What I learned
- How to use Detect It Easy (DIE) to analyze PE file metadata, entropy, and section layouts without running the sample.
- How to utilize `autoit-ripper` to decompile AutoIt scripts and extract hidden strings, encoded file paths, and external network indicators.

## References
- [LetsDefend — Malicious AutoIT Challenge Walkthrough](https://stumblesec.medium.com/letsdefend-malicious-autoit-challenge-walkthrough-c6bac6538ead)
