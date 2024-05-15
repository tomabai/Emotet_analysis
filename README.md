# Emotet Analysis Report

## Overview

This repository hosts the "Emotet Analysis Report" by Tom Abai, which provides an in-depth analysis of the Emotet malware, also known as Heodo. The report covers the initial detection, analysis of malicious documents, dynamic and static analysis, network activity, and code analysis.

## Table of Contents
- [Introduction](#introduction)
- [First Stage Initial Analysis](#first-stage-initial-analysis)
- [Second Stage Initial Analysis](#second-stage-initial-analysis)
- [Dynamic Analysis](#dynamic-analysis)
- [Code Analysis](#code-analysis)
- [Conclusion](#conclusion)
- [Threat Indicators](#threat-indicators)
- [License](#license)

## Introduction
Emotet malware is a trojan first detected in 2014 and has become one of the most prevalent threats of the decade. Its primary goal is to steal information and exfiltrate sensitive data to its Command and Control (C2) servers. The malware typically spreads through phishing emails containing malicious attachments.

## First Stage Initial Analysis
- **File Type**: DOC
- **File Size**: 160KB
- **Hashes**:
  - MD5: 5d77014f9e33dd2bcc170fdac81bf9ab
  - SHA256: c78bdae87b97d1139b8ec99392d9a45105bc4b84c7b5fa9d17768584ca20ba78

The initial analysis involves submitting the document's hash to VirusTotal, which detects it as a trojan. Further analysis using Oledump and Olevba reveals the presence of macros and obfuscated VBA scripts that trigger upon enabling content, leading to the execution of malicious commands via PowerShell.

## Second Stage Initial Analysis
- **File Type**: UIF
- **File Size**: 349KB
- **Hashes**:
  - MD5: 782f98c00905f1b80f0dfc6dc287cd6e
  - SHA256: 06040e1406a3b99da60e639edcf14ddb1f3c812993b408a8164285f2a580caaf

The second stage involves downloading a DLL from external sources using the PowerShell script. Static and dynamic analysis reveals the use of various Windows API functions for malicious actions and unpacking processes.

## Dynamic Analysis
Dynamic analysis of the DLL shows that it reads cookies and history files from the system and exfiltrates data to remote servers. This behavior is confirmed through network activity monitoring and analysis using tools like Procmon.

## Code Analysis
The code analysis involves reverse engineering the malware to understand its execution flow, memory allocation, and decryption routines. The malware uses various techniques to hide itself and execute its payload, including encryption, API hashing, and indirect function calls.

## Conclusion
Emotet is a sophisticated malware with strong capabilities to hide itself and exfiltrate sensitive data. It connects to multiple C2 servers to receive commands and perform further malicious actions.

## Threat Indicators
- **IP Addresses/Domains**:
  - 2[.]58[.]16[.]88
  - 206[.]189[.]232[.]2
  - 178[.]250[.]54[.]208
  - [Full list available in the report](Emotet%20Analysis%20Report%20-%20Tom%20Abai.pdf)

- **Dropped File**:
  - Name: tuyzvooperhbb.pxw
  - Size: 128 KiB
  - SHA256: 0c54b630d6a714a8c6d01acc9bb78df18597d68cfd39c1daea58155a2cbf5b65


---

Please refer to the full [Emotet Analysis Report](Emotet%20Analysis%20Report%20-%20Tom%20Abai.pdf) for detailed information and analysis.
