# PowerShell Tools for Cybersecurity & Pentesting

## Overview

A compact, practical toolkit of PowerShell scripts built for security consultants and penetration testers. Designed to be lightweight, easy to use, and effective in real-world environments.

<p>
<a href="README_ES.md">Leer en Español</a>
</p>

## ✨ Included Tools

* Invoke-BasicADScanner — Basic scanner for common Active Directory misconfigurations and weak settings.

* Get-CriticalSecurityEvents — Collector & analyzer for important Windows Security events (export to CSV/JSON).

* Invoke-BasicObfuscation — Small utility with simple obfuscation techniques (reverse string, Base64, simple wrappers).

## Requirements

* Windows (client or server) with PowerShell. Scripts are compatible with PowerShell 5.1 and later.

* For Active Directory queries: ActiveDirectory PowerShell module (RSAT) available on the host or run on a Domain Controller.

* Run PowerShell as Administrator to access Security logs and certain OS features.

## 🚀 Quick Start

1. Clone or copy the repository to your analyst machine.

2. Open PowerShell as Administrator.

3. Examples:
'''
### Run AD scanner and save CSV
.\Invoke-BasicADScanner.ps1 -OutputPath .\AD_Audit_Report.csv


### Collect security events for the last 2 days and save JSON
.\Get-CriticalSecurityEvents.ps1 -Days 2 -OutputPath .\events.json


### Load obfuscation function and run interactively
. .\Invoke-BasicObfuscation.ps1
Invoke-BasicObfuscation -Command "Write-Host 'Hello World'"
'''
Tip: Dot-source (. .\script.ps1) scripts when you want to load functions into your current session.

## Features & Notes

* Uses XML-based event parsing for robust, language-independent extraction of fields like TargetUserName, ProcessName, etc.

* Supports .csv and .json export formats.

* For best AD-related coverage, run AD/Directory scripts on a Domain Controller or collect events centrally from DCs.

* Adjust the event ID lists and time windows to match your environment and noise levels.

## ⚠️ Legal & Ethical Notice

These tools are provided only for authorized security assessments and legal penetration tests. Do not run them against systems for which you do not have explicit permission — unauthorized use is illegal and unethical.

## 📎 Suggestions & Next Steps

* Use a dedicated VM or jump box for analysis.

* Centralize outputs to a SIEM or shared storage for triage and reporting.

* Optionally integrate results into CSV/JSON pipelines or convert to ECS/CEF for ingestion.

## Contributing

Contributions are welcome. Please open issues or pull requests with improvements, additional scripts, or better parsing/formatting for your environment.

## License

MIT License — use at your own risk.
