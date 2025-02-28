# Browser Extension Security Scanner

A Python-based tool to scan browser extensions for security risks across Chrome, Edge, Firefox, and Safari. This scanner performs static and dynamic analysis to identify risky permissions, suspicious code patterns, and unusual network activity, helping organizations secure their browser environments.

## Features

- **Multi-Browser Support:** Analyzes extensions for Chrome, Edge, Firefox, and Safari.
- **Static Analysis:** Parses `manifest.json` or `Info.plist` files to evaluate permissions and scans JavaScript for dangerous patterns.
- **Dynamic Analysis:** Monitors network requests in a headless browser (Chrome/Edge only) to detect potential threats.
- **Risk Scoring:** Calculates a risk score (0-100) based on permissions, code issues, and network behavior.
- **Reporting:** Saves detailed JSON reports locally and optionally sends findings to Tenable for centralized tracking.


Be sure to add in your own API Tenable keys. 

   
