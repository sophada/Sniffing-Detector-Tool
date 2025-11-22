# Sniffing Detector Tool by Sophada

A lightweight C# console application that monitors your system for potentially unwanted monitoring and reverse engineering tools.

## Features

- **Process Monitoring** - Detects suspicious running processes
- **Folder Scanning** - Checks for installed monitoring software
- **Auto-Refresh** - Continuous scanning at configurable intervals
- **JSON Configuration** - Easily customize detection rules

## Quick Start

1. Ready compiled, just donwload and run the application
2. Scanner auto-generates `scan_settings.json` on first run
3. Customize detection rules in the config file
4. Monitor runs automatically every 4 seconds (configurable)

## What It Detects

**USB/Serial Monitoring Tools**
- USBPcap, BusDog, USBlyzer
- Serial Port Monitor, PortMon
- Simple USB Logger

**Network Analysis Tools**
- Wireshark, Fiddler, Charles Proxy
- Burp Suite, NetworkMiner
- Tcpdump, Npcap/WinPcap

**Reverse Engineering Tools**
- IDA Pro, Ghidra, Radare2
- x64dbg, OllyDbg, WinDbg
- Cheat Engine, Process Hacker
- dnSpy, ILSpy, dotPeek

**And 40+ more tools**

## Configuration

Edit `scan_settings.json` to customize:
```json
{
  "ScanIntervalSeconds": 4,
  "MonitoredFolders": [...],
  "SuspiciousProcesses": [...]
}
```

## Requirements

- .NET Framework 4.7.2 or higher / .NET 6.0+
- Windows OS
- Administrator privileges recommended for full process scanning

## Disclaimer

This tool is for **personal security awareness only**. Many detected tools have legitimate uses in IT, security research, and software development. Always comply with your organization's policies and applicable laws.
For more info contact me on Google Chat: contact@sophada.com
## License

MIT License
