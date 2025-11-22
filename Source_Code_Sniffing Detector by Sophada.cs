using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;

class Program
{
    static void Main()
    {
        Console.Title = "Security Scanner by Sophada";
        Console.BackgroundColor = ConsoleColor.Black;
        Console.Clear();

        var config = LoadConfig();

        while (true)
        {
            Console.Clear();
            PrintHeader();
            RunScanAnimation("Scanning running processes");
            CheckProcesses(config);
            RunScanAnimation("Scanning suspicious folders");
            CheckFolders(config);
            WriteDark($"[+] Next scan in {config.ScanIntervalSeconds} seconds...");
            Thread.Sleep(config.ScanIntervalSeconds * 1000);
        }
    }

    static Config LoadConfig()
    {
        const string configFile = "scan_settings.json";

        if (!File.Exists(configFile))
        {
            var defaultConfig = new Config
            {
                ScanIntervalSeconds = 4,
                MonitoredFolders = new List<FolderRule>
                {
                    new FolderRule { Path = @"C:\Program Files\Simple USB Logger", Name = "SUSBLogger Detected" },
                    new FolderRule { Path = @"C:\USBPcap", Name = "USB PCAP Tool" },
                    new FolderRule { Path = @"C:\Program Files\BusDog", Name = "BusDog USB Monitor" },
                    new FolderRule { Path = @"C:\Program Files (x86)\BusDog", Name = "BusDog USB Monitor" },
                    new FolderRule { Path = @"C:\Program Files\Serial Port Monitor", Name = "Serial Port Monitor" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Serial Port Monitor", Name = "Serial Port Monitor" },
                    new FolderRule { Path = @"C:\Program Files\Eltima Software\Serial Port Monitor", Name = "Eltima Serial Monitor" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Eltima Software\Serial Port Monitor", Name = "Eltima Serial Monitor" },
                    new FolderRule { Path = @"C:\Program Files\HHD Software\Serial Monitor", Name = "HHD Serial Monitor" },
                    new FolderRule { Path = @"C:\Program Files (x86)\HHD Software\Serial Monitor", Name = "HHD Serial Monitor" },
                    new FolderRule { Path = @"C:\Program Files\Advanced Serial Port Monitor", Name = "Advanced Serial Monitor" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Advanced Serial Port Monitor", Name = "Advanced Serial Monitor" },
                    new FolderRule { Path = @"C:\Program Files\Wireshark", Name = "Wireshark Network Analyzer" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Wireshark", Name = "Wireshark Network Analyzer" },
                    new FolderRule { Path = @"C:\Program Files\USBlyzer", Name = "USBlyzer USB Analyzer" },
                    new FolderRule { Path = @"C:\Program Files (x86)\USBlyzer", Name = "USBlyzer USB Analyzer" },
                    new FolderRule { Path = @"C:\Program Files\Cheat Engine", Name = "Cheat Engine Debugger" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Cheat Engine", Name = "Cheat Engine Debugger" },
                    new FolderRule { Path = @"C:\Program Files\Process Hacker", Name = "Process Hacker" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Process Hacker", Name = "Process Hacker" },
                    new FolderRule { Path = @"C:\Program Files\Process Hacker 2", Name = "Process Hacker 2" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Process Hacker 2", Name = "Process Hacker 2" },
                    new FolderRule { Path = @"C:\Program Files\OllyDbg", Name = "OllyDbg Debugger" },
                    new FolderRule { Path = @"C:\Program Files (x86)\OllyDbg", Name = "OllyDbg Debugger" },
                    new FolderRule { Path = @"C:\Program Files\x64dbg", Name = "x64dbg Debugger" },
                    new FolderRule { Path = @"C:\Program Files (x86)\x64dbg", Name = "x64dbg Debugger" },
                    new FolderRule { Path = @"C:\Program Files\IDA", Name = "IDA Pro Disassembler" },
                    new FolderRule { Path = @"C:\Program Files (x86)\IDA", Name = "IDA Pro Disassembler" },
                    new FolderRule { Path = @"C:\Program Files\Fiddler", Name = "Fiddler Web Debugger" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Fiddler", Name = "Fiddler Web Debugger" },
                    new FolderRule { Path = @"C:\Program Files\Charles", Name = "Charles Proxy" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Charles", Name = "Charles Proxy" },
                    new FolderRule { Path = @"C:\Program Files\Burp Suite", Name = "Burp Suite Proxy" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Burp Suite", Name = "Burp Suite Proxy" },
                    new FolderRule { Path = @"C:\Program Files\Ghidra", Name = "Ghidra Reverse Engineering" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Ghidra", Name = "Ghidra Reverse Engineering" },
                    new FolderRule { Path = @"C:\Program Files\Immunity Debugger", Name = "Immunity Debugger" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Immunity Debugger", Name = "Immunity Debugger" },
                    new FolderRule { Path = @"C:\Program Files\WinDbg", Name = "Windows Debugger" },
                    new FolderRule { Path = @"C:\Program Files (x86)\WinDbg", Name = "Windows Debugger" },
                    new FolderRule { Path = @"C:\Program Files\Radare2", Name = "Radare2 Framework" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Radare2", Name = "Radare2 Framework" },
                    new FolderRule { Path = @"C:\Program Files\USBDeview", Name = "USBDeview Tool" },
                    new FolderRule { Path = @"C:\Program Files (x86)\USBDeview", Name = "USBDeview Tool" },
                    new FolderRule { Path = @"C:\Program Files\NetworkMiner", Name = "NetworkMiner Analyzer" },
                    new FolderRule { Path = @"C:\Program Files (x86)\NetworkMiner", Name = "NetworkMiner Analyzer" },
                    new FolderRule { Path = @"C:\Program Files\Tcpdump", Name = "Tcpdump Packet Analyzer" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Tcpdump", Name = "Tcpdump Packet Analyzer" },
                    new FolderRule { Path = @"C:\Program Files\SysInternals", Name = "SysInternals Suite" },
                    new FolderRule { Path = @"C:\Program Files (x86)\SysInternals", Name = "SysInternals Suite" },
                    new FolderRule { Path = @"C:\Program Files\HxD", Name = "HxD Hex Editor" },
                    new FolderRule { Path = @"C:\Program Files (x86)\HxD", Name = "HxD Hex Editor" },
                    new FolderRule { Path = @"C:\Program Files\010 Editor", Name = "010 Hex Editor" },
                    new FolderRule { Path = @"C:\Program Files (x86)\010 Editor", Name = "010 Hex Editor" },
                    new FolderRule { Path = @"C:\Program Files\Npcap", Name = "Npcap Packet Capture" },
                    new FolderRule { Path = @"C:\Program Files (x86)\Npcap", Name = "Npcap Packet Capture" },
                    new FolderRule { Path = @"C:\Program Files\WinPcap", Name = "WinPcap Packet Capture" },
                    new FolderRule { Path = @"C:\Program Files (x86)\WinPcap", Name = "WinPcap Packet Capture" }
                },
                SuspiciousProcesses = new List<string>
                {
                    "USBPcapCMD",
                    "SimpleUSBLogger",
                    "Wireshark",
                    "USBLogger",
                    "BusDog",
                    "busdog",
                    "SerialPortMonitor",
                    "SPMonitor",
                    "portmon",
                    "AdvancedSerialPortMonitor",
                    "HHDSerialMonitor",
                    "ComPortMonitor",
                    "EltimaSerialMonitor",
                    "usbpcap",
                    "usblyzer",
                    "serialmon",
                    "freeusbanalyzer",
                    "comportmonitor",
                    "cheatengine",
                    "cheatengine-x86_64",
                    "processhacker",
                    "ProcessHacker",
                    "ollydbg",
                    "x64dbg",
                    "x32dbg",
                    "ida",
                    "ida64",
                    "idaq",
                    "idaq64",
                    "Fiddler",
                    "FiddlerEverywhere",
                    "Charles",
                    "Burp Suite",
                    "burpsuite",
                    "Ghidra",
                    "ghidraRun",
                    "ImmunityDebugger",
                    "WinDbg",
                    "windbg",
                    "radare2",
                    "r2",
                    "USBDeview",
                    "NetworkMiner",
                    "tcpdump",
                    "procmon",
                    "procmon64",
                    "procexp",
                    "procexp64",
                    "autoruns",
                    "autoruns64",
                    "HxD",
                    "010Editor",
                    "Npcap",
                    "WinPcap",
                    "tshark",
                    "dumpcap",
                    "ettercap",
                    "cain",
                    "dsniff",
                    "apimonitor",
                    "ApiMonitor",
                    "SpyStudio",
                    "regshot",
                    "ProcessMonitor",
                    "dnSpy",
                    "dotPeek",
                    "ILSpy",
                    "PEiD",
                    "CFF Explorer",
                    "pestudio",
                    "DIE",
                    "DetectItEasy",
                    "ResourceHacker",
                    "reshacker"
                }
            };

            File.WriteAllText(configFile, JsonSerializer.Serialize(defaultConfig, new JsonSerializerOptions { WriteIndented = true }));
            return defaultConfig;
        }

        return JsonSerializer.Deserialize<Config>(File.ReadAllText(configFile));
    }

    static void PrintHeader()
    {
        WriteBig("===============================================");
        WriteBig("           SECURITY SCANNER by Sophada");
        WriteBig("===============================================");
        Console.WriteLine();
    }

    static void RunScanAnimation(string text)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(text);
        Console.ResetColor();

        for (int i = 0; i < 25; i++)
        {
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.Write("█");
            Console.ResetColor();
            Thread.Sleep(30);
        }

        Console.WriteLine("\n");
    }

    static void CheckProcesses(Config config)
    {
        Write("[PROCESS RESULTS]");
        var processes = Process.GetProcesses();
        bool found = false;

        foreach (var process in processes)
        {
            foreach (var name in config.SuspiciousProcesses)
            {
                if (process.ProcessName.Contains(name, StringComparison.OrdinalIgnoreCase))
                {
                    WriteRed($" ⚠ {process.ProcessName} (PID: {process.Id})");
                    found = true;
                }
            }
        }

        if (!found) WriteDark(" OK - No suspicious processes detected");
        Console.WriteLine();
    }

    static void CheckFolders(Config config)
    {
        Write("[FOLDER RESULTS]");
        bool found = false;

        foreach (var rule in config.MonitoredFolders)
        {
            if (Directory.Exists(rule.Path))
            {
                WriteRed($" ⚠ {rule.Name} ({rule.Path})");
                found = true;
            }
        }

        if (!found) WriteDark(" OK - No suspicious folders detected");
        Console.WriteLine();
    }

    static void Write(string text)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    static void WriteBig(string text)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    static void WriteRed(string text)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    static void WriteDark(string text)
    {
        Console.ForegroundColor = ConsoleColor.DarkGreen;
        Console.WriteLine(text);
        Console.ResetColor();
    }
}

class Config
{
    public int ScanIntervalSeconds { get; set; }
    public List<FolderRule> MonitoredFolders { get; set; }
    public List<string> SuspiciousProcesses { get; set; }
}

class FolderRule
{
    public string Path { get; set; }
    public string Name { get; set; }
}