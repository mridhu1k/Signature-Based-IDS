# Signature-Based IDS

A Python command-line intrusion detection project that checks files and captured network traffic against signatures stored in a local JSON database. It can scan a single file, watch a folder for newly created files, and inspect packets on a network interface.

## Requirements

- Python 3 and pip
- Scapy and Watchdog
- Linux/Ubuntu for the setup below. Packet capture generally requires root or appropriate capture privileges.
- Optional: `gnome-terminal` for the separate alert window and `notify-send` for desktop notifications. Alerts are also printed and written to a log.

## Setup

```bash
git clone https://github.com/mridhu1k/Signature-Based-IDS.git
cd Signature-Based-IDS
python3 -m venv venv
source venv/bin/activate
python -m pip install scapy watchdog
python main.py
```

Run from the project directory: the application reads and writes `database.json` and `detections.log` relative to the current working directory. If the database is missing, startup creates an empty one.

For network capture on Linux, if your account lacks capture privileges, start the application using the virtual environment's interpreter:

```bash
sudo ./venv/bin/python3 main.py
```

Capture traffic only on networks and interfaces you are authorized to monitor. Running as root can create root-owned database or log files.

## Usage

Choose an option from the menu:

1. **Scan single file** — provide a file path. The scanner compares its MD5 digest with stored hashes, then searches UTF-8-decoded content for string signatures, ignoring invalid bytes. The first match generates an alert.
2. **Monitor a folder** — provide a directory. New files directly inside it are scanned when created; subdirectories and later modifications are not monitored. Press Ctrl+C to stop monitoring.
3. **Start packet sniffer** — select Scapy's default interface or choose an interface from the list. Packet payloads are checked against string signatures; packets without a Raw layer use Scapy's string representation. Repeated alerts for the same source and pattern are suppressed for three seconds. Press Ctrl+C to stop capture.
4. **Add a signature** — enter a value and choose `h` for an MD5 hash or `s` for a string. Signatures are saved in `database.json`.
5. **Open an alert window** — launch a GNOME Terminal showing new log entries. Folder monitoring and packet capture also attempt to open this window.
6. **Exit** the application.

Alerts appear in the terminal and are appended to `detections.log`. Warning and critical alerts also attempt a desktop notification. The alert window follows new log entries and highlights warning and critical text; it requires a working graphical session.

## Signatures

The database has two lists:

```json
{
  "hashes": ["example-md5-digest"],
  "strings": ["example-pattern"]
}
```

Replace the example hash with a lowercase 32-character MD5 digest. Hash matching is exact; string matching is case-insensitive and checks for substrings. The included database contains demonstration signatures, including common words that can produce false positives. Review and tailor them before use. You can remove entries by editing the JSON file; keep both lists present. Changes made through the menu are saved to this tracked file.

To try a string detection without malware, create a temporary file containing a configured signature and select option 1:

```bash
printf 'worm\n' > /tmp/ids-demo.txt
```

Enter `/tmp/ids-demo.txt` when prompted. This example assumes `worm` remains in the database.

## Project structure

| File | Responsibility |
| --- | --- |
| `main.py` | Menu, startup and alert-window launcher |
| `database_manager.py` | Load, create and update the JSON signature database |
| `file_scanner.py` | MD5 and content matching for files |
| `realtime_monitor.py` | Watchdog handler for newly created files |
| `packet_sniffer.py` | Scapy packet capture and string matching |
| `interface_manager.py` | List interfaces and select Scapy's default |
| `logger_utility.py` | Terminal, log and desktop alerts |
| `database.json` | Stored hash and string signatures |

## Limitations

This is a simple signature-matching project, not a complete security product. It cannot identify unknown threats without matching signatures, decrypt encrypted traffic, or reassemble signatures split across packets. UTF-8 decoding can discard bytes, and the file scanner reads the entire file into memory for content matching. Folder monitoring can scan a file before it has finished being written. A scan error is logged but can also be followed by the menu's “File appears clean” message, so check the log and errors before interpreting that message as a successful scan. MD5 is used for exact signature lookup and is not collision-resistant.
