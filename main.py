import os
import subprocess
import time
from database_manager import initialize_db, add_signature
from file_scanner import scan_file
from realtime_monitor import start_monitoring
from packet_sniffer import start_sniffing
from interface_manager import display_interfaces, get_default_interface

def spawn_fresh_alert_console():
    """
    Spawns a new Ubuntu terminal window for high-priority alerts.
    Logic: 
    1. 'clear' ensures the window starts empty.
    2. 'tail -n 0 -f' ensures ONLY new data added AFTER this moment is shown.
    3. 'grep' highlights WARNING and CRITICAL threats in red.
    """
    log_path = "detections.log"
    
    # Ensure the log file exists so the tail command doesn't crash
    if not os.path.exists(log_path):
        with open(log_path, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [INFO] IDS Log Initialized.\n")

    # The command string for the new terminal
    # -n 0 is the magic flag that hides old data
    cmd = f'clear && echo "--- LIVE THREAT MONITOR (FRESH SESSION) ---" && tail -n 0 -f {log_path} | grep --line-buffered --color=always -E "WARNING|CRITICAL|$"'
    
    try:
        # Launching the GNOME Terminal (standard on Ubuntu)
        subprocess.Popen([
            'gnome-terminal', 
            '--title=IDS LIVE ALERTS', 
            '--', 'bash', '-c', cmd
        ])
        print("[+] Fresh Alert Console spawned in a new window.")
    except Exception as e:
        print(f"[-] Could not spawn alert console: {e}")

def main_menu():
    # Setup the JSON database on boot
    initialize_db()
    
    while True:
        print("\n" + "="*40)
        print("      MODULAR IDS SYSTEM (V2.6)      ")
        print("="*40)
        print("1. Scan Single File (Instant)")
        print("2. Start Real-Time Folder Monitor")
        print("3. Start Packet Sniffer (NIDS)")
        print("4. Add Virus Signature (Hash/String)")
        print("5. Spawn Manual Fresh Alert Window")
        print("6. Exit")
        print("-" * 40)
        
        choice = input("Select an option: ")

        if choice == "1":
            path = input("Enter path to file: ")
            if os.path.exists(path):
                # Optional: spawn a fresh window just for this scan result
                # spawn_fresh_alert_console() 
                found = scan_file(path)
                if not found: 
                    print("[+] File appears clean.")
            else:
                print("[-] Invalid path.")

        elif choice == "2":
            path = input("Enter directory to monitor: ")
            if os.path.isdir(path):
                # Automation: Open the fresh alert window for this session
                spawn_fresh_alert_console()
                print(f"[*] Monitoring {path}. Press Ctrl+C to stop...")
                start_monitoring(path)
            else:
                print("[-] Invalid directory.")

        elif choice == "3":
            print("\n--- Network Interface Setup ---")
            print("1. Auto-detect Default Interface")
            print("2. Select Interface Manually")
            sub_choice = input("Choice: ")
            
            selected_iface = None
            if sub_choice == "1":
                selected_iface = get_default_interface()
            elif sub_choice == "2":
                ifaces = display_interfaces()
                try:
                    idx = int(input("Enter the number of the interface: "))
                    selected_iface = ifaces[idx]
                except (ValueError, IndexError):
                    print("[-] Invalid selection.")
            
            if selected_iface:
                # Automation: Open a fresh alert window for network sniffing
                spawn_fresh_alert_console()
                try:
                    start_sniffing(selected_iface)
                except PermissionError:
                    print("\n[!] PERMISSION ERROR: Sniffing requires sudo.")
                    print("Run: sudo ./venv/bin/python3 main.py")
                except Exception as e:
                    print(f"[-] Sniffer Error: {e}")

        elif choice == "4":
            val = input("Enter Hash or String: ")
            t = input("Type (h for Hash, s for String): ").lower()
            add_signature(val, "hash" if t == 'h' else "string")
            print("[+] Signature successfully added to database.json")

        elif choice == "5":
            spawn_fresh_alert_console()

        elif choice == "6":
            print("[*] Shutting down IDS system...")
            break
        else:
            print("[-] Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
