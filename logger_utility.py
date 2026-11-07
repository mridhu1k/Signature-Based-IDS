import datetime
import subprocess # Needed to trigger system notifications

LOG_FILE = "detections.log"

def send_system_notification(message, level):
    """Sends a desktop pop-up notification."""
    try:
        # icon selection based on level
        icon = "dialog-warning" if level == "WARNING" else "dialog-error"
        # The command to show a popup in Ubuntu
        subprocess.Popen(['notify-send', f"IDS ALERT - {level}", message, '-i', icon])
    except Exception:
        pass # Ignore if notify-send is not installed

def log_alert(message, level="INFO"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] [{level}] {message}"
    
    # Display 1: Terminal
    print(formatted_msg)
    
    # Display 2: Log File
    with open(LOG_FILE, "a") as f:
        f.write(formatted_msg + "\n")
    
    # Display 3: Desktop Pop-up (Only for threats)
    if level in ["WARNING", "CRITICAL"]:
        send_system_notification(message, level)
