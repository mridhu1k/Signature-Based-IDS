import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from file_scanner import scan_file
from logger_utility import log_alert

class ScanHandler(FileSystemEventHandler):
    """
    Watchdog Event Handler.
    Logic: Overrides on_created to trigger a scan immediately when a file appears.
    """
    def on_created(self, event):
        if not event.is_directory:
            log_alert(f"New file detected: {event.src_path}")
            scan_file(event.src_path)

def start_monitoring(path_to_watch):
    """
    Initializes the folder observer.
    Logic: Sets up the Observer thread and keeps it running until interrupted.
    """
    event_handler = ScanHandler()
    observer = Observer()
    observer.schedule(event_handler, path_to_watch, recursive=False)
    observer.start()
    log_alert(f"Monitoring started on: {path_to_watch}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
