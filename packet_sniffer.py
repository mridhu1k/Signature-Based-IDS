from scapy.all import sniff, TCP, UDP, IP, Raw
from logger_utility import log_alert
from database_manager import load_signatures
from interface_manager import get_default_interface
import time
from logger_utility import log_alert
 


last_seen_alerts = {}
COOLDOWN_SECONDS = 3

def process_packet(packet):
    """
    Analyzes an individual network packet.
    Logic: 1. Checks if packet has a 'Raw' data layer. 
           2. Decodes payload. 
           3. Compares against string signatures in DB.
    """
    
    try:
    	sigs = load_signatures()
    except Exception as e:
    	print(f"Error loading signature: {e}")
    	return
    
    
    global last_seen_alerts
    
    if packet.haslayer(IP):
    	print(f"[*] Packet Captured: {packet[IP].src} -> {packet[IP].dst}")
    
    sigs = load_signatures()
    payload = ""
    
    if packet.haslayer(Raw):
    	payload = packet[Raw].load.decode('utf-8', errors='ignore')
    else:
    	payload = str(packet)
    
    for pattern in sigs["strings"]:
    	if pattern.lower() in payload.lower():
    		current_time = time.time()
    		src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
    		alert_key = (src_ip, pattern)
    		
    		last_alert_time = last_seen_alerts.get(alert_key, 0)
    		if current_time - last_alert_time > COOLDOWN_SECONDS:
    			log_alert(f"NETWORK THREAT: '{pattern}' detected from {src_ip}", "CRITICAL")
    			last_seen_alerts[alert_key] = current_time
    		else:
    			pass
		
		
def start_sniffing(interface=None):
    """
    Starts the Scapy sniffer.
    Logic: If no interface is provided, it auto-detects the default.
    """
    if interface is None:
        interface = get_default_interface()
    
    from logger_utility import log_alert
    log_alert(f"NIDS ACTIVE: Sniffing on interface [{interface}]...")
    
    # We use 'prn' as a callback to your process_packet function
    from packet_sniffer import process_packet
    from scapy.all import sniff
    
    sniff(iface=interface, prn=process_packet, store=0)
