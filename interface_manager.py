from scapy.all import get_if_list, conf
import os

def list_interfaces():
    """
    Retrieves all network interfaces on the system.
    Logic: Uses Scapy's get_if_list to query the OS.
    """
    interfaces = get_if_list()
    return interfaces

def get_default_interface():
    """
    Identifies the primary active network interface.
    Logic: Checks the system routing table to find the 'default' gateway.
    """
    # conf.iface is Scapy's best guess at the active interface
    return conf.iface

def display_interfaces():
    """
    Prints a clean list for the user to choose from.
    Logic: Iterates through the list and formats for CLI.
    """
    print("\n--- Available Network Interfaces ---")
    ifaces = list_interfaces()
    for i, iface in enumerate(ifaces):
        print(f"{i}. {iface}")
    return ifaces
