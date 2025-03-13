import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import socket
import subprocess
import ipaddress
import time
import os
import re

def is_reachable(ip):
    """
    Check if an IP address is reachable using the Windows ping command,
    suppressing any console window.
    """
    try:
        result = subprocess.run(
            ['ping', '-n', '1', '-w', '1000', str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.returncode == 0
    except Exception:
        return False

def auto_detect_local_network():
    """
    Automatically detect the local network by parsing ipconfig output.
    Returns a string like "192.168.1.0/24".
    """
    try:
        output = subprocess.check_output("ipconfig", shell=True, encoding="utf-8", errors="ignore")
    except subprocess.CalledProcessError:
        output = ""
    ip = None
    mask = None
    ip_pattern = re.compile(r"IPv4 Address.*?:\s*([\d\.]+)")
    mask_pattern = re.compile(r"Subnet Mask.*?:\s*([\d\.]+)")
    for line in output.splitlines():
        if not ip:
            ip_match = ip_pattern.search(line)
            if ip_match:
                candidate_ip = ip_match.group(1).strip()
                if candidate_ip != "127.0.0.1":  # skip loopback
                    ip = candidate_ip
        if not mask:
            mask_match = mask_pattern.search(line)
            if mask_match:
                mask = mask_match.group(1).strip()
        if ip and mask:
            break
    if not ip or not mask:
        return "127.0.0.1/32"
    prefix = sum(bin(int(octet)).count("1") for octet in mask.split('.'))
    network_obj = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    return str(network_obj)

def get_validated_network():
    """
    Checks for a cached network. If none exists, auto-detects the local network,
    displays a pop-up confirmation, and if needed, asks the user to enter the network.
    The final network is cached for future runs.
    """
    config_file = "local_network.txt"
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            network = f.read().strip()
            if network:
                return network
    temp_root = tk.Tk()
    temp_root.withdraw()
    network = auto_detect_local_network()
    confirm = messagebox.askyesno("Confirm Network",
                                  f"Detected local network: {network}\nIs this correct?",
                                  parent=temp_root)
    if not confirm:
        new_network = simpledialog.askstring("Enter Network",
                                               "Please enter your local network (e.g., 192.168.1.0/24):",
                                               parent=temp_root)
        if new_network:
            try:
                ipaddress.ip_network(new_network, strict=False)
            except Exception:
                messagebox.showerror("Error", "Invalid network format. Defaulting to 127.0.0.1/32", parent=temp_root)
                new_network = "127.0.0.1/32"
        else:
            new_network = "127.0.0.1/32"
        network = new_network
    temp_root.destroy()
    with open(config_file, "w") as f:
        f.write(network)
    return network

def get_device_details(ip):
    """
    Returns a string with details for a given IP address.
    The details include the IP, hostname (if resolvable),
    and a quick scan of common camera-related ports.
    """
    details = f"IP Address: {ip}\n"
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        details += f"Hostname: {hostname}\n"
    except Exception:
        details += "Hostname: Unknown\n"

    # Define a list of common camera-related ports.
    camera_ports = [80, 443, 554, 8000, 8001, 8080]
    details += "\nCommon Camera Ports:\n"
    for port in camera_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((str(ip), port))
        if result == 0:
            details += f"Port {port}: Open\n"
        else:
            details += f"Port {port}: Closed\n"
        s.close()
    return details

class NetworkScannerGUI:
    def __init__(self, root, local_network):
        self.root = root
        self.root.title("Network Scanner")
        self.local_network = local_network
        
        # Display the confirmed local network.
        self.network_label = tk.Label(root, text=f"Local Network: {self.local_network}")
        self.network_label.pack(pady=5)
        
        # Buttons: Start, Pause/Resume, Kill.
        self.start_button = tk.Button(root, text="Start", command=self.start_scan)
        self.start_button.pack(pady=5)
        
        self.pause_button = tk.Button(root, text="Pause", command=self.toggle_pause, state=tk.DISABLED)
        self.pause_button.pack(pady=5)
        
        self.kill_button = tk.Button(root, text="Kill", command=self.kill_scan, state=tk.DISABLED)
        self.kill_button.pack(pady=5)
        
        # Frame for the list boxes.
        self.list_frame = tk.Frame(root)
        self.list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # List box for active IPs.
        self.active_label = tk.Label(self.list_frame, text="Active IPs")
        self.active_label.grid(row=0, column=0, padx=5)
        self.active_listbox = tk.Listbox(self.list_frame, width=40, height=15)
        self.active_listbox.grid(row=1, column=0, padx=5, pady=5)
        self.active_listbox.bind("<Double-1>", self.on_active_ip_double_click)
        
        # List box for available IPs.
        self.available_label = tk.Label(self.list_frame, text="Available IPs")
        self.available_label.grid(row=0, column=1, padx=5)
        self.available_listbox = tk.Listbox(self.list_frame, width=40, height=15)
        self.available_listbox.grid(row=1, column=1, padx=5, pady=5)
        
        # Progress bar and progress label.
        self.progress = ttk.Progressbar(root, orient="horizontal", mode="determinate", length=300)
        self.progress.pack(pady=10)
        self.progress_label = tk.Label(root, text="")
        self.progress_label.pack()
        
        # Lists to store scan results.
        self.active_ips = []
        self.available_ips = []
        
        # Thread control events.
        self.scanning_thread = None
        self.pause_event = threading.Event()
        self.kill_event = threading.Event()
        self.pause_event.set()  # Initially not paused.
    
    def start_scan(self):
        # Clear previous results.
        self.active_listbox.delete(0, tk.END)
        self.available_listbox.delete(0, tk.END)
        self.active_ips = []
        self.available_ips = []
        self.progress["value"] = 0
        self.progress_label.config(text="")
        
        # Reset control events.
        self.kill_event.clear()
        self.pause_event.set()
        
        # Update button states.
        self.start_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.NORMAL, text="Pause")
        self.kill_button.config(state=tk.NORMAL)
        
        # Start scanning on the confirmed local network.
        self.scanning_thread = threading.Thread(target=self.scan_network, args=(self.local_network,), daemon=True)
        self.scanning_thread.start()
    
    def scan_network(self, network_str):
        try:
            network = ipaddress.ip_network(network_str, strict=False)
        except ValueError as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Invalid network: {e}"))
            self.root.after(0, lambda: self.start_button.config(state=tk.NORMAL))
            return
        hosts = list(network.hosts())
        total = len(hosts)
        count = 0
        for ip in hosts:
            if self.kill_event.is_set():
                break
            # Pause if needed.
            while not self.pause_event.is_set():
                if self.kill_event.is_set():
                    break
                time.sleep(0.1)
            if self.kill_event.is_set():
                break
            if is_reachable(ip):
                try:
                    hostname = socket.gethostbyaddr(str(ip))[0]
                except socket.herror:
                    hostname = "Unknown"
                new_entry = f"{ip} - {hostname}"
                self.active_ips.append(new_entry)
                self.root.after(0, self.active_listbox.insert, tk.END, new_entry)
            else:
                self.available_ips.append(str(ip))
                self.root.after(0, self.available_listbox.insert, tk.END, str(ip))
            count += 1
            progress_value = int((count / total) * 100)
            self.root.after(0, self.update_progress, progress_value, count, total)
        # Final update of the list boxes (if needed) and reset buttons.
        self.root.after(0, self.reset_buttons)
    
    def update_progress(self, value, count, total):
        self.progress["value"] = value
        self.progress_label.config(text=f"Scanned {count} of {total} IPs")
    
    def reset_buttons(self):
        self.start_button.config(state=tk.NORMAL)
        self.pause_button.config(state=tk.DISABLED)
        self.kill_button.config(state=tk.DISABLED)
    
    def toggle_pause(self):
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.pause_button.config(text="Resume")
        else:
            self.pause_event.set()
            self.pause_button.config(text="Pause")
    
    def kill_scan(self):
        self.kill_event.set()
        self.pause_event.set()  # Resume if paused so thread can exit.
        self.pause_button.config(state=tk.DISABLED)
        self.kill_button.config(state=tk.DISABLED)
        self.progress_label.config(text="Scan killed.")
    
    def on_active_ip_double_click(self, event):
        """When an active IP is double-clicked, show its network details."""
        selection = self.active_listbox.curselection()
        if selection:
            index = selection[0]
            item = self.active_listbox.get(index)
            # Expecting item format "IP - hostname"
            ip = item.split(" - ")[0]
            self.show_details(ip)
    
    def show_details(self, ip):
        """Open a new window displaying network details for the selected IP."""
        details = get_device_details(ip)
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Details for {ip}")
        text = tk.Text(details_window, wrap=tk.WORD, width=50, height=15)
        text.insert(tk.END, details)
        text.config(state=tk.DISABLED)
        text.pack(padx=10, pady=10)

if __name__ == '__main__':
    # Get the local network via a pop-up confirmation dialog.
    local_network = get_validated_network()
    # Launch the main GUI with the confirmed network.
    root = tk.Tk()
    app = NetworkScannerGUI(root, local_network)
    root.mainloop()
