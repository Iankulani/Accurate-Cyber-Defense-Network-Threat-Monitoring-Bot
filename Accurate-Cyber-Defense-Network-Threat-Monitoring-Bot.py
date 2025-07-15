import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, Menu, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import socket
import threading
import time
import psutil
import datetime
import requests
from scapy.all import sniff, IP, TCP, UDP, ICMP
import dpkt
import sys
import os
import subprocess
import json
from collections import defaultdict
import platform
import netifaces

# Configuration
CONFIG_FILE = "cyberguard_config.json"
DEFAULT_CONFIG = {
    "telegram_token": "",
    "telegram_chat_id": "",
    "monitored_ips": [],
    "theme": "blue",
    "alert_thresholds": {
        "port_scan": 5,
        "ddos": 100,
        "dos": 50,
        "unusual_traffic": 30,
        "ping_of_death": 1
    }
}

class CyberGuard:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Defnse Advanced Network Monitoring BOT")
        self.root.geometry("1200x800")
        
        # Load configuration
        self.config = self.load_config()
        
        # Initialize variables
        self.monitoring = False
        self.detected_threats = []
        self.network_stats = defaultdict(lambda: defaultdict(int))
        self.packet_count = 0
        self.start_time = time.time()
        self.sniffer_thread = None
        self.monitored_ips = set(self.config["monitored_ips"])
        
        # Setup UI
        self.setup_ui()
        
        # Setup Telegram bot
        self.telegram_bot = TelegramBot(
            self.config["telegram_token"],
            self.config["telegram_chat_id"]
        )
        
        # Initialize network interfaces
        self.interfaces = self.get_network_interfaces()
        
        # Start periodic stats update
        self.update_stats()
    
    def setup_ui(self):
        # Apply theme
        self.apply_theme(self.config["theme"])
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create main frames
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Terminal and controls
        self.left_frame = ttk.Frame(self.main_frame, width=400)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Right panel - Dashboard and charts
        self.right_frame = ttk.Frame(self.main_frame)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Terminal
        self.setup_terminal()
        
        # Charts area
        self.setup_charts()
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def apply_theme(self, theme):
        if theme == "blue":
            self.root.configure(background="#e6f2ff")
            style = ttk.Style()
            style.theme_use("clam")
            style.configure(".", background="#e6f2ff", foreground="#003366")
            style.configure("TFrame", background="#e6f2ff")
            style.configure("TLabel", background="#e6f2ff", foreground="#003366")
            style.configure("TButton", background="#4da6ff", foreground="white")
            style.configure("TEntry", fieldbackground="white")
            style.configure("TScrollbar", background="#cce0ff")
            style.configure("TCombobox", fieldbackground="white")
            style.configure("Treeview", background="white", fieldbackground="white")
    
    def create_menu_bar(self):
        menubar = Menu(self.root)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Report", command=self.save_report)
        file_menu.add_command(label="Load Configuration", command=self.load_config_dialog)
        file_menu.add_command(label="Save Configuration", command=self.save_config_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = Menu(menubar, tearoff=0)
        view_menu.add_command(label="Refresh Dashboard", command=self.update_charts)
        view_menu.add_command(label="Clear Terminal", command=self.clear_terminal)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Network Scanner", command=self.open_network_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Settings menu
        settings_menu = Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Telegram Settings", command=self.open_telegram_settings)
        settings_menu.add_command(label="Alert Thresholds", command=self.open_alert_thresholds)
        theme_menu = Menu(settings_menu, tearoff=0)
        theme_menu.add_command(label="Blue Theme", command=lambda: self.change_theme("blue"))
        theme_menu.add_command(label="Dark Theme", command=lambda: self.change_theme("dark"))
        theme_menu.add_command(label="Light Theme", command=lambda: self.change_theme("light"))
        settings_menu.add_cascade(label="Change Theme", menu=theme_menu)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def setup_terminal(self):
        terminal_frame = ttk.LabelFrame(self.left_frame, text="Accuarate Cyber Defense Terminal")
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.terminal_output = scrolledtext.ScrolledText(
            terminal_frame, wrap=tk.WORD, width=50, height=20
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.terminal_output.insert(tk.END, "Accuarate Cyber Defense Terminal - Type 'help' for commands\n")
        self.terminal_output.configure(state="disabled")
        
        self.terminal_input = ttk.Entry(terminal_frame)
        self.terminal_input.pack(fill=tk.X, padx=5, pady=5)
        self.terminal_input.bind("<Return>", self.process_command)
        
        # Add command history
        self.command_history = []
        self.history_index = -1
        self.terminal_input.bind("<Up>", self.prev_command)
        self.terminal_input.bind("<Down>", self.next_command)
        
        # Control buttons
        button_frame = ttk.Frame(terminal_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Clear", command=self.clear_terminal).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Help", command=self.show_help).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Exit", command=self.root.quit).pack(side=tk.RIGHT, padx=2)
    
    def setup_charts(self):
        # Threat summary frame
        threat_frame = ttk.LabelFrame(self.right_frame, text="Threat Summary")
        threat_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create figure for charts
        self.figure = plt.Figure(figsize=(10, 8), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, master=threat_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initial empty charts
        self.update_charts()
        
        # Stats frame
        stats_frame = ttk.Frame(self.right_frame)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Network stats
        ttk.Label(stats_frame, text="Network Statistics:").pack(anchor=tk.W)
        
        self.stats_text = tk.Text(stats_frame, height=5, wrap=tk.WORD)
        self.stats_text.pack(fill=tk.X, padx=5, pady=5)
        self.stats_text.insert(tk.END, "No statistics available yet.\n")
        self.stats_text.configure(state="disabled")
    
    def process_command(self, event):
        command = self.terminal_input.get().strip()
        self.terminal_input.delete(0, tk.END)
        
        if not command:
            return
        
        # Add to history
        self.command_history.append(command)
        self.history_index = len(self.command_history)
        
        # Process command
        self.print_terminal(f"> {command}")
        
        cmd_parts = command.lower().split()
        primary_cmd = cmd_parts[0]
        
        try:
            if primary_cmd == "help":
                self.show_help()
            elif primary_cmd == "ping":
                if len(cmd_parts) < 2:
                    self.print_terminal("Usage: ping <ip_address>")
                else:
                    self.ping_ip(cmd_parts[1])
            elif primary_cmd == "start":
                if len(cmd_parts) < 3 or cmd_parts[1] != "monitoring":
                    self.print_terminal("Usage: start monitoring <ip_address>")
                else:
                    self.start_monitoring(cmd_parts[2])
            elif primary_cmd == "stop":
                self.stop_monitoring()
            elif primary_cmd == "scan":
                if len(cmd_parts) < 2:
                    self.print_terminal("Usage: scan <ip_address>")
                else:
                    self.scan_ip(cmd_parts[1])
            elif primary_cmd == "view":
                if len(cmd_parts) < 2:
                    self.print_terminal("Usage: view threats")
                elif cmd_parts[1] == "threats":
                    self.view_threats()
            elif primary_cmd == "netstat":
                self.netstat()
            elif primary_cmd == "ifconfig":
                if len(cmd_parts) > 1 and cmd_parts[1] == "/all":
                    self.ifconfig(all_info=True)
                else:
                    self.ifconfig()
            elif primary_cmd == "clear":
                self.clear_terminal()
            elif primary_cmd == "exit":
                self.root.quit()
            else:
                self.print_terminal(f"Unknown command: {command}\nType 'help' for available commands")
        except Exception as e:
            self.print_terminal(f"Error executing command: {str(e)}")
    
    def prev_command(self, event):
        if self.command_history and self.history_index > 0:
            self.history_index -= 1
            self.terminal_input.delete(0, tk.END)
            self.terminal_input.insert(0, self.command_history[self.history_index])
    
    def next_command(self, event):
        if self.command_history and self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.terminal_input.delete(0, tk.END)
            self.terminal_input.insert(0, self.command_history[self.history_index])
        elif self.command_history and self.history_index == len(self.command_history) - 1:
            self.history_index += 1
            self.terminal_input.delete(0, tk.END)
    
    def print_terminal(self, text):
        self.terminal_output.configure(state="normal")
        self.terminal_output.insert(tk.END, text + "\n")
        self.terminal_output.see(tk.END)
        self.terminal_output.configure(state="disabled")
    
    def clear_terminal(self):
        self.terminal_output.configure(state="normal")
        self.terminal_output.delete(1.0, tk.END)
        self.terminal_output.configure(state="disabled")
    
    def show_help(self):
        help_text = """
Available Commands:
  help                  - Show this help message
  ping <ip>            - Ping an IP address
  start monitoring <ip> - Start monitoring an IP address
  stop                 - Stop monitoring
  scan <ip>            - Scan an IP address for open ports
  view threats         - View detected threats
  netstat              - Show network statistics
  ifconfig             - Show network interface configuration
  ifconfig /all        - Show detailed network interface info
  clear                - Clear the terminal
  exit                 - Exit the program
"""
        self.print_terminal(help_text)
    
    def ping_ip(self, ip):
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "4", ip]
            output = subprocess.run(command, capture_output=True, text=True)
            self.print_terminal(output.stdout)
        except Exception as e:
            self.print_terminal(f"Error pinging {ip}: {str(e)}")
    
    def start_monitoring(self, ip):
        try:
            socket.inet_aton(ip)
            if ip not in self.monitored_ips:
                self.monitored_ips.add(ip)
                self.config["monitored_ips"].append(ip)
                self.save_config()
            
            if not self.monitoring:
                self.monitoring = True
                self.sniffer_thread = threading.Thread(target=self.start_sniffing, daemon=True)
                self.sniffer_thread.start()
                self.print_terminal(f"Started monitoring {ip} and network traffic")
                self.status_bar.config(text=f"Monitoring {ip} - Active")
            else:
                self.print_terminal(f"Added {ip} to monitored IPs")
        except socket.error:
            self.print_terminal(f"Invalid IP address: {ip}")
    
    def stop_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            if self.sniffer_thread and self.sniffer_thread.is_alive():
                self.sniffer_thread.join(timeout=2)
            self.print_terminal("Stopped monitoring network traffic")
            self.status_bar.config(text="Monitoring Stopped")
        else:
            self.print_terminal("No active monitoring to stop")
    
    def scan_ip(self, ip):
        self.print_terminal(f"Scanning {ip} for open ports...")
        
        try:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]
            open_ports = []
            
            def scan_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        result = s.connect_ex((ip, port))
                        if result == 0:
                            open_ports.append(port)
                except:
                    pass
            
            threads = []
            for port in common_ports:
                t = threading.Thread(target=scan_port, args=(port,))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
            
            if open_ports:
                self.print_terminal(f"Open ports on {ip}: {', '.join(map(str, open_ports))}")
                self.detect_threat("port_scan", f"Detected open ports on {ip}: {open_ports}")
            else:
                self.print_terminal(f"No common open ports found on {ip}")
        except Exception as e:
            self.print_terminal(f"Error scanning {ip}: {str(e)}")
    
    def view_threats(self):
        if not self.detected_threats:
            self.print_terminal("No threats detected yet")
            return
        
        self.print_terminal("\nDetected Threats:")
        for i, threat in enumerate(self.detected_threats, 1):
            self.print_terminal(f"{i}. [{threat['type']}] {threat['description']} at {threat['timestamp']}")
    
    def netstat(self):
        try:
            connections = psutil.net_connections()
            self.print_terminal("Active Connections:")
            self.print_terminal("Proto Local Address          Foreign Address        Status")
            
            for conn in connections:
                if conn.status == psutil.CONN_NONE:
                    continue
                
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                
                self.print_terminal(f"{conn.type.upper()[0]}    {laddr:20} {raddr:20} {conn.status}")
        except Exception as e:
            self.print_terminal(f"Error getting network stats: {str(e)}")
    
    def ifconfig(self, all_info=False):
        try:
            interfaces = netifaces.interfaces()
            self.print_terminal("Network Interfaces:")
            
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                self.print_terminal(f"\nInterface: {iface}")
                
                if netifaces.AF_INET in addrs:
                    self.print_terminal("IPv4 Addresses:")
                    for addr in addrs[netifaces.AF_INET]:
                        self.print_terminal(f"  Address: {addr['addr']}")
                        self.print_terminal(f"  Netmask: {addr['netmask']}")
                        if 'broadcast' in addr:
                            self.print_terminal(f"  Broadcast: {addr['broadcast']}")
                
                if all_info and netifaces.AF_LINK in addrs:
                    self.print_terminal("MAC Address:")
                    for addr in addrs[netifaces.AF_LINK]:
                        self.print_terminal(f"  MAC: {addr['addr']}")
        except Exception as e:
            self.print_terminal(f"Error getting interface info: {str(e)}")
    
    def start_sniffing(self):
        try:
            self.print_terminal("Starting network traffic monitoring...")
            
            # Get the default network interface
            default_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            
            # Start sniffing in a separate thread
            sniff(prn=self.analyze_packet, iface=default_iface, store=0)
        except Exception as e:
            self.print_terminal(f"Error starting packet capture: {str(e)}")
    
    def analyze_packet(self, packet):
        if not self.monitoring:
            return
        
        self.packet_count += 1
        
        try:
            # Extract basic packet information
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                
                # Check if packet involves monitored IPs
                if ip_src in self.monitored_ips or ip_dst in self.monitored_ips:
                    # Update stats
                    self.update_packet_stats(packet)
                    
                    # Detect threats
                    self.detect_packet_threats(packet)
        except Exception as e:
            self.print_terminal(f"Error analyzing packet: {str(e)}")
    
    def update_packet_stats(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Update general stats
            self.network_stats['total']['packets'] += 1
            self.network_stats[ip_src]['sent'] += 1
            self.network_stats[ip_dst]['received'] += 1
            
            # Protocol specific stats
            if TCP in packet:
                self.network_stats['total']['tcp'] += 1
                self.network_stats[ip_src]['tcp_sent'] += 1
                self.network_stats[ip_dst]['tcp_received'] += 1
                
                # Port specific stats
                dst_port = packet[TCP].dport
                self.network_stats[ip_src][f'tcp_port_{dst_port}'] += 1
                
            elif UDP in packet:
                self.network_stats['total']['udp'] += 1
                self.network_stats[ip_src]['udp_sent'] += 1
                self.network_stats[ip_dst]['udp_received'] += 1
                
                # Port specific stats
                dst_port = packet[UDP].dport
                self.network_stats[ip_src][f'udp_port_{dst_port}'] += 1
                
            elif ICMP in packet:
                self.network_stats['total']['icmp'] += 1
                self.network_stats[ip_src]['icmp_sent'] += 1
                self.network_stats[ip_dst]['icmp_received'] += 1
    
    def detect_packet_threats(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Port scanning detection
            if TCP in packet and packet[TCP].flags == 0x02:  # SYN flag only
                port = packet[TCP].dport
                self.network_stats[ip_src][f'syn_to_port_{port}'] += 1
                
                # Check if this IP is sending SYN packets to multiple ports
                syn_count = sum(1 for k in self.network_stats[ip_src] if k.startswith('syn_to_port_'))
                if syn_count > self.config["alert_thresholds"]["port_scan"]:
                    self.detect_threat(
                        "port_scan",
                        f"Possible port scan detected from {ip_src} to {ip_dst} ({syn_count} ports)"
                    )
            
            # Ping of Death detection
            if ICMP in packet and len(packet) > 65535:
                self.detect_threat(
                    "ping_of_death",
                    f"Ping of Death attack detected from {ip_src} to {ip_dst}"
                )
            
            # DOS/DDOS detection
            if self.network_stats[ip_src]['sent'] > self.config["alert_thresholds"]["dos"]:
                if self.network_stats[ip_src]['sent'] > self.config["alert_thresholds"]["ddos"]:
                    self.detect_threat(
                        "ddos",
                        f"Possible DDoS attack detected from {ip_src} (high packet rate)"
                    )
                else:
                    self.detect_threat(
                        "dos",
                        f"Possible DoS attack detected from {ip_src} (high packet rate)"
                    )
            
            # Unusual traffic detection
            normal_ports = [80, 443, 22, 53]  # HTTP, HTTPS, SSH, DNS
            if TCP in packet and packet[TCP].dport not in normal_ports:
                self.network_stats[ip_src][f'unusual_port_{packet[TCP].dport}'] += 1
                if self.network_stats[ip_src][f'unusual_port_{packet[TCP].dport}'] > self.config["alert_thresholds"]["unusual_traffic"]:
                    self.detect_threat(
                        "unusual_traffic",
                        f"Unusual traffic detected from {ip_src} to port {packet[TCP].dport}"
                    )
    
    def detect_threat(self, threat_type, description):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        threat = {
            "type": threat_type,
            "description": description,
            "timestamp": timestamp,
            "severity": self.get_threat_severity(threat_type)
        }
        
        self.detected_threats.append(threat)
        
        # Update UI
        self.update_charts()
        
        # Send Telegram alert
        self.send_telegram_alert(threat)
        
        # Print to terminal
        self.print_terminal(f"[ALERT] {threat_type.upper()}: {description}")
    
    def get_threat_severity(self, threat_type):
        severities = {
            "ddos": "Critical",
            "dos": "High",
            "port_scan": "Medium",
            "unusual_traffic": "Low",
            "ping_of_death": "High"
        }
        return severities.get(threat_type, "Medium")
    
    def send_telegram_alert(self, threat):
        if not self.telegram_bot.is_configured():
            return
        
        message = (
            f"🚨 *Accurate Cyber Defense Advanced Network Monitoring Tool* 🚨\n"
            f"*Type*: {threat['type'].upper()}\n"
            f"*Severity*: {threat['severity']}\n"
            f"*Description*: {threat['description']}\n"
            f"*Timestamp*: {threat['timestamp']}"
        )
        
        self.telegram_bot.send_message(message)
    
    def update_stats(self):
        if self.monitoring:
            uptime = time.time() - self.start_time
            hours, remainder = divmod(uptime, 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime_str = f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
            
            stats_text = (
                f"Monitoring Uptime: {uptime_str}\n"
                f"Packets Analyzed: {self.packet_count}\n"
                f"Threats Detected: {len(self.detected_threats)}\n"
                f"Monitored IPs: {', '.join(self.monitored_ips) if self.monitored_ips else 'None'}"
            )
            
            self.stats_text.configure(state="normal")
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, stats_text)
            self.stats_text.configure(state="disabled")
        
        # Schedule next update
        self.root.after(5000, self.update_stats)
    
    def update_charts(self):
        # Clear previous charts
        self.figure.clear()
        
        if not self.detected_threats:
            # Show empty message if no threats
            ax = self.figure.add_subplot(111)
            ax.text(0.5, 0.5, "No threats detected yet", 
                    ha='center', va='center', fontsize=12)
            ax.axis('off')
        else:
            # Prepare threat data for charts
            threat_types = [t['type'] for t in self.detected_threats]
            unique_types, type_counts = np.unique(threat_types, return_counts=True)
            
            # Pie chart
            ax1 = self.figure.add_subplot(121)
            ax1.pie(type_counts, labels=unique_types, autopct='%1.1f%%', startangle=90)
            ax1.set_title('Threat Distribution')
            
            # Bar chart
            ax2 = self.figure.add_subplot(122)
            ax2.bar(unique_types, type_counts)
            ax2.set_title('Threat Count by Type')
            ax2.set_ylabel('Count')
            ax2.tick_params(axis='x', rotation=45)
        
        self.figure.tight_layout()
        self.canvas.draw()
    
    def get_network_interfaces(self):
        try:
            return netifaces.interfaces()
        except:
            return []
    
    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Merge with default config to ensure all keys exist
                    return {**DEFAULT_CONFIG, **config}
        except Exception as e:
            self.print_terminal(f"Error loading config: {str(e)}")
        
        return DEFAULT_CONFIG
    
    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            self.print_terminal(f"Error saving config: {str(e)}")
    
    def load_config_dialog(self):
        file_path = filedialog.askopenfilename(
            title="Load Configuration",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    config = json.load(f)
                    self.config = {**DEFAULT_CONFIG, **config}
                    self.save_config()
                    self.print_terminal(f"Configuration loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load config: {str(e)}")
    
    def save_config_dialog(self):
        file_path = filedialog.asksaveasfilename(
            title="Save Configuration",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.config, f, indent=4)
                self.print_terminal(f"Configuration saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save config: {str(e)}")
    
    def save_report(self):
        file_path = filedialog.asksaveasfilename(
            title="Save Threat Report",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write("CyberGuard Threat Report\n")
                    f.write(f"Generated on: {datetime.datetime.now()}\n\n")
                    
                    if not self.detected_threats:
                        f.write("No threats detected during this monitoring session.\n")
                    else:
                        f.write(f"Total Threats Detected: {len(self.detected_threats)}\n\n")
                        f.write("Threat Details:\n")
                        for i, threat in enumerate(self.detected_threats, 1):
                            f.write(
                                f"{i}. [{threat['type'].upper()}] {threat['description']} "
                                f"(Severity: {threat['severity']}, Time: {threat['timestamp']})\n"
                            )
                
                self.print_terminal(f"Threat report saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {str(e)}")
    
    def open_network_scanner(self):
        scanner_window = tk.Toplevel(self.root)
        scanner_window.title("Network Scanner")
        scanner_window.geometry("600x400")
        
        ttk.Label(scanner_window, text="Network Scanner Tool", font=('Arial', 12, 'bold')).pack(pady=10)
        
        frame = ttk.Frame(scanner_window)
        frame.pack(pady=10)
        
        ttk.Label(frame, text="IP Range:").grid(row=0, column=0, padx=5, pady=5)
        self.scan_start_ip = ttk.Entry(frame, width=15)
        self.scan_start_ip.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(frame, text="to").grid(row=0, column=2, padx=5, pady=5)
        self.scan_end_ip = ttk.Entry(frame, width=15)
        self.scan_end_ip.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Button(frame, text="Scan", command=self.run_network_scan).grid(row=0, column=4, padx=10)
        
        self.scan_results = scrolledtext.ScrolledText(scanner_window, wrap=tk.WORD)
        self.scan_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.scan_results.insert(tk.END, "Scan results will appear here...")
    
    def run_network_scan(self):
        start_ip = self.scan_start_ip.get().strip()
        end_ip = self.scan_end_ip.get().strip()
        
        if not start_ip or not end_ip:
            messagebox.showerror("Error", "Please enter both start and end IP addresses")
            return
        
        self.scan_results.delete(1.0, tk.END)
        self.scan_results.insert(tk.END, f"Scanning network from {start_ip} to {end_ip}...\n")
        
        # This is a placeholder - actual network scanning would go here
        # In a real implementation, you would scan the IP range
        self.scan_results.insert(tk.END, "Scan complete. No actual scanning implemented in this demo.\n")
    
    def open_packet_analyzer(self):
        analyzer_window = tk.Toplevel(self.root)
        analyzer_window.title("Packet Analyzer")
        analyzer_window.geometry("800x600")
        
        ttk.Label(analyzer_window, text="Packet Analyzer Tool", font=('Arial', 12, 'bold')).pack(pady=10)
        
        self.packet_list = ttk.Treeview(analyzer_window, columns=('Time', 'Source', 'Destination', 'Protocol', 'Length'), show='headings')
        self.packet_list.heading('Time', text='Time')
        self.packet_list.heading('Source', text='Source')
        self.packet_list.heading('Destination', text='Destination')
        self.packet_list.heading('Protocol', text='Protocol')
        self.packet_list.heading('Length', text='Length')
        self.packet_list.column('Time', width=120)
        self.packet_list.column('Source', width=150)
        self.packet_list.column('Destination', width=150)
        self.packet_list.column('Protocol', width=80)
        self.packet_list.column('Length', width=60)
        self.packet_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add some sample data
        self.packet_list.insert('', 'end', values=('12:34:56', '192.168.1.1', '192.168.1.2', 'TCP', '64'))
        self.packet_list.insert('', 'end', values=('12:34:57', '192.168.1.2', '192.168.1.1', 'TCP', '60'))
        self.packet_list.insert('', 'end', values=('12:34:58', '8.8.8.8', '192.168.1.1', 'UDP', '120'))
    
    def open_telegram_settings(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Telegram Settings")
        settings_window.geometry("500x300")
        
        ttk.Label(settings_window, text="Telegram Bot Configuration", font=('Arial', 12, 'bold')).pack(pady=10)
        
        frame = ttk.Frame(settings_window)
        frame.pack(pady=10)
        
        ttk.Label(frame, text="Bot Token:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.token_entry = ttk.Entry(frame, width=40)
        self.token_entry.grid(row=0, column=1, padx=5, pady=5)
        self.token_entry.insert(0, self.config["telegram_token"])
        
        ttk.Label(frame, text="Chat ID:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.chat_id_entry = ttk.Entry(frame, width=40)
        self.chat_id_entry.grid(row=1, column=1, padx=5, pady=5)
        self.chat_id_entry.insert(0, self.config["telegram_chat_id"])
        
        button_frame = ttk.Frame(settings_window)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Save", command=lambda: self.save_telegram_settings(settings_window)).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Test", command=self.test_telegram_bot).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=settings_window.destroy).pack(side=tk.RIGHT, padx=10)
    
    def save_telegram_settings(self, window):
        self.config["telegram_token"] = self.token_entry.get().strip()
        self.config["telegram_chat_id"] = self.chat_id_entry.get().strip()
        self.save_config()
        
        # Update Telegram bot instance
        self.telegram_bot = TelegramBot(
            self.config["telegram_token"],
            self.config["telegram_chat_id"]
        )
        
        messagebox.showinfo("Success", "Telegram settings saved successfully")
        window.destroy()
    
    def test_telegram_bot(self):
        if not self.telegram_bot.is_configured():
            messagebox.showerror("Error", "Please enter both Telegram token and chat ID")
            return
        
        try:
            self.telegram_bot.send_message("AccurateBot: This is a test message from your security monitoring system.")
            messagebox.showinfo("Success", "Test message sent successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send test message: {str(e)}")
    
    def open_alert_thresholds(self):
        thresholds_window = tk.Toplevel(self.root)
        thresholds_window.title("Alert Threshold Settings")
        thresholds_window.geometry("400x300")
        
        ttk.Label(thresholds_window, text="Alert Threshold Configuration", font=('Arial', 12, 'bold')).pack(pady=10)
        
        frame = ttk.Frame(thresholds_window)
        frame.pack(pady=10)
        
        # Port Scan Threshold
        ttk.Label(frame, text="Port Scan (SYN packets):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.port_scan_entry = ttk.Entry(frame, width=10)
        self.port_scan_entry.grid(row=0, column=1, padx=5, pady=5)
        self.port_scan_entry.insert(0, str(self.config["alert_thresholds"]["port_scan"]))
        
        # DDoS Threshold
        ttk.Label(frame, text="DDoS (packets/sec):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.ddos_entry = ttk.Entry(frame, width=10)
        self.ddos_entry.grid(row=1, column=1, padx=5, pady=5)
        self.ddos_entry.insert(0, str(self.config["alert_thresholds"]["ddos"]))
        
        # DoS Threshold
        ttk.Label(frame, text="DoS (packets/sec):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        self.dos_entry = ttk.Entry(frame, width=10)
        self.dos_entry.grid(row=2, column=1, padx=5, pady=5)
        self.dos_entry.insert(0, str(self.config["alert_thresholds"]["dos"]))
        
        # Unusual Traffic Threshold
        ttk.Label(frame, text="Unusual Traffic (packets):").grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        self.unusual_entry = ttk.Entry(frame, width=10)
        self.unusual_entry.grid(row=3, column=1, padx=5, pady=5)
        self.unusual_entry.insert(0, str(self.config["alert_thresholds"]["unusual_traffic"]))
        
        # Ping of Death Threshold
        ttk.Label(frame, text="Ping of Death (packets):").grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        self.ping_entry = ttk.Entry(frame, width=10)
        self.ping_entry.grid(row=4, column=1, padx=5, pady=5)
        self.ping_entry.insert(0, str(self.config["alert_thresholds"]["ping_of_death"]))
        
        button_frame = ttk.Frame(thresholds_window)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Save", command=lambda: self.save_alert_thresholds(thresholds_window)).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancel", command=thresholds_window.destroy).pack(side=tk.RIGHT, padx=10)
    
    def save_alert_thresholds(self, window):
        try:
            self.config["alert_thresholds"]["port_scan"] = int(self.port_scan_entry.get())
            self.config["alert_thresholds"]["ddos"] = int(self.ddos_entry.get())
            self.config["alert_thresholds"]["dos"] = int(self.dos_entry.get())
            self.config["alert_thresholds"]["unusual_traffic"] = int(self.unusual_entry.get())
            self.config["alert_thresholds"]["ping_of_death"] = int(self.ping_entry.get())
            
            self.save_config()
            messagebox.showinfo("Success", "Alert thresholds saved successfully")
            window.destroy()
        except ValueError:
            messagebox.showerror("Error", "Please enter valid integer values for all thresholds")
    
    def change_theme(self, theme):
        self.config["theme"] = theme
        self.save_config()
        self.apply_theme(theme)
    
    def show_user_guide(self):
        guide_window = tk.Toplevel(self.root)
        guide_window.title("Accurate Cyber Defense Advaned Network Monitoring Tool Guit Bot")
        guide_window.geometry("700x500")
        
        text = scrolledtext.ScrolledText(guide_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        guide_text = """
Accurate Cyber Defense User Guide

1. Getting Started:
   - Use the 'start monitoring <ip>' command to begin monitoring network traffic
   - The dashboard will display detected threats and network statistics

2. Terminal Commands:
   - ping <ip>: Test connectivity to an IP address
   - scan <ip>: Scan an IP for open ports
   - view threats: Show all detected threats
   - netstat: Display active network connections
   - ifconfig: Show network interface information

3. Threat Detection:
   CyberGuard detects the following threats:
   - Port scanning
   - DDoS and DoS attacks
   - Unusual network traffic
   - Ping of Death attacks

4. Telegram Integration:
   - Configure your Telegram bot token and chat ID in Settings
   - Alerts will be sent to your Telegram when threats are detected

5. Reports:
   - Save threat reports from the File menu
   - Reports include all detected threats with timestamps
"""
        text.insert(tk.END, guide_text)
        text.configure(state="disabled")
    
    def show_about(self):
        messagebox.showinfo(
            "About Accurate Cyber Defense",
            "Accurate Cyber Defense- Advanced Network Threat Monitoring BOT\n\n"
            "Version 1.0\n"
            "© 2025 Accurate Cyber Defense Security Bot\n\n"
            "A comprehensive network monitoring solution for detecting "
            "and alerting on various cybersecurity threats in real-time."
        )

class TelegramBot:
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
    
    def is_configured(self):
        return bool(self.token and self.chat_id)
    
    def send_message(self, text):
        if not self.is_configured():
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            params = {
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(url, params=params)
            return response.status_code == 200
        except Exception as e:
            print(f"Error sending Telegram message: {str(e)}")
            return False

def main():
    root = tk.Tk()
    app = CyberGuard(root)
    root.mainloop()

if __name__ == "__main__":
    main()