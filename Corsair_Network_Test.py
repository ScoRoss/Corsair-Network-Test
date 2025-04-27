#Author: Ross Lamont
#Date: 27/04/2025
#Description: A network testing tool for Corsair devices, providing various network diagnostics and performance tests.
#Version Alpha: 0.9 
# This script is designed to be run as a standalone application and provides a GUI for users to perform network tests.

import time
import threading
import socket
import requests
import ping3
import speedtest
import dns.resolver
import dns.exception
import json
from datetime import datetime
from Mail_Trace import install_mail_trace, create_mail_trace_tab
install_mail_trace()
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from PIL import Image, ImageTk


# Main application class for the network testing tool
class NetworkTesterApp:
    def __init__(self, root):
        # Initialize the main application window
        self.root = root
        self.root.title("Corsair Network Test Tool")
        self.root.geometry("900x700")
        self.root.configure(bg='#0078D7')
        
        # Load and display an icon (if available)
        try:
            self.image = Image.open("network_icon.png")
            self.image = self.image.resize((150, 150), Image.LANCZOS)
            self.tk_image = ImageTk.PhotoImage(self.image)
            self.image_label = tk.Label(root, image=self.tk_image, bg='#0078D7')
            self.image_label.pack(pady=10)
            self.mail_trace_tab = create_mail_trace_tab(self.notebook)
        except:
            pass
        
        # Create the main frame for the application
        self.main_frame = tk.Frame(root, bg='white', padx=10, pady=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Configure styles for the tabs
        style = ttk.Style()
        style.configure('TNotebook', background='white')
        style.configure('TNotebook.Tab', background='#0078D7', foreground='white')
        
        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Add tabs for local network and website/DNS tests
        self.local_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.local_tab, text="Local Network")
        self.setup_local_tab()
        
        self.website_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.website_tab, text="Website/DNS")
        self.setup_website_tab()
                # — Mail Trace Tab —
        create_mail_trace_tab(self.notebook)
        
        # Console for logging messages
        self.console = scrolledtext.ScrolledText(self.main_frame, height=12, wrap=tk.WORD)
        self.console.pack(fill=tk.BOTH, expand=False, pady=(10,0))
        self.console.insert(tk.END, "Ready to perform tests...\n")
        
        # Save button to save test results
        self.save_btn = tk.Button(self.main_frame, text="💾 Save Results", 
                                  command=self.save_results,
                                  bg='#0078D7', fg='black',
                                  relief=tk.RAISED, bd=3,
                                  font=('Arial', 10, 'bold'))
        self.save_btn.pack(pady=10)
        self.save_btn.config(state=tk.DISABLED)  # Disabled until results are available
        
        # Status bar to display the current status
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = tk.Label(root, textvariable=self.status_var, 
                                  relief=tk.SUNKEN, anchor=tk.W,
                                  bg='#005A9E', fg='white')
        self.status_bar.pack(fill=tk.X)
        
        # Dictionary to store test data
        self.test_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "local_network": {},
            "website_tests": []
        }

    # Setup the "Local Network" tab
    def setup_local_tab(self):
        style = ttk.Style()
        style.configure('Blue.TButton', foreground='black', background='#0078D7',
                       font=('Arial', 10, 'bold'))

        # Section for displaying network information
        info_frame = ttk.LabelFrame(self.local_tab, text="Network Information")
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(info_frame, text="Get Network Info", 
                   command=self.get_network_info,
                   style='Blue.TButton').pack(pady=5)
        self.local_info_text = scrolledtext.ScrolledText(info_frame, height=6)
        self.local_info_text.pack(fill=tk.X, padx=5, pady=5)

        # Section for running a speed test
        speed_frame = ttk.LabelFrame(self.local_tab, text="Speed Test")
        speed_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(speed_frame, text="Run Speed Test", 
                   command=self.run_speed_test,
                   style='Blue.TButton').pack(pady=5)
        self.speed_results = ttk.Label(speed_frame, text="Not tested yet")
        self.speed_results.pack()

        # Section for advanced network tests
        adv_frame = ttk.LabelFrame(self.local_tab, text="Advanced Tests")
        adv_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Button(adv_frame, text="Ping Google DNS", 
                   command=lambda: self.ping_test("8.8.8.8"),
                   style='Blue.TButton').grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(adv_frame, text="Ping Local Gateway", 
                   command=lambda: self.ping_test("192.168.1.1"),
                   style='Blue.TButton').grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(adv_frame, text="Scan Common Ports", 
                   command=self.scan_common_ports,
                   style='Blue.TButton').grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(adv_frame, text="Traceroute to Google", 
                   command=lambda: self.run_traceroute("google.com"),
                   style='Blue.TButton').grid(row=1, column=1, padx=5, pady=5)

    # Setup the "Website/DNS" tab
    def setup_website_tab(self):
        style = ttk.Style()
        style.configure('Blue.TButton', foreground='black', background='#0078D7',
                       font=('Arial', 10, 'bold'))

        # Section for testing website connectivity
        website_frame = ttk.LabelFrame(self.website_tab, text="Website Tests")
        website_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(website_frame, text="Website URL:").grid(row=0, column=0, padx=5, pady=5)
        self.website_entry = ttk.Entry(website_frame, width=30)
        self.website_entry.grid(row=0, column=1, padx=5, pady=5)
        self.website_entry.insert(0, "example.com")
        ttk.Button(website_frame, text="Test Website", 
                   command=self.test_website,
                   style='Blue.TButton').grid(row=0, column=2, padx=5, pady=5)

        # Section for performing DNS lookups
        dns_frame = ttk.LabelFrame(self.website_tab, text="DNS Tests")
        dns_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(dns_frame, text="Hostname:").grid(row=0, column=0, padx=5, pady=5)
        self.dns_entry = ttk.Entry(dns_frame, width=30)
        self.dns_entry.grid(row=0, column=1, padx=5, pady=5)
        self.dns_entry.insert(0, "example.com")
        ttk.Button(dns_frame, text="DNS Lookup", 
                   command=self.dns_lookup,
                   style='Blue.TButton').grid(row=0, column=2, padx=5, pady=5)

        # Section for displaying test results
        results_frame = ttk.LabelFrame(self.website_tab, text="Test Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.website_results = scrolledtext.ScrolledText(results_frame, height=10)
        self.website_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Log messages to the console and update the status bar
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{timestamp}] {message}\n")
        self.console.see(tk.END)
        self.status_var.set(message)
        self.root.update()

    # Run a function in a separate thread
    def run_in_thread(self, func, *args):
        thread = threading.Thread(target=func, args=args)
        thread.daemon = True
        thread.start()

    # Fetch and display network information
    def get_network_info(self):
        self.run_in_thread(self._get_network_info)

    def _get_network_info(self):
        try:
            self.log("Getting network information...")
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            try:
                public_ip = requests.get('https://api.ipify.org').text
            except:
                public_ip = "Unable to determine"
            info = f"Hostname: {hostname}\nLocal IP: {local_ip}\nPublic IP: {public_ip}\n"
            self.local_info_text.delete(1.0, tk.END)
            self.local_info_text.insert(tk.END, info)
            self.test_data["local_network"]["info"] = {"hostname": hostname, "local_ip": local_ip, "public_ip": public_ip}
            self.log("Network information retrieved successfully")
            self.save_btn.config(state=tk.NORMAL)
        except Exception as e:
            self.log(f"Error getting network info: {e}")

    # Run a speed test
    def run_speed_test(self):
        self.run_in_thread(self._run_speed_test)

    def _run_speed_test(self):
        try:
            self.log("Starting speed test...")
            st = speedtest.Speedtest()
            st.get_best_server()
            self.log("Testing download speed...")
            download = st.download() / 1_000_000
            self.log(f"Download speed: {download:.2f} Mbps")
            self.log("Testing upload speed...")
            upload = st.upload() / 1_000_000
            self.log(f"Upload speed: {upload:.2f} Mbps")
            result = f"Download: {download:.2f} Mbps\nUpload: {upload:.2f} Mbps"
            self.speed_results.config(text=result)
            self.test_data["local_network"]["speed_test"] = {"download": download, "upload": upload, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            self.log("Speed test completed successfully")
            self.save_btn.config(state=tk.NORMAL)
        except Exception as e:
            self.log(f"Speed test failed: {e}")

    # Ping a target and log the results
    def ping_test(self, target):
        self.run_in_thread(self._ping_test, target)

    def _ping_test(self, target):
        try:
            self.log(f"Pinging {target}...")
            latency = ping3.ping(target, unit='ms')
            if latency is not None:
                self.log(f"Ping to {target}: {latency:.2f} ms")
                self.test_data["local_network"].setdefault("ping_tests", []).append({"target": target, "latency": latency, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
                self.save_btn.config(state=tk.NORMAL)
            else:
                self.log(f"No response from {target}")
        except Exception as e:
            self.log(f"Ping test failed: {e}")

    # Scan common ports on the local machine
    def scan_common_ports(self):
        self.run_in_thread(self._scan_common_ports)

    def _scan_common_ports(self):
        try:
            target = socket.gethostbyname(socket.gethostname())
            self.log(f"Scanning common ports on {target}...")
            common_ports = [21,22,23,25,53,80,110,143,443,3389]
            open_ports = []
            for port in common_ports:
                self.log(f"Checking port {port}...")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((target, port)) == 0:
                    open_ports.append(port)
                    self.log(f"Port {port} is open")
                sock.close()
            if open_ports:
                self.log(f"Open ports: {', '.join(map(str, open_ports))}")
            else:
                self.log("No common ports open")
            self.test_data["local_network"]["port_scan"] = {"target": target, "open_ports": open_ports, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            self.save_btn.config(state=tk.NORMAL)
        except Exception as e:
            self.log(f"Port scan failed: {e}")

    # Perform a traceroute to a target
    def run_traceroute(self, target):
        self.run_in_thread(self._run_traceroute, target)

    def _run_traceroute(self, target):
        try:
            self.log(f"Running traceroute to {target}...")
            max_hops = 30
            port = 33434
            ttl = 1
            results = []
            while ttl <= max_hops:
                recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                send.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                recv.bind(("", port))
                send.sendto(b"", (target, port))
                curr_addr = None
                try:
                    _, curr_addr = recv.recvfrom(512)
                    curr_addr = curr_addr[0]
                except:
                    pass
                finally:
                    send.close()
                    recv.close()
                if curr_addr:
                    try:
                        curr_name = socket.gethostbyaddr(curr_addr)[0]
                    except:
                        curr_name = curr_addr
                    hop = f"{ttl}\t{curr_name} ({curr_addr})"
                    self.log(hop)
                    results.append(hop)
                    if curr_addr == socket.gethostbyname(target):
                        break
                else:
                    self.log(f"{ttl}\t*")
                    results.append(f"{ttl}\t*")
                ttl += 1
            self.test_data["local_network"]["traceroute"] = {"target": target, "results": results, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            self.save_btn.config(state=tk.NORMAL)
        except Exception as e:
            self.log(f"Traceroute failed: {e}")

    # Test a website's connectivity and performance
    def test_website(self):
        url = self.website_entry.get().strip()
        if not url.startswith(('http://','https://')):
            url = 'http://' + url
        self.run_in_thread(self._test_website, url)

    def _test_website(self, url):
        try:
            self.website_results.delete(1.0, tk.END)
            self.log(f"Testing website: {url}")
            test = {"url": url, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "success": False}
            host = url.split('//')[-1].split('/')[0]
            try:
                ip = socket.gethostbyname(host)
                self.website_results.insert(tk.END, f"DNS Resolution: {host} → {ip}\n\n")
                test["dns"] = {"hostname": host, "ip": ip}
            except:
                self.website_results.insert(tk.END, f"DNS failed for {host}\n")
                return
            start = time.time()
            resp = requests.get(url, timeout=10)
            load = (time.time()-start)*1000
            self.website_results.insert(tk.END, f"Status: {resp.status_code}\nLoad Time: {load:.2f} ms\nSize: {len(resp.content)} bytes\n")
            test.update({"success": True, "http": {"status_code": resp.status_code, "load_time": load, "content_size": len(resp.content)}})
            self.log(f"Website status {resp.status_code}")
            self.test_data["website_tests"].append(test)
            self.save_btn.config(state=tk.NORMAL)
        except Exception as e:
            self.log(f"Website test error: {e}")

    # Perform a DNS lookup for a given hostname
    def dns_lookup(self):
        host = self.dns_entry.get().strip()
        self.run_in_thread(self._dns_lookup, host)

    def _dns_lookup(self, host):
        try:
            self.website_results.delete(1.0, tk.END)
            self.log(f"Detailed DNS lookup for {host}")
            resolver = dns.resolver.Resolver()
            servers = resolver.nameservers
            self.website_results.insert(tk.END, "Using DNS servers:\n" + "\n".join(map(str,servers)) + "\n\n")
            record_types = ['A','AAAA','CNAME','MX','NS','TXT','SOA']
            for r in record_types:
                try:
                    start = time.time()
                    ans = resolver.resolve(host, r, lifetime=5)
                    rt = (time.time()-start)*1000
                    self.website_results.insert(tk.END, f"{r} (time {rt:.2f} ms):\n")
                    recs = []
                    for rd in ans:
                        self.website_results.insert(tk.END, f" - {rd} (TTL {ans.rrset.ttl})\n")
                        recs.append(str(rd))
                    self.website_results.insert(tk.END, "\n")
                except dns.resolver.NoAnswer:
                    self.website_results.insert(tk.END, f"{r}: No answer\n")
                except dns.resolver.NXDOMAIN:
                    self.website_results.insert(tk.END, f"{r}: NXDOMAIN\n")
                except dns.exception.DNSException as e:
                    self.website_results.insert(tk.END, f"{r}: Error {e}\n")
            self.log(f"DNS lookup done for {host}")
        except Exception as e:
            self.log(f"DNS lookup error: {e}")

    # Save the test results to a JSON file
    def save_results(self):
        try:
            fname = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[("JSON","*.json"),("All","*.*")])
            if fname:
                with open(fname,'w') as f:
                    json.dump(self.test_data, f, indent=2)
                self.log(f"Saved to {fname}")
        except Exception as e:
            self.log(f"Save error: {e}")

# Entry point for the application
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTesterApp(root)
    root.mainloop()