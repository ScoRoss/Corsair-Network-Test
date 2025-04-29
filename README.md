# Corsair Network Test Tool

A standalone Python/Tkinter application for diagnosing network connectivity and performance, specifically tailored for Corsair devices and general network troubleshooting. Includes a built-in “Mail Trace” tab that captures and displays SMTP handshake debug information whenever a crash report is sent.

---

## 🛠️ Features

### Local Network
- **Get Network Info**: Hostname, local IP, public IP (via [ipify.org][ipify]).
- **Speed Test**: Download/upload throughput using [speedtest-cli][speedtest].
- **Ping Tests**: Latency to Google DNS (`8.8.8.8`) and local gateway (`192.168.1.1`).
- **Port Scan**: Check common TCP ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 3389).
- **Traceroute**: Hop-by-hop path to a given host (default: `google.com`).

### Website & DNS
- **Website Test**:  
  - DNS resolution  
  - HTTP status code  
  - Load time (ms)  
  - Response size (bytes)
- **DNS Lookup**: Query A, AAAA, CNAME, MX, NS, TXT, SOA records, with response times and TTLs.

### Mail Trace
- **Crash-Report Email**: Captures unhandled exceptions in Tkinter callbacks and emails a full Python traceback.
- **SMTP Debug Trace**: Records the entire SMTP handshake (EHLO, STARTTLS, AUTH, MAIL, RCPT, DATA) and displays it in-app for real-time troubleshooting.
- **Configurable SMTP Settings**:  
  - Host, port, username, password (app-password recommended for Gmail)  
  - Recipient list (comma-separated)  
- **In-App Log Console**: View live logs and SMTP trace lines without cluttering the terminal.

---

## 🚀 Installation

1. **Clone the repo**  
   ```bash
   git clone https://github.com/<your-username>/corsair-network-test.git
   cd corsair-network-test

### Future Work

# Will be looking to add a RED Warning text for when a DNS is down.
