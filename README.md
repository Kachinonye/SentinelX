# 🛡️ SentinelX — Adaptive Linux Intrusion Detection & Automated Response Framework

**SentinelX** is an advanced Bash-based Linux security monitoring and intrusion response framework designed to detect suspicious activity, monitor system health, analyze network behavior, and automatically respond to potential threats.

Built as a comprehensive Linux administration and cybersecurity project, SentinelX combines intrusion detection, process monitoring, network inspection, firewall automation, logging, and configurable response mechanisms into a single security platform.

---

## ✨ Features

- 🛡️ SSH authentication monitoring
- 🔐 Detects repeated login failures and suspicious `sudo` activity
- 👀 Monitors suspicious processes and abnormal CPU or memory usage
- 🌐 Watches network connections and blacklisted IP addresses
- 🚫 Automatically blocks malicious IPs
- ⚡ Terminates suspicious processes
- 📧 Optional administrator notifications
- ⚙️ Fully configurable through `/etc/sentinelx.conf`
- 🧪 Safe **DRY_RUN** mode for testing
- 📝 Centralized logging
- 🔒 Supports `iptables`, `nftables`, and `UFW`
- 🚦 Prevents multiple instances using `flock` or PID locking
- 🐧 Compatible with modern Linux distributions

---

## 📂 Project Structure

```text
SentinelX/
├── sentinelx.sh
├── sentinelx.conf
├── logs/
└── README.md
```

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/Kachinonye/sentinelx.git
```

Install the script:

```bash
sudo cp sentinelx.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/sentinelx.sh
```

Create the configuration file:

```bash
sudo nano /etc/sentinelx.conf
```

Run SentinelX:

```bash
sudo sentinelx.sh
```

---

## ⚙️ Configuration

Configuration options include:

- Monitoring interval
- CPU threshold
- Memory threshold
- DRY_RUN mode
- Firewall backend
- Email alerts
- Logging options

---

## 💼 Skills Demonstrated

This project showcases practical experience with:

- Linux System Administration
- Bash Shell Scripting
- Linux Security
- Intrusion Detection
- Incident Response
- Firewall Automation
- Process Monitoring
- Network Monitoring
- SSH Security
- Configuration Management
- Log Analysis
- Automation
- Technical Documentation

---

## 🎯 Use Cases

SentinelX is ideal for:

- Linux System Administrators
- DevOps Engineers
- Cloud Engineers
- Security Analysts
- Home Lab Security
- Server Hardening
- Linux Administration Training

---

## 🔮 Planned Enhancements

Future releases may include:

- Web dashboard
- Threat intelligence feeds
- Geo-IP blocking
- Email and Slack alerts
- JSON logging
- HTML security reports
- Multi-server management
- Plugin architecture
- AI-assisted anomaly detection

---

## 👨‍💻 Author

**Kachinonye Nmezi**

Linux Administrator | Bash Automation Specialist | AWS Cloud Learner

GitHub: https://github.com/Kachinonye

LinkedIn: https://www.linkedin.com/in/kachinonye-nmezi-74170723b/

---

## 📜 License

Licensed under the MIT License.
