# 🛡️ SentinelX — Adaptive Linux Intrusion Detection & Automated Response Framework

**SentinelX** is an advanced Bash-based Linux intrusion detection and automated response framework that continuously monitors system activity, detects suspicious behavior, and automatically responds to potential security threats.

Designed as a comprehensive Linux administration and cybersecurity project, SentinelX combines process monitoring, authentication log analysis, network inspection, firewall automation, configuration management, and adaptive response into a single security platform.

---

## ✨ Features

- 🔐 Monitors SSH authentication logs for brute-force attacks
- 🚨 Detects suspicious `sudo` activity
- 👀 Identifies abnormal CPU and memory usage
- ⚙️ Detects processes running from suspicious locations
- 🌐 Monitors active network connections
- 🚫 Detects connections to blacklisted IP addresses
- 🔍 Flags unusual listening ports
- 🛡️ Automatically blocks malicious IP addresses
- ⚡ Terminates suspicious processes
- 📧 Optional administrator notifications
- ⚙️ Configurable through `/etc/sentinelx.conf`
- 🧪 Safe **DRY_RUN** mode for testing
- 📝 Centralized logging and blocked IP persistence
- 🔒 Supports **iptables**, **nftables**, and **UFW**
- 🚦 Prevents multiple instances using `flock` or PID locking
- 🐧 Compatible with modern Linux distributions

---

## 📂 Project Structure

```text
SentinelX/
├── sentinelx.sh
├── sentinelx.conf
├── logs/
├── reports/
└── README.md
```

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/Kachinonye/sentinelx.git
```

Navigate into the project:

```bash
cd sentinelx
```

Make the script executable:

```bash
chmod +x sentinelx.sh
```

Copy the script:

```bash
sudo cp sentinelx.sh /usr/local/bin/
```

Create the configuration file:

```bash
sudo nano /etc/sentinelx.conf
```

Example configuration:

```bash
INTERVAL=60
CPU_THRESHOLD=70
MEM_THRESHOLD=70
DRY_RUN=true
USE_UFW=false
MAIL_TO="admin@example.com"
```

Create required directories:

```bash
sudo mkdir -p /var/log/sentinelx
sudo touch /var/log/sentinelx/sentinelx.log
sudo touch /etc/sentinelx.blocked_ips
```

---

## ▶️ Usage

Run SentinelX:

```bash
sudo ./sentinelx.sh
```

or

```bash
sudo sentinelx.sh
```

SentinelX continuously monitors your Linux system and automatically responds to suspicious activity according to the configured policy.

---

## ⚙️ Configuration

SentinelX supports configurable settings including:

- Monitoring interval
- CPU usage threshold
- Memory usage threshold
- DRY_RUN mode
- Firewall backend selection
- Email notifications
- Logging location

All configuration is managed through:

```text
/etc/sentinelx.conf
```

---

## 💼 Skills Demonstrated

This project showcases practical experience with:

- Linux System Administration
- Bash Shell Scripting
- Linux Security
- Intrusion Detection
- Incident Response
- Process Monitoring
- Network Monitoring
- SSH Security
- Firewall Management
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

- Web-based monitoring dashboard
- Email and Slack alerts
- HTML security reports
- JSON logging
- Threat intelligence integration
- Geo-IP blocking
- Multi-server monitoring
- Plugin architecture
- AI-assisted anomaly detection
- REST API

---

## 🏆 Project Highlights

SentinelX integrates several core Linux administration disciplines into a single solution:

- Authentication monitoring
- Process inspection
- Network security
- Firewall automation
- Threat detection
- Automated response
- Configuration management
- Audit logging

It represents a practical demonstration of Linux administration, Bash automation, and security engineering skills.

---

## 👨‍💻 Author

**Kachinonye Nmezi**

Linux Administrator | Bash Automation Specialist | AWS Cloud Learner

GitHub: https://github.com/Kachinonye

LinkedIn: https://www.linkedin.com/in/kachinonye-nmezi-74170723b/

---

## 📜 License

Licensed under the MIT License.
