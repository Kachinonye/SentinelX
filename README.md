# SentinelX — Adaptive Linux Intrusion Response

**Version:** 2025-10-14  
**Author:** Kachinonye Nmezi  
**Repo:** [https://github.com/Kachinonye/sentinelx](https://github.com/Kachinonye/sentinelx)

---

## Overview

SentinelX is an **advanced Linux intrusion detection and response tool** designed to monitor critical system events, processes, and network connections. It provides adaptive responses to potential threats while supporting a **DRY_RUN mode** for safe testing. 

---

## Features

- **Auth Log Monitoring:** Detects repeated SSH failures and suspicious sudo activity.
- **Process Inspection:** Identifies high CPU/memory usage and processes running from suspicious paths.
- **Network Watchdog:** Monitors connections to blacklisted IPs and unusual listening ports.
- **Automated Response:** Blocks IPs, kills malicious processes, and optionally sends alerts to the administrator.
- **Configurable & Safe:** Uses a configuration file `/etc/sentinelx.conf`. DRY_RUN mode allows testing without making changes.
- **Logging & Persistence:** Maintains logs in `/var/log/sentinelx/` and persists blocked IPs in `/etc/sentinelx.blocked_ips`.
- **Compatibility:** Works with iptables, nftables, and UFW. Detects available tools automatically.
- **Single Instance Enforcement:** Ensures only one instance runs at a time using `flock` or PID locking.

---

## Installation

```bash
# Create project directory (optional)
mkdir -p ~/sentinelx && cd ~/sentinelx

# Copy the script
sudo cp sentinelx.sh /usr/local/bin/sentinelx.sh
sudo chmod +x /usr/local/bin/sentinelx.sh

# Create configuration
sudo nano /etc/sentinelx.conf

# Example config:
# INTERVAL=60
# CPU_THRESHOLD=70
# MEM_THRESHOLD=70
# DRY_RUN=true
# USE_UFW=false
# MAIL_TO="your-email@example.com"

# Ensure log directories and files exist
sudo mkdir -p /var/log/sentinelx
sudo touch /var/log/sentinelx/sentinelx.log
sudo chmod 600 /var/log/sentinelx/sentinelx.log
sudo touch /etc/sentinelx.blocked_ips
sudo chmod 600 /etc/sentinelx.blocked_ips

