#!/usr/bin/env bash
# sentinelx.sh — SentinelX Adaptive Linux Intrusion Response (Phase 1)
# Version: 2025-10-14
# Place: /usr/local/bin/sentinelx.sh
# Run as root (systemd will run it). Supports DRY_RUN mode in /etc/sentinelx.conf

set -o pipefail
shopt -s nullglob

###########################
# Configuration & Defaults
###########################
CONF_FILE="/etc/sentinelx.conf"
LOG_DIR="/var/log/sentinelx"
LOG_FILE="$LOG_DIR/sentinelx.log"
PID_FILE="/var/run/sentinelx.pid"
LOCK_FILE="/var/lock/sentinelx.lock"
WHITELIST_BINARIES=("/usr/sbin/sshd" "/usr/sbin/cron" "/bin/bash" "/usr/bin/python3")
WHITELIST_USERS=("root" "syslog")
BLACKLISTED_IPS_FILE="/etc/sentinelx.blocked_ips"
DEFAULT_INTERVAL=60     # seconds between cycles
CPU_THRESHOLD=80       # percent
MEM_THRESHOLD=80       # percent
SUSPICIOUS_PATHS=("/tmp" "/dev/shm" "/var/tmp")
DRY_RUN=true           # default, overridden by config file
USE_UFW=false          # attempt to use ufw if true, fall back to iptables
MAIL_TO=""             # admin email for alerts (optional)

# Tools detection
SS_CMD="$(command -v ss || true)"
IPTABLES_CMD="$(command -v iptables || true)"
NFT_CMD="$(command -v nft || true)"
UFW_CMD="$(command -v ufw || true)"
JOURNALCTL="$(command -v journalctl || true)"
PS_CMD="$(command -v ps || true)"
FLOCK_CMD="$(command -v flock || true)"
HOSTNAME="$(hostname -s)"
DATE_CMD="$(date +'%Y-%m-%d %H:%M:%S')"

###########################
# Helper Functions
###########################

log() {
  local level="$1"; shift
  local msg="$*"
  printf '%s [%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$level" "$msg" >> "$LOG_FILE"
}

ensure_dirs() {
  mkdir -p "$LOG_DIR"
  touch "$LOG_FILE"
  mkdir -p "$(dirname "$BLACKLISTED_IPS_FILE")"
  touch "$BLACKLISTED_IPS_FILE"
  chmod 700 "$LOG_DIR"
  chmod 600 "$LOG_FILE"
  chmod 600 "$BLACKLISTED_IPS_FILE"
}

load_config() {
  if [[ -r "$CONF_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONF_FILE"
    log INFO "Loaded config from $CONF_FILE"
  else
    log WARN "Config file $CONF_FILE not found or not readable. Using defaults (DRY_RUN=$DRY_RUN)."
  fi
  # enforce defaults if unset
  : "${INTERVAL:=$DEFAULT_INTERVAL}"
  : "${CPU_THRESHOLD:=$CPU_THRESHOLD}"
  : "${MEM_THRESHOLD:=$MEM_THRESHOLD}"
  : "${DRY_RUN:=$DRY_RUN}"
}

is_whitelisted_binary() {
  local bin="$1"
  for w in "${WHITELIST_BINARIES[@]}"; do
    if [[ "$bin" == "$w" ]]; then
      return 0
    fi
  done
  return 1
}

is_whitelisted_user() {
  local user="$1"
  for u in "${WHITELIST_USERS[@]}"; do
    if [[ "$user" == "$u" ]]; then
      return 0
    fi
  done
  return 1
}

persist_blocked_ip() {
  local ip="$1"
  grep -Fxq "$ip" "$BLACKLISTED_IPS_FILE" || echo "$ip" >> "$BLACKLISTED_IPS_FILE"
}

already_blocked() {
  local ip="$1"
  grep -Fxq "$ip" "$BLACKLISTED_IPS_FILE"
}

block_ip() {
  local ip="$1"
  if already_blocked "$ip"; then
    log INFO "block_ip: $ip already blocked (skipping)"
    return 0
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    log ACTION "[DRY_RUN] Would block IP $ip"
    echo "[DRY_RUN] block $ip"
    return 0
  fi

  if [[ -n "$UFW_CMD" && "$USE_UFW" == "true" ]]; then
    $UFW_CMD insert 1 deny from "$ip" || log ERROR "ufw failed to block $ip"
  elif [[ -n "$IPTABLES_CMD" ]]; then
    $IPTABLES_CMD -I INPUT -s "$ip" -j DROP || log ERROR "iptables failed to block $ip"
  elif [[ -n "$NFT_CMD" ]]; then
    $NFT_CMD add table inet sentinelx 2>/dev/null || true
    $NFT_CMD add chain inet sentinelx input { type filter hook input priority 0\; } 2>/dev/null || true
    $NFT_CMD insert rule inet sentinelx input ip saddr "$ip" drop || log ERROR "nft failed to block $ip"
  else
    log ERROR "No firewall command found to block IP $ip"
    return 1
  fi
  persist_blocked_ip "$ip"
  log ACTION "Blocked IP $ip"
}

kill_process() {
  local pid="$1"
  local reason="$2"
  if [[ "$DRY_RUN" == "true" ]]; then
    log ACTION "[DRY_RUN] Would kill PID $pid (Reason: $reason)"
    return 0
  fi
  if kill -15 "$pid" 2>/dev/null; then
    log ACTION "Sent SIGTERM to PID $pid (Reason: $reason)"
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null && log ACTION "Sent SIGKILL to PID $pid"
    fi
  else
    log ERROR "Failed to send SIGTERM to PID $pid"
  fi
}

alert_admin() {
  local subject="$1"
  local body="$2"
  log ALERT "$subject -- $body"
  if [[ -n "$MAIL_TO" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      log ACTION "[DRY_RUN] Would email $MAIL_TO: $subject"
    else
      if command -v mailx >/dev/null 2>&1; then
        printf '%s\n' "$body" | mailx -s "$subject" "$MAIL_TO"
      else
        printf '%s\n' "$body" | /usr/sbin/sendmail -t "$MAIL_TO" 2>/dev/null || log WARN "No mailer found to send alert"
      fi
    fi
  fi
}

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    log FATAL "SentinelX must run as root. Exiting."
    echo "ERROR: SentinelX must run as root." >&2
    exit 1
  fi
}

###########################
# Detection Engines
###########################

scan_auth_logs() {
  local lookback_minutes=10
  local cutoff
  cutoff=$(date -d "-${lookback_minutes} minutes" +%s)
  local findings=()

  if [[ -n "$JOURNALCTL" ]]; then
    mapfile -t ssh_fails < <($JOURNALCTL -u ssh -S "-${lookback_minutes}m" 2>/dev/null | grep -i "failed password" || true)
    mapfile -t sudo_fails < <($JOURNALCTL _COMM=sudo -S "-${lookback_minutes}m" 2>/dev/null | grep -i "authentication failure" || true)
  else
    if [[ -r /var/log/auth.log ]]; then
      mapfile -t ssh_fails < <(grep -i "failed password" /var/log/auth.log || true)
      mapfile -t sudo_fails < <(grep -i "sudo:" /var/log/auth.log || true)
    fi
  fi

  for line in "${ssh_fails[@]}"; do
    if [[ "$line" =~ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
      ip="${BASH_REMATCH[1]}"
      if ! already_blocked "$ip"; then
        findings+=("ssh_failed:$ip:$line")
      fi
    fi
  done

  for line in "${sudo_fails[@]}"; do
    findings+=("sudo_event::$line")
  done

  for f in "${findings[@]}"; do
    IFS=":" read -r type ip raw <<<"$f"
    if [[ "$type" == "ssh_failed" && -n "$ip" ]]; then
      log WARN "Detected SSH failure from $ip"
      block_ip "$ip"
      alert_admin "SentinelX: Blocked SSH brute from $ip on $HOSTNAME" "Log: $raw"
    elif [[ "$type" == "sudo_event" ]]; then
      log WARN "Sudo event: $raw"
      alert_admin "SentinelX: sudo suspicious on $HOSTNAME" "$raw"
    fi
  done
}

scan_processes() {
  local findings=()
  while IFS= read -r line; do
    pid=$(echo "$line" | awk '{print $1}')
    user=$(echo "$line" | awk '{print $2}')
    pcpu=$(echo "$line" | awk '{print $3}')
    pmem=$(echo "$line" | awk '{print $4}')
    cmd=$(echo "$line" | awk '{for(i=8;i<=NF;i++) printf $i " "; print ""}')

    if is_whitelisted_user "$user"; then
      continue
    fi

    pcpu_int=${pcpu%.*}
    pmem_int=${pmem%.*}
    if [[ -n "$pcpu_int" && "$pcpu_int" -ge "$CPU_THRESHOLD" ]]; then
      findings+=("high_cpu:$pid:$user:$pcpu:$cmd")
    fi
    if [[ -n "$pmem_int" && "$pmem_int" -ge "$MEM_THRESHOLD" ]]; then
      findings+=("high_mem:$pid:$pid:$user:$pmem:$cmd")
    fi

    exe_path="$(readlink -f /proc/$pid/exe 2>/dev/null || echo '')"
    for sp in "${SUSPICIOUS_PATHS[@]}"; do
      if [[ -n "$exe_path" && "$exe_path" == "$sp"* && ! is_whitelisted_binary "$exe_path" ]]; then
        findings+=("susp_path:$pid:$user:$exe_path:$cmd")
      fi
    done
  done < <($PS_CMD -eo pid,user,pcpu,pmem,cmd --no-headers 2>/dev/null | grep -v "^$" || true)

  for f in "${findings[@]}"; do
    IFS=":" read -r ftype pid user a b c <<<"$f"
    case "$ftype" in
      high_cpu)
        log WARN "PID $pid by $user high CPU ($a%). Cmd: $b"
        kill_process "$pid" "High CPU ($a%)"
        alert_admin "SentinelX: killed PID $pid high CPU on $HOSTNAME" "PID $pid user $user $a% cmd: $b"
        ;;
      high_mem)
        log WARN "PID $pid by $user high MEM ($a%). Cmd: $b"
        kill_process "$pid" "High MEM ($a%)"
        alert_admin "SentinelX: killed PID $pid high memory on $HOSTNAME" "PID $pid user $user $a% cmd: $b"
        ;;
      susp_path)
        log WARN "PID $pid suspicious path $a (cmd: $b)"
        kill_process "$pid" "Suspicious path $a"
        alert_admin "SentinelX: killed PID $pid suspicious path on $HOSTNAME" "PID $pid user $user path $a cmd: $b"
        ;;
    esac
  done
}

scan_network() {
  local static_blacklist="/etc/sentinelx.blacklist"
  if [[ -r "$static_blacklist" ]]; then
    while IFS= read -r ip; do
      if [[ -n "$ip" && ! "$ip" =~ ^# ]]; then
        if [[ -n "$SS_CMD" ]]; then
          if $SS_CMD -tunpH 2>/dev/null | grep -q "$ip"; then
            log WARN "Connection to blacklisted IP $ip detected"
            block_ip "$ip"
            alert_admin "SentinelX: blocked static-blacklist IP $ip on $HOSTNAME" "Connection detected"
          fi
        fi
      fi
    done < "$static_blacklist"
  fi

  if [[ -n "$SS_CMD" ]]; then
    while IFS= read -r line; do
      if [[ "$line" =~ :([0-9]{2,5})\s ]]; then
        lport="${BASH_REMATCH[1]}"
        if [[ "$lport" != "22" && "$lport" != "80" && "$lport" != "443" && "$lport" != "3306" && "$lport" != "5432" ]]; then
          log WARN "Unusual listening port $lport: $line"
          alert_admin "SentinelX: unusual port $lport on $HOSTNAME" "$line"
        fi
      fi
    done < <($SS_CMD -ltnpH 2>/dev/null || true)
  fi
}

###########################
# Main Loop / Bootstrap
###########################

main() {
  require_root
  ensure_dirs
  load_config

  if [[ -n "$FLOCK_CMD" ]]; then
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
      log WARN "Another SentinelX instance running. Exiting."
      exit 0
    fi
  else
    if [[ -f "$PID_FILE" ]]; then
      pid_existing=$(cat "$PID_FILE" 2>/dev/null || true)
      if [[ -n "$pid_existing" && -d "/proc/$pid_existing" ]]; then
        log WARN "Another instance (PID $pid_existing) running. Exiting."
        exit 0
      fi
    fi
    echo $$ > "$PID_FILE"
  fi

  log INFO "SentinelX started (DRY_RUN=$DRY_RUN) interval=${INTERVAL}s on $HOSTNAME"
  trap 'log INFO "SentinelX exiting"; rm -f "$PID_FILE"; exit 0' SIGTERM SIGINT

  while true; do
    scan_auth_logs
    scan_processes
    scan_network

    local max_bytes=10485760
    if [[ -f "$LOG_FILE" ]]; then
      local size
      size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
      if (( size > max_bytes )); then
        mv "$LOG_FILE" "$LOG_FILE.$(date +%s)"
        touch "$LOG_FILE"
        log INFO "Rotated log file"
      fi
    fi

    sleep "${INTERVAL}"
  done
}

main "$@"
