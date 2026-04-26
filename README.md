# 🛡️ BEAST Universal Hardening Script
**`checklist.ps1.sh`** — Bash/PowerShell polyglot system hardening script for Debian/Kali Linux.  
Runs 30+ hardening checks across security, networking, kernel, and forensics domains.

---

## 🚀 Quick Start
```bash
chmod +x checklist.ps1.sh
sudo bash checklist.ps1.sh          # Full run (interactive)
sudo bash checklist.ps1.sh --dry-run  # Preview only
```

---

## 📋 What It Does

### Original 18 Steps
| Step | Action |
|------|--------|
| 1 | **User audit** — interactive authorized user list (nano), removes unauthorized accounts |
| 2 | **Admin password audit** — checks for expired/missing passwords |
| 3 | **Full system upgrade** — `apt-get dist-upgrade` |
| 4 | **PAM / SSH hardening** — PermitRootLogin no, basic SSH lockdown |
| 5 | **Firewall (UFW)** — default deny incoming, allow SSH, auto-installs ufw |
| 6 | **Fail2Ban** — installs and enables |
| 7 | **Unattended background updates** — `apt-get -y upgrade` scheduled |
| 8 | **Password policies** — `chage` max age, warn days |
| 9 | **Account lockout** — `faillock` reset, pam_faillock configured |
| 10 | **Audit policy** — installs auditd, enables and starts it, `auditctl -e 1` |
| 11 | **MSCT Security Options** — baseline security settings logged |
| 12 | **Disable unsafe services** — rpcbind, cups, avahi-daemon |
| 13 | **Mask unnecessary features** — rpcbind masked |
| 14 | **Suspicious file scan** — hidden files, SUID binaries, scripts in /tmp |
| 15 | **Backup suspicious files** — copies to `~/cp-backups/<timestamp>/` |
| 16 | **Service detection** — Apache, MySQL, README keyword scan |
| 17 | **Apache / MySQL hardening** — mod_security2, headers, secure_installation |
| 18 | **VirusTotal scan** — optional API key, scans suspicious files |

### 🆕 Added: Rounds 1–5 (Session 2026-04-26)

| ID | Feature | What it does |
|----|---------|-------------|
| R1-A | **Kernel sysctl hardening** | Writes `/etc/sysctl.d/99-beast-hardening.conf` — disables IP forwarding, enables SYN cookies, ASLR=2, rp_filter, disables ICMP redirects, logs martians, restricts dmesg + ptrace, disables suid coredumps |
| R1-B | **GRUB hardening** | Sets timeout=5, disables recovery menu, chmod 600 on grub.cfg |
| R2-A | **USB storage disabled** | Blacklists `usb-storage` via `/etc/modprobe.d/beast-disable-usb.conf` |
| R2-B | **Core dumps disabled** | `/etc/security/limits.conf` + systemd `coredump.conf.d/disable.conf` |
| R2-C | **TCP Wrappers** | `hosts.deny: ALL: ALL` / `hosts.allow: sshd: ALL` |
| R3-A | **Empty password check** | Scans `/etc/shadow`, locks any account with blank password |
| R3-B | **Unattended upgrades** | Installs & configures `unattended-upgrades` for auto security patches |
| R3-C | **Sudoers NOPASSWD audit** | Finds and alerts on all NOPASSWD sudo entries |
| R4-A | **Listening port audit** | `ss -tlnp` scan, flags anything unexpected beyond SSH |
| R4-B | **ClamAV antivirus** | Installs clamav, updates signatures, scans `/tmp` and `/home` |
| R4-C | **IPv6 disabled** | Via sysctl `net.ipv6.conf.all.disable_ipv6=1` |
| R5-A | **Full SSH hardening** | MaxAuthTries=3, LoginGraceTime=30, no X11/TCPForwarding, ClientAlive timers, no empty passwords, no rhosts/hostbased auth |
| R5-B | **Login banners** | Sets `/etc/issue`, `/etc/issue.net`, `/etc/motd` + SSH Banner directive |
| R5-C | **Cron audit** | Inventories all cron.d / cron.daily / cron.weekly entries to forensics log |

---

## 🐛 Bugs Fixed (All Sessions)

| # | Bug | Fix |
|---|-----|-----|
| B-1 | PowerShell heredoc caused `unexpected EOF` (backtick in double-quoted string) | Changed to `<<'PSEOF'` single-quoted heredoc |
| B-2 | `systemctl restart apache2` ran unconditionally (semicolon logic error) | Wrapped in `if [[ "$APACHE_FOUND" == true ]]` |
| B-3 | `nano` blocked non-interactive test runs | Replaced with heredoc for CI; restored for production |
| B-4 | `sudo ufw enable` hung waiting for y/n | `echo "y" \| sudo ufw enable` |
| B-5 | `fail2ban` enable failed — package not installed | Auto-installs before enabling |
| B-6 | `auditctl -e 1` failed — auditd not installed | Auto-installs + starts service |
| B-7 | `a2enmod security2` failed — libapache2-mod-security2 missing | Auto-installs package |
| B-8 | Suspicious file scan flagged own `~/cp-backups/` dir on every run | Added path filter to exclude backup/log dirs |
| B-9 | Running via `sudo` caused `$USER=root`, flagging legitimate user as unauthorized | Switched to `INVOKING_USER=${SUDO_USER:-$USER}` |
| B-10 | `Protocol 2` in SSH config caused `sshd reload` failure (removed in OpenSSH 7+) | Removed `Protocol 2` directive |
| B-11 | Cron audit dumped entire shell script bodies into log | Restricted grep to lines starting with `[0-9*@]` |

---

## 📁 Log Files
All runs write to `~/cp-logs/`:
- `hardening_<timestamp>.log` — full step-by-step output
- `errors_<timestamp>.log` — warnings and errors
- `forensics_<timestamp>.log` — security findings, detections, alerts

Backups of modified configs written to `~/cp-backups/<timestamp>/`.

---

## ⚠️ Notes
- Designed for **Kali / Debian-based** systems
- Requires `sudo` (NOPASSWD recommended for CI, remove after)
- Step 1 opens `nano` interactively — run with a TTY for full use
- VirusTotal (Step 18) requires a free API key at [virustotal.com](https://virustotal.com)
