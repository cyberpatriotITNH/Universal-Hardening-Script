# 🛡️ BEAST Hardening Script — Master Log
**Script:** `~/checklist.ps1.sh`  
**Target VM:** `kitty@192.168.86.23` (Kali Linux)  
**Sessions:** 2026-04-25 → 2026-04-26

---

## 📦 ADDITIONS LOG — All Features Added

### Original 18 Steps (Pre-existing)
| Step | Feature |
|------|---------|
| 1 | User audit — nano-based authorized list, removes unauthorized accounts |
| 2 | Admin password audit via `passwd -S` |
| 3 | Full system upgrade (`apt-get dist-upgrade`) |
| 4 | Basic PAM / SSH hardening (PermitRootLogin no) |
| 5 | Firewall via UFW — default deny incoming, allow SSH |
| 6 | Fail2Ban install and enable |
| 7 | Background unattended system updates |
| 8 | Password policies via `chage` (max age, warn days) |
| 9 | Account lockout via `faillock` |
| 10 | Audit policy — auditd install, `auditctl -e 1` |
| 11 | MSCT security options (logged) |
| 12 | Disable unsafe services: rpcbind, cups, avahi-daemon |
| 13 | Mask rpcbind |
| 14 | Suspicious file scan — SUID binaries, hidden files, scripts in /tmp |
| 15 | Backup suspicious files to `~/cp-backups/<timestamp>/` |
| 16 | Service detection — Apache, MySQL, README keyword scan |
| 17 | Apache hardening (mod_security2, headers) + MySQL secure install |
| 18 | VirusTotal scan on suspicious files (optional API key) |

### Round 1 — Kernel + GRUB (2026-04-26)
| ID | Feature | Detail |
|----|---------|--------|
| R1-A | Kernel sysctl hardening | Writes `/etc/sysctl.d/99-beast-hardening.conf`. Params: `ip_forward=0`, `tcp_syncookies=1`, `icmp_echo_ignore_broadcasts=1`, `accept_source_route=0`, `accept_redirects=0`, `rp_filter=1`, `log_martians=1`, `randomize_va_space=2` (ASLR), `sysrq=0`, `dmesg_restrict=1`, `ptrace_scope=1`, `suid_dumpable=0` |
| R1-B | GRUB hardening | `GRUB_TIMEOUT=5`, disables recovery menu, `chmod 600 /boot/grub/grub.cfg`, runs `update-grub` |

### Round 2 — USB + Core Dumps + TCP Wrappers (2026-04-26)
| ID | Feature | Detail |
|----|---------|--------|
| R2-A | USB storage disabled | Writes `/etc/modprobe.d/beast-disable-usb.conf` with `install usb-storage /bin/true` + `blacklist usb-storage`. Unloads module if active. |
| R2-B | Core dumps disabled | `* hard core 0` + `* soft core 0` in `/etc/security/limits.conf`. Writes `/etc/systemd/coredump.conf.d/disable.conf` (`Storage=none`, `ProcessSizeMax=0`) |
| R2-C | TCP Wrappers | `hosts.deny: ALL: ALL` — deny all by default. `hosts.allow: sshd: ALL` — permit SSH. |

### Round 3 — Passwords + Auto-updates + Sudoers Audit (2026-04-26)
| ID | Feature | Detail |
|----|---------|--------|
| R3-A | Empty password detection | Reads `/etc/shadow`, locks any account with blank password via `passwd -l`. Reports `[OK]` if none found. |
| R3-B | Unattended upgrades | Installs `unattended-upgrades`, writes `/etc/apt/apt.conf.d/20auto-upgrades` (update daily, upgrade daily, autoclean weekly), enables service. |
| R3-C | Sudoers NOPASSWD audit | Greps all of `/etc/sudoers` and `/etc/sudoers.d/` for NOPASSWD entries, logs each as `[ALERT]` to forensics log. |

### Round 4 — Port Audit + ClamAV + IPv6 (2026-04-26)
| ID | Feature | Detail |
|----|---------|--------|
| R4-A | Listening port audit | Runs `ss -tlnp`, logs full table to forensics. Flags any non-SSH listening port as `[ALERT] Unexpected listening port`. |
| R4-B | ClamAV antivirus | Auto-installs `clamav` + `clamav-daemon` if missing. Stops `clamav-freshclam`, runs `freshclam` for sig update. Scans `/tmp` and `/home` recursively, logs infected files. |
| R4-C | IPv6 disable | Appends `net.ipv6.conf.all.disable_ipv6=1` and `net.ipv6.conf.default.disable_ipv6=1` to sysctl hardening conf and applies immediately. |

### Round 5 — Full SSH + Banners + Cron Audit (2026-04-26)
| ID | Feature | Detail |
|----|---------|--------|
| R5-A | Full SSH hardening | Applies 13 sshd_config directives: `PermitRootLogin no`, `PermitEmptyPasswords no`, `X11Forwarding no`, `MaxAuthTries 3`, `LoginGraceTime 30`, `AllowTcpForwarding no`, `ClientAliveInterval 300`, `ClientAliveCountMax 2`, `UsePAM yes`, `PrintLastLog yes`, `IgnoreRhosts yes`, `HostbasedAuthentication no`, `PasswordAuthentication yes`. Auto-detects `ssh` vs `sshd` service name. |
| R5-B | Login banners | Writes warning banner to `/etc/issue`, `/etc/issue.net`, `/etc/motd`. Adds `Banner /etc/issue.net` to sshd_config. |
| R5-C | Cron audit | Scans all cron directories (`cron.d`, `cron.daily`, `cron.hourly`, `cron.weekly`, `cron.monthly`, `cron.monthly`, `/var/spool/cron/crontabs`). Logs only actual schedule lines (starting with digit/`*`/`@`) to forensics log. |

---

## 🐛 BUG LOG — All Bugs Found & Fixed

| # | Session | Location | Bug Description | Fix Applied |
|---|---------|----------|-----------------|-------------|
| B-01 | Pre | Line ~360 (PS block) | PowerShell heredoc in bare `"..."` double-quoted string — PS backticks caused `unexpected EOF` at runtime | Changed to `<<'PSEOF'` single-quoted heredoc to prevent bash variable expansion |
| B-02 | Pre | Line ~639 (Step 17) | Semicolon after `$APACHE_FOUND && a2enmod...` made `systemctl restart apache2` run unconditionally even when Apache not found | Wrapped entire block in `if [[ "$APACHE_FOUND" == true ]]; then ... fi` |
| B-03 | Pre | Line ~447 (Step 1) | `nano` call blocks all non-interactive / CI runs — no TTY = instant silent exit, leaving auth list empty | Replaced with pre-filled heredoc for testing; restored `nano` to line 447 for production |
| B-04 | Pre | Line ~536 (Step 5) | `sudo ufw enable` hangs indefinitely waiting for `y/n` confirmation prompt | Changed to `echo "y" \| sudo ufw enable` |
| B-05 | Pre | Line ~543 (Step 6) | `systemctl enable fail2ban` fails with unit not found — package not installed on fresh Kali | Added `dpkg -s fail2ban &>/dev/null \|\| sudo apt-get install -y fail2ban` before enable |
| B-06 | Pre | Step 10 | `auditctl -e 1` fails — auditd not installed, command not found | Added auto-install + `systemctl enable --now auditd` before `auditctl` call |
| B-07 | Pre | Step 17 | `a2enmod security2` fails — `libapache2-mod-security2` package not installed | Added `dpkg -s libapache2-mod-security2 &>/dev/null \|\| sudo apt-get install -y ...` |
| B-08 | R3 | Step 14 (hidden file scan) | Suspicious file scan recursively hit `~/cp-backups/` and `~/cp-logs/` on every run, flagging the script's own backup files as suspicious — self-contaminating logs | Added `[[ "$f" == *"/cp-backups/"* ]] && continue` and same for `/cp-logs/` |
| B-09 | R3 | Step 1 (user audit) | When run via `sudo bash`, `$USER` resolves to `root` — legitimate user (e.g. `kitty`) was flagged as `[ALERT] Unauthorized user` | Changed to `INVOKING_USER=${SUDO_USER:-$USER}` and used that for all user comparisons |
| B-10 | R5 | R5-A (SSH hardening) | `Protocol 2` directive in SSH settings caused `sshd reload` to fail — `Protocol` was removed from OpenSSH 7.0+ as only SSH-2 is supported | Removed `Protocol 2` entry from the SSH settings associative array entirely |
| B-11 | R5 | R5-C (cron audit) | Cron audit grepped all non-comment lines from cron files, dumping entire shell script bodies (hundreds of lines of functions, if-blocks, etc.) into the forensics log | Restricted grep with `grep -E "^[0-9*@]"` to only capture actual schedule time expressions |
| B-12 | R5 (scan 2) | R5-A (SSH hardening) | `systemctl reload sshd` fails on Kali/Debian where the SSH service is named `ssh` not `sshd` — unit not found error | Added service name detection: `systemctl list-units \| grep -q sshd.service && SSH_SVC=sshd \|\| SSH_SVC=ssh` |

---

## 🔍 SCAN RESULTS — Live VM Findings (2026-04-26 Run)

### Security Alerts Triggered
| Alert | Detail | Severity |
|-------|--------|----------|
| Unauthorized user `haxor` | Account detected and removed | 🔴 HIGH |
| NOPASSWD: `kitty-nopasswd` | `kitty ALL=(ALL) NOPASSWD:ALL` in sudoers.d | 🔴 HIGH |
| NOPASSWD: `kali-grant-root` | `%kali-trusted ALL=(ALL:ALL) NOPASSWD:ALL` | 🔴 HIGH |
| NOPASSWD: `ospd-openvas` | `_gvm NOPASSWD: /usr/sbin/openvas` | 🟡 MEDIUM |
| Port `*:80` open | Apache2 listening on all interfaces | 🟡 MEDIUM |
| `/tmp/evil.sh` | Reverse shell script (`nc -e /bin/bash`) | 🔴 HIGH |
| `/tmp/backdoor.py` | Python socket backdoor | 🔴 HIGH |
| `/tmp/scanner.pl` | Perl network scanner | 🟡 MEDIUM |
| SUID binaries (34 found) | Includes `pkexec`, `sudo`, `rsh`, kismet capture tools | 🟡 INFO |
| Hidden files in `/etc/skel` | `.bashrc`, `.zshrc`, `.profile` etc — system defaults | 🟢 INFO |
| Hidden files in `/home/kitty/.mozilla` | Firefox storage metadata files | 🟢 INFO |

### Hardening Confirmed Applied
| Check | Result |
|-------|--------|
| Kernel sysctl (`99-beast-hardening.conf`) | ✅ Applied |
| GRUB timeout=5, grub.cfg 600 | ✅ Applied |
| USB storage blacklisted | ✅ Applied |
| Core dumps disabled | ✅ Applied |
| TCP wrappers | ✅ Applied |
| No empty passwords | ✅ Confirmed |
| Unattended upgrades | ✅ Enabled |
| UFW firewall | ✅ Active |
| Fail2Ban | ✅ Active |
| Auditd | ✅ Active, auditctl enabled |
| IPv6 disabled | ✅ Applied via sysctl |
| SSH hardened (12 directives) | ✅ Applied |
| Login banners | ✅ Set on issue/issue.net/motd |
| rpcbind / cups / avahi disabled | ✅ Inactive |
| Cron audit | ✅ 5 cron entries logged to forensics |

### Cron Entries Found on VM
| Schedule | Owner | Command |
|----------|-------|---------|
| `09,39 * * * *` | root | `/usr/lib/php/sessionclean` |
| `30 3 * * 0` | root | `e2scrub_all_cron` |
| `10 3 * * *` | root | `e2scrub_all -A -r` |
| `5-55/10 * * * *` | root | `debian-sa1 1 1` (sysstat) |
| `59 23 * * *` | root | `debian-sa1 60 2` (sysstat) |

---

## 📊 SCRIPT STATS

| Metric | Value |
|--------|-------|
| Total lines | 995 |
| Original steps | 18 |
| New steps added | 15 (R1-A through R5-C) |
| Total steps | 33 |
| Bugs fixed | 12 (B-01 → B-12) |
| Rounds completed | 5 of 10 |
| Rounds remaining | 6–10 (pending) |

---

*Last updated: 2026-04-26 — Rounds 6–10 pending VM availability*
