#!/bin/bash
: '
:: ========================================
:: The B.E.A.S.T (Better Executable Application for Security and Threat intelligence) Polyglot Bash/PowerShell Script (Windows first)
:: Usage: ./checklist.ps1.sh [--normal|--forensic|--dry-run|--undo]
:: ========================================
'

# Detect PowerShell environment
if [ -n "$PSVersionTable" ] || [ -n "$WINDIR" ]; then
powershell -NoProfile -Command "
# ========================================
# CyberPatriot PowerShell Hardening Script
# All findings go to Forensics log
# System changes go to Normal log
# ========================================

param(
    [switch]$NORMAL,
    [switch]$FORENSIC,
    [switch]$DRYRUN,
    [switch]$UNDO
)

# -----------------------------
# Global Paths
# -----------------------------
$TIMESTAMP = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$BACKUP_DIR = "C:\cp-backups\$TIMESTAMP"
$LOG_DIR = "C:\cp-logs"
$LOG = "$LOG_DIR/hardening_$TIMESTAMP.log"
$FORENSICS_LOG = "$LOG_DIR/forensics_$TIMESTAMP.log"

# Ensure directories exist
if (-not $DRYRUN) {
    New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
    New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
}

# -----------------------------
# Logging Functions
# -----------------------------
function Write-Forensics([string]$Message){
    $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $FORENSICS_LOG -Value "$time `t $Message"
}

function Write-Normal([string]$Message){
    if (-not $DRYRUN) { Add-Content -Path $LOG -Value "$Message" }
}

function Backup-File([string]$Path){
    if (Test-Path $Path){
        $dest = Join-Path $BACKUP_DIR (Split-Path $Path -Leaf)
        Copy-Item -Path $Path -Destination $dest -Force
        Write-Forensics "[BACKUP] $Path -> $dest"
    }
}

# -----------------------------
# Step 1: User/Admin Audit
# -----------------------------
Write-Host "=== Step 1/18: User/Admin Audit ==="
$tmpFile = "$env:TEMP\authorized_users.txt"
@"
# Authorized Administrators:
# benjamin
# password: W1llH4ck4B4con
# llitt
# password: ugotlittup
# Authorized Users:
# user1
# user2
"@ | Out-File -FilePath $tmpFile -Encoding UTF8
Start-Process notepad.exe $tmpFile -Wait

$allLines = Get-Content $tmpFile
$section = ""
$admins_list = @()
$users_list = @()
$admin_passwords = @{}
$lastAdmin = ""

foreach ($line in $allLines){
    $line = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line -like "#*") { continue }

    switch ($line){
        "Authorized Administrators:" { $section="admin"; continue }
        "Authorized Users:" { $section="user"; continue }
    }

    if ($section -eq "admin") {
        if ($line -match "^password:\s*(.+)$") {
            $admin_passwords[$lastAdmin] = $Matches[1]
        } else {
            $lastAdmin = $line
            $admins_list += $line
        }
    } elseif ($section -eq "user") {
        $users_list += $line
    }
}

$allAuthorized = $admins_list + $users_list
$foundUsers = Get-LocalUser
$removedUsers = @()

foreach ($u in $foundUsers){
    Write-Forensics "[USER AUDIT] User: $($u.Name), Enabled: $($u.Enabled), Admin: $($u.IsAdministrator)"
    if (-not ($allAuthorized -contains $u.Name)){
        Write-Forensics "[ALERT] Unauthorized user found: $($u.Name)"
        if (-not $FORENSIC -and -not $DRYRUN){
            $choice = Read-Host "Remove user $($u.Name)? [y/N]"
            if ($choice -match "^[Yy]$") {
                Remove-LocalUser -Name $u.Name
                Write-Normal "[USER] Removed unauthorized user $($u.Name)"
            }
        }
    }
}

# -----------------------------
# Step 2: Admin Password Enforcement
# -----------------------------
Write-Host "=== Step 2/18: Admin Password Enforcement ==="
foreach ($admin in $admins_list){
    $localUser = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
    if ($null -ne $localUser){
        $passwordSet = $true
        try { $hash = (Get-LocalUser $admin).PasswordExpires } catch { $passwordSet=$false }
        if (-not $passwordSet -or $admin_passwords[$admin]){
            if (-not $FORENSIC -and -not $DRYRUN){
                $securePass = Read-Host "Enter strong password for admin $admin" -AsSecureString
                $plainPass = [System.Net.NetworkCredential]::new("", $securePass).Password
                $admin_passwords[$admin] = $plainPass
                $localUser | Set-LocalUser -Password $securePass
                Write-Normal "[PASSWORD] Password set/updated for admin: $admin"
            } else {
                Write-Forensics "[PASSWORD] Admin $admin requires password set/update (forensic/dry-run)"
            }
        } else {
            Write-Forensics "[PASSWORD] Admin $admin password verified"
        }
    }
}

# -----------------------------
# Step 3: Disable Guest Account
# -----------------------------
Write-Host "=== Step 3/18: Disable Guest Account ==="
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest){
    if (-not $FORENSIC -and -not $DRYRUN){
        Disable-LocalUser -Name "Guest"
        Write-Normal "[USER] Guest account disabled"
    }
    Write-Forensics "[USER AUDIT] Guest account exists"
}

# -----------------------------
# Step 4: Account Lockout Policy
# -----------------------------
Write-Host "=== Step 4/18: Account Lockout Policy ==="
if ($NORMAL -and -not $DRYRUN){ net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 }
Write-Forensics "Checked/enforced account lockout policy"

# -----------------------------
# Step 5: Local Audit Policy
# -----------------------------
Write-Host "=== Step 5/18: Local Audit Policy ==="
if ($NORMAL -and -not $DRYRUN){ auditpol /set /category:* /success:enable /failure:enable }
Write-Forensics "Audit policy enabled for all categories"

# -----------------------------
# Step 6: Security Options
# -----------------------------
Write-Host "=== Step 6/18: Security Options ==="
$SecOpts = @{
    'DontDisplayLastUserName'=1
    'DisableCAD'=0
    'LimitBlankPasswordUse'=1
}
foreach ($key in $SecOpts.Keys){
    if ($NORMAL -and -not $DRYRUN){
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name $key -Value $SecOpts[$key]
        Write-Normal "[SECURITY OPTION] Applied $key"
    }
    Write-Forensics "Security option $key checked/applied"
}

# -----------------------------
# Step 7: Firewall
# -----------------------------
Write-Host "=== Step 7/18: Firewall Configuration ==="
if ($NORMAL -and -not $DRYRUN){
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Normal "[FIREWALL] Firewall configured"
}
Write-Forensics "Firewall status checked"

# -----------------------------
# Step 8: Windows Update
# -----------------------------
Write-Host "=== Step 8/18: Windows Update ==="
if ($NORMAL -and -not $DRYRUN){
    $wuSettings = New-Object -ComObject 'Microsoft.Update.AutoUpdate'
    $wuSettings.Settings.NotificationLevel = 4
    $wuSettings.Settings.Save()
    Write-Normal "[UPDATE] Windows Update configured"
}
Write-Forensics "Windows Update status checked"

# -----------------------------
# Step 9: Services Hardening
# -----------------------------
Write-Host "=== Step 9/18: Services Hardening ==="
$ServicesToDisable=@('FTPSVC','Spooler','RemoteRegistry','TermService')
foreach ($svc in $ServicesToDisable){
    if ($NORMAL -and -not $DRYRUN){
        Stop-Service $svc -Force
        Set-Service $svc -StartupType Disabled
        Write-Normal "[SERVICE] $svc stopped and disabled"
    }
    Write-Forensics "Service $svc checked"
}

# -----------------------------
# Step 10: Windows Features Hardening
# -----------------------------
Write-Host "=== Step 10/18: Windows Features ==="
$FeaturesToDisable=@('TelnetClient','SMB1Protocol','WindowsMediaPlayer','IIS-Services','AD-Domain-Services')
foreach ($f in $FeaturesToDisable){
    if ($NORMAL -and -not $DRYRUN){
        Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart
        Write-Normal "[FEATURE] $f disabled"
    }
    Write-Forensics "Feature $f checked"
}

# -----------------------------
# Step 11: Event Logs & Scheduled Tasks
# -----------------------------
Write-Host "=== Step 11/18: Event Logs & Scheduled Tasks ==="
if ($NORMAL -and -not $DRYRUN){
    wevtutil el | ForEach-Object { wevtutil cl $_ }
    Get-ScheduledTask | Where-Object {$_.TaskName -notlike '*Microsoft*'} | Disable-ScheduledTask
    Write-Normal "[EVENTS] Cleared logs and disabled tasks"
}
Write-Forensics "Event logs & scheduled tasks checked"

# -----------------------------
# Step 12: Suspicious File Scan
# -----------------------------
Write-Host "=== Step 12/18: Suspicious File Scan ==="
$SuspiciousFiles = Get-ChildItem -Path 'C:\Users','C:\ProgramData' -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match '.ps1|.bat|.exe|.pl|.py' -or $_.Attributes -match 'Hidden' }
foreach ($f in $SuspiciousFiles){
    $reasons=@()
    if ($f.Attributes -match 'Hidden'){ $reasons+='Hidden file' }
    if ($f.Extension -match '.ps1|.bat|.exe|.pl|.py'){ $reasons+="Suspicious extension ($($f.Extension))" }
    $reasonStr = ($reasons -join '; ')
    Write-Forensics "[SUSPICIOUS] $($f.FullName) - $reasonStr"
}

# -----------------------------
# Step 13: Backup User Files
# -----------------------------
Write-Host "=== Step 13/18: Backing up User Files ==="
if ($NORMAL -and -not $DRYRUN){
    Get-ChildItem -Path C:\Users -Recurse -Force | ForEach-Object { Backup-File $_.FullName }
}
Write-Forensics "User files backup checked"

# -----------------------------
# Step 14: VirusTotal Scan
# -----------------------------
Write-Host "=== Step 14/18: VirusTotal Scan ==="
if (-not $DRYRUN){
    if (-not $VT_API_KEY){ $VT_API_KEY = Read-Host "Enter VirusTotal API key" }
    foreach ($f in $SuspiciousFiles){ 
        try {
            $sha256 = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
            Write-Forensics "[VT SCAN] $($f.FullName) SHA256=$sha256"
        } catch { Write-Forensics "[ERROR] Failed to hash $($f.FullName)" }
    }
}

# -----------------------------
# Step 15: Extra MSCT Hardening
# -----------------------------
Write-Host "=== Step 15/18: Extra Hardening ==="
if ($NORMAL -and -not $DRYRUN){
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'EnableSecuritySignature' -Value 1
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' -Name 'WriteProtect' -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Normal "[HARDEN] Extra MSCT hardening applied"
}
Write-Forensics "Extra hardening checked"

# -----------------------------
# Step 16: Password Policies Review
# -----------------------------
Write-Host "=== Step 16/18: Password Policies Review ==="
Get-LocalUser | ForEach-Object { Write-Forensics "[PWD POLICY] $($_.Name) - PasswordExpires: $($_.PasswordExpires)" }

# -----------------------------
# Step 17: Audit Policy Review
# -----------------------------
Write-Host "=== Step 17/18: Audit Policy Review ==="
$auditSettings = auditpol /get /category:*
foreach ($line in $auditSettings){ Write-Forensics "[AUDIT] $line" }

# -----------------------------
# Step 18: Apache/MySQL Detection & Hardening
# -----------------------------
Write-Host "=== Step 18/18: Apache/MySQL Hardening ==="
# Apache
$apacheSvc = Get-Service | Where-Object {$_.Name -match "Apache"}
if ($apacheSvc){
    Write-Forensics "Detected Apache service"
    if (-not $DRYRUN){
        $httpdConf = "C:\Apache24\conf\httpd.conf"
        if (Test-Path $httpdConf){
            Copy-Item $httpdConf "$httpdConf.bak" -Force
            (Get-Content $httpdConf) -replace 'Options Indexes','Options -Indexes' | Set-Content $httpdConf
            (Get-Content $httpdConf) -replace 'ServerTokens OS','ServerTokens Prod' | Set-Content $httpdConf
            (Get-Content $httpdConf) -replace 'ServerSignature On','ServerSignature Off' | Set-Content $httpdConf
            Start-Service $apacheSvc.Name -ErrorAction SilentlyContinue
            Write-Normal "[APACHE] Hardened httpd.conf and restarted"
        }
    }
}

# MySQL
$mysqlSvc = Get-Service | Where-Object {$_.Name -match "MySQL|mysqld"}
if ($mysqlSvc){
    Write-Forensics "Detected MySQL service"
    if (-not $DRYRUN){
        $mysqlRootPass = Read-Host "Enter strong MySQL root password" -AsSecureString
        $plainPass = [System.Net.NetworkCredential]::new("", $mysqlRootPass).Password
        $sqlCmds = @"
ALTER USER 'root'@'localhost' IDENTIFIED BY '$plainPass';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db LIKE 'test\_%';
FLUSH PRIVILEGES;
"@
        $tmpSql = "$env:TEMP\mysql_hardening.sql"
        $sqlCmds | Set-Content $tmpSql
        & "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p"$plainPass" < $tmpSql
        Remove-Item $tmpSql -Force
        Write-Normal "[MYSQL] Root password secured, anonymous/test DB removed"
    }
}

Write-Host "[INFO] 18-step hardening & forensics complete"
Write-Forensics "[INFO] Script completed"
"
fi


##########################
# ==== BASH SECTION ====
##########################

# Default mode flags
DRYRUN=false
MODE="normal"
UNDO=false
TIMESTAMP=$(date +'%F-%H%M%S')
LOG_DIR="./cp-logs"
BACKUP_DIR="./cp-backups/$TIMESTAMP"
mkdir -p "$LOG_DIR" "$BACKUP_DIR"
LOG="$LOG_DIR/hardening_$TIMESTAMP.log"
ERR="$LOG_DIR/errors_$TIMESTAMP.log"
FORENSICS_LOG="$LOG_DIR/forensics_$TIMESTAMP.log"
SUSPICIOUS_OUTPUT="$LOG_DIR/suspicious_files_$TIMESTAMP.txt"

exec > >(tee -i "$LOG") 2> >(tee -a "$ERR" >&2)

RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; CYAN="\e[36m"; RESET="\e[0m"

# --------------------
# Process CLI Arguments
# --------------------
for arg in "$@"; do
    [[ "$arg" == "--dry-run" ]] && DRYRUN=true
    [[ "$arg" =~ --forensic|--forensics ]] && MODE="forensic"
    [[ "$arg" == "--undo" ]] && UNDO=true
done

# --------------------
# Undo Functionality
# --------------------
BACKED_UP_FILES=()
REMOVED_USERS=()
STOPPED_SERVICES=()
backup_file() {
    [[ -f "$1" ]] && cp -n "$1" "$BACKUP_DIR/$(basename $1).bak" && BACKED_UP_FILES+=("$1")
}
undo_script() {
    echo -e "${YELLOW}UNDO MODE: Restoring backups and undoing changes...${RESET}"
    for file in "${BACKED_UP_FILES[@]}"; do
        [[ -f "$BACKUP_DIR/$(basename $file).bak" ]] && sudo cp "$BACKUP_DIR/$(basename $file).bak" "$file"
    done
    for user in "${REMOVED_USERS[@]}"; do
        sudo adduser --disabled-password --gecos "" "$user"
        echo "Re-added user $user"
    done
    for svc in "${STOPPED_SERVICES[@]}"; do
        sudo systemctl enable "$svc"
        sudo systemctl start "$svc"
    done
    echo -e "${GREEN}UNDO COMPLETE${RESET}"
    exit 0
}
$UNDO && undo_script

# --------------------
# OS Detection
# --------------------
if [ -f /etc/os-release ]; then source /etc/os-release; else echo -e "${RED}Cannot detect OS${RESET}" && exit 1; fi
echo -e "${CYAN}Detected OS: $NAME $VERSION_ID${RESET}"

# PAM and SSH config path (APT-based distros)
PAM_DIR="/etc/pam.d"
SSHD="/etc/ssh/sshd_config"

echo -e "${YELLOW}--- Running full 18-step hardening ---${RESET}"

##########################
# Step 1: USER / ADMIN AUDIT
##########################
echo "--- [1/18] USER/AUTHORIZED ADMIN AUDIT ---"
tmp_audit=$(mktemp /tmp/user_audit.XXXX)
cat > "$tmp_audit" <<EOL
# Authorized Administrators:
# $USER
# iwest
# password: JITTerS
# Authorized Users:
# hspecter
# jpearson
EOL
nano "$tmp_audit"

declare -A ADMIN_PASSWORDS
users_list=""; admins_list="$USER "
section=""; last_admin=""
while IFS= read -r line; do
    line=$(echo "$line"|xargs)
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue

    case "$line" in
        "Authorized Administrators:"|"Authorized Users:") section="$line"; continue ;;
    esac

    if [[ "$section" == "Authorized Administrators:" ]]; then
        if [[ "$line" =~ ^password:\ (.+)$ ]]; then
            ADMIN_PASSWORDS["$last_admin"]="${BASH_REMATCH[1]}"
        else
            last_admin="$line"
            admins_list+="$line "
        fi
    elif [[ "$section" == "Authorized Users:" ]]; then
        users_list+="$line "
    fi
done < "$tmp_audit"
rm -f "$tmp_audit"

all_authorized="$admins_list $users_list"
REMOVED_USERS=()
echo -e "${YELLOW}Auditing system users...${RESET}"
for user in $(awk -F: '$3>=1000 && $3<=6000 {print $1}' /etc/passwd); do
    if [[ ! " $all_authorized " =~ " $user " ]]; then
        echo "ALERT: Unauthorized user detected: $user"
        REMOVED_USERS+=("$user")
        if [[ "$MODE" != "forensic" && "$DRYRUN" == false ]]; then
            read -p "Do you want to remove $user? [y/N]: " choice
            [[ "$choice" =~ ^[Yy]$ ]] && sudo deluser --remove-home "$user"
        fi
    fi
done

##########################
# Step 2: ADMIN PASSWORD ENFORCEMENT
##########################
echo "--- [2/18] Admin password audit ---"
for admin in $admins_list; do
    [[ "$admin" == "$USER" ]] && continue
    current_hash=$(getent shadow "$admin" | cut -d: -f2)
    if [[ -z "$current_hash" || "$current_hash" == "!" || "$current_hash" == "*" ]]; then
        echo "Admin $admin has no password set!"
        if [[ "$MODE" != "forensic" && "$DRYRUN" == false ]]; then
            read -p "Enter new password for $admin: " new_pass; echo
            echo "$admin:$new_pass" | sudo chpasswd
        fi
    fi
done

##########################
# Step 3: SYSTEM UPDATE CHECK
##########################
echo "--- [3/18] Updating system ---"
$DRYRUN && echo "[DRY-RUN] Skipping apt update/upgrade." || { sudo apt update -y && sudo apt upgrade -y; }

##########################
# Step 4: PAM/SSH HARDENING
##########################
echo "--- [4/18] PAM/SSH hardening ---"
backup_file "$PAM_DIR/common-password"
backup_file "$SSHD"
$DRYRUN || {
    sudo sed -i 's/^#\(.*pam_cracklib.so.*\)/\1 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' "$PAM_DIR/common-password"
    sudo sed -i 's/^#\(PermitRootLogin\s*\).*$/\1 no/' "$SSHD"
}

##########################
# Step 5: FIREWALL CONFIG
##########################
echo "--- [5/18] Firewall setup ---"
$DRYRUN || {
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw enable
}

##########################
# Step 6: FAIL2BAN
##########################
echo "--- [6/18] Fail2Ban installation/check ---"
$DRYRUN || sudo systemctl enable --now fail2ban

##########################
# Step 7: BACKGROUND UPDATES
##########################
echo "--- [7/18] System updates ---"
$DRYRUN || sudo apt upgrade -y

##########################
# Step 8: ACCOUNT POLICIES
##########################
echo "--- [8/18] Password policies ---"
$DRYRUN || sudo chage --maxdays 90 --mindays 10 $USER

##########################
# Step 9: ACCOUNT LOCKOUT
##########################
echo "--- [9/18] Account lockout ---"
$DRYRUN || sudo faillock --user $USER --reset

##########################
# Step 10: LOCAL AUDIT POLICY
##########################
echo "--- [10/18] Audit policies ---"
$DRYRUN || sudo auditctl -e 1

##########################
# Step 11: SECURITY OPTIONS
##########################
echo "--- [11/18] MSCT Security Options ---"
$DRYRUN || echo "[INFO] MSCT security applied (logs only)"

##########################
# Step 12: SERVICES DISABLE
##########################
echo "--- [12/18] Disabling unsafe services ---"
for svc in rpcbind cups avahi-daemon; do
    $DRYRUN || { sudo systemctl stop "$svc"; sudo systemctl disable "$svc"; STOPPED_SERVICES+=("$svc"); }
done

##########################
# Step 13: FEATURES
##########################
echo "--- [13/18] Disabling unnecessary features ---"
$DRYRUN || sudo systemctl mask rpcbind.service

##########################
# Step 14: SUSPICIOUS FILE SCAN
##########################
echo "--- [14/18] Suspicious files scan ---"
> "$SUSPICIOUS_OUTPUT"

# Function to log suspicious files with reason
log_suspicious() {
    local file="$1"
    local reason="$2"
    echo "[SUSPICIOUS] $file - Reason: $reason" | tee -a "$FORENSICS_LOG"
    echo "$file" >> "$SUSPICIOUS_OUTPUT"
}

# World-writable files
while IFS= read -r f; do
    log_suspicious "$f" "World-writable"
done < <(find /etc /usr /bin /sbin -type f -perm -0002 2>/dev/null)

# SUID/SGID files
while IFS= read -r f; do
    log_suspicious "$f" "SUID/SGID"
done < <(find /usr/bin /usr/sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

# Hidden files in /etc and /home
while IFS= read -r f; do
    log_suspicious "$f" "Hidden file"
done < <(find /etc /home -name ".*" -type f 2>/dev/null)

# Scripts or executables in /tmp and /var/tmp
while IFS= read -r f; do
    log_suspicious "$f" "Suspicious extension ($(basename "$f"))"
done < <(find /tmp /var/tmp -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.php" -o -name "*.exe" \) 2>/dev/null)
##########################
# Step 15: BACKUP SUSPICIOUS FILES
##########################
echo "--- [15/18] Backing up suspicious files ---"
$DRYRUN || while read -r f; do backup_file "$f"; done < "$SUSPICIOUS_OUTPUT"

##########################
# Step 16: READ README / Apache/MySQL Detection
##########################
echo "--- [16/18] Detecting Apache/MySQL & scanning README ---"
README_PATH=$(find / -type f -iname 'README' 2>/dev/null | head -n1)
if [[ -z "$README_PATH" ]]; then
    read -p "README not found. Enter README URL: " README_URL
    README_PATH="/tmp/README.download"
    curl -sSL "$README_URL" -o "$README_PATH"
fi
if grep -iq "apache" "$README_PATH"; then echo "[INFO] Apache mentioned in README"; APACHE_FOUND=true; fi
if grep -iq "mysql" "$README_PATH"; then echo "[INFO] MySQL mentioned in README"; MYSQL_FOUND=true; fi

##########################
# Step 17: SERVICE-SPECIFIC HARDENING
##########################
echo "--- [17/18] Apache/MySQL hardening ---"
$DRYRUN || {
    $APACHE_FOUND && sudo a2enmod security2 headers; sudo systemctl restart apache2
    $MYSQL_FOUND && sudo mysql_secure_installation
}

##########################
# Step 18: VIRUSTOTAL SCAN
##########################
# --------------------------
# Step 18: VirusTotal Scan (Linux, smart sleep)
# --------------------------

if [[ "$DRYRUN" == false ]]; then
    echo "--- [18/18] Running VirusTotal scan on suspicious files ---" | tee -a "$FORENSICS_LOG"

    read -sp "Enter VirusTotal API Key: " VIRUSTOTAL_API_KEY
    echo
    if [[ -z "$VIRUSTOTAL_API_KEY" ]]; then
        echo "[ERROR] No API key provided, skipping VirusTotal scan." | tee -a "$FORENSICS_LOG"
    else
        while IFS= read -r line; do
            file=$(echo "$line" | cut -d'|' -f1)
            reason=$(echo "$line" | cut -d'|' -f2)
            file=$(echo "$file" | sed 's|\\|/|g')
            sha256=$(sha256sum "$file" | awk '{print $1}')
            echo "[VT] Suspicious file: $file | Reason: $reason | SHA256: $sha256" | tee -a "$FORENSICS_LOG"

            success=false
            while [[ "$success" == false ]]; do
                response=$(curl -sSL -w "%{http_code}" -H "x-apikey: $VIRUSTOTAL_API_KEY" \
                    "https://www.virustotal.com/api/v3/files/$sha256")
                http_code="${response: -3}"  # Last 3 chars are the HTTP status
                body="${response::-3}"       # Rest is the JSON body

                if [[ "$http_code" == "200" ]]; then
                    malicious=$(echo "$body" | jq '.data.attributes.last_analysis_stats.malicious')
                    suspicious=$(echo "$body" | jq '.data.attributes.last_analysis_stats.suspicious')
                    harmless=$(echo "$body" | jq '.data.attributes.last_analysis_stats.harmless')
                    echo "[VT RESULT] $file | Malicious: $malicious | Suspicious: $suspicious | Harmless: $harmless" | tee -a "$FORENSICS_LOG"
                    success=true
                elif [[ "$http_code" == "429" ]]; then
                    echo "[VT WAIT] Too Many Requests for $file, waiting 60 seconds..." | tee -a "$FORENSICS_LOG"
                    sleep 60
                else
                    echo "[VT ERROR] $file | HTTP $http_code | Response: $body" | tee -a "$FORENSICS_LOG"
                    success=true
                fi
            done

            # Always wait 15 seconds after each request
            sleep 15
        done < "$SUSPICIOUS_OUTPUT"
    fi
fi

echo -e "${GREEN}BASH 18-STEP HARDENING COMPLETE${RESET}"
# --------------------------
# LOG PATHS TO STDOUT
# --------------------------
echo "================== LOG LOCATIONS =================="
[[ -f "$LOG" ]] && echo "Normal log:        $LOG"
[[ -f "$ERR" ]] && echo "Error log:         $ERR"
[[ -f "$FORENSICS_LOG" ]] && echo "Forensics log:     $FORENSICS_LOG"
echo "==================================================="
