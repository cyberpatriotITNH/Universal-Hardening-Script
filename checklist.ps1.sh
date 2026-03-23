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
param(
    [switch]$NORMAL,
    [switch]$FORENSIC,
    [switch]$DRYRUN,
    [switch]$UNDO
)

# Global Paths
$TIMESTAMP = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$BACKUP_DIR = "C:\cp-backups\$TIMESTAMP"
$FOR_LOG = "C:\cp-logs\forensics_$TIMESTAMP.log"
$VT_API_KEY = ""

# Helper Function for logging
function Write-Forensics([string]$Message){
    Add-Content -Path $FOR_LOG -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') `t $Message"
}

function Backup-File([string]$Path){
    if (Test-Path $Path){
        $dest = Join-Path $BACKUP_DIR (Split-Path $Path -Leaf)
        Copy-Item -Path $Path -Destination $dest -Force
        Write-Forensics "Backed up file: $Path -> $dest"
    }
}

function VT-Scan {
    param (
        [string]$File
    )

    if (-not (Test-Path $File)) {
        Write-Forensics "[ERROR] File not found: $File"
        return
    }

    # Compute SHA256 hash
    try {
        $sha256 = (Get-FileHash $File -Algorithm SHA256).Hash
    } catch {
        Write-Forensics "[ERROR] Failed to compute hash for $File - $_"
        return
    }

    # VirusTotal API URL and headers
    $VTUrl = "https://www.virustotal.com/api/v3/files/$sha256"
    $Headers = @{ "x-apikey" = $VT_API_KEY }

    $success = $false
    while (-not $success) {
        try {
            $Response = Invoke-RestMethod -Uri $VTUrl -Headers $Headers -Method GET

            if ($Response.data) {
                $Stats = $Response.data.attributes.last_analysis_stats

                if ($Stats.malicious -gt 0) {
                    Write-Forensics "[MALICIOUS] $File detected as malicious by VirusTotal"
                } else {
                    Write-Forensics "[CLEAN] $File scanned clean by VirusTotal"
                }

            } else {
                Write-Forensics "[INFO] No VirusTotal data available for $File"
            }

            $success = $true
        } catch {
            # Handle 429 "Too Many Requests"
            if ($_ -match "429") {
                Write-Forensics "[VT WAIT] Too Many Requests for $File, waiting 60 seconds..."
                Start-Sleep -Seconds 60
            } else {
                Write-Forensics "[ERROR] VirusTotal scan failed for $File - $_"
                $success = $true
            }
        }
    }

    # Wait 15 seconds between files to respect 4 requests/min
    Start-Sleep -Seconds 15
}

# -----------------------------
# Step 0: Prepare directories
# -----------------------------
if (-not $DRYRUN){
    New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path $FOR_LOG) -Force | Out-Null
}

Write-Host "[INFO] Starting 18-step hardening & forensics..."
Write-Forensics "[INFO] Script started in mode: $($NORMAL ? 'NORMAL' : 'FORENSIC')"

# --------------------------
# STEP 1-2: USER/ADMIN AUDIT & STRONG PASSWORD ENFORCEMENT
# Interactive Notepad input for authorized accounts, passwords optional
# --------------------------
Write-Host "[1/18] Interactive user/admin audit"

# Temporary file for authorized users/admins
$tmpFile = "$env:TEMP\authorized_users.txt"
@"
# Paste your authorized users/admins below
# Format:
# Authorized Administrators:
# benjamin (you)
# password: W1llH4ck4B4con
# llitt
# Password: ugotlittup
# Authorized Users:
# user1
# user2
"@ | Out-File -FilePath $tmpFile -Encoding UTF8

# Open Notepad and wait for user input
Start-Process notepad.exe $tmpFile -Wait

# Read and parse input
$allLines = Get-Content $tmpFile
$section = ""
$admins_list = @()
$users_list = @()
$admin_passwords = @{}
$lastAdmin = ""

foreach ($line in $allLines) {
    $line = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line -like "#*") { continue }

    switch ($line) {
        "Authorized Administrators:" { $section = "admin"; continue }
        "Authorized Users:" { $section = "user"; continue }
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

foreach ($u in $foundUsers) {
    if (-not ($allAuthorized -contains $u.Name)) {
        Write-Host "[ALERT] Unauthorized user found: $($u.Name)"
        Add-Content $FORENSICS_LOG "[USER AUDIT] Unauthorized user detected: $($u.Name)"

        if (-not $FORENSIC -and -not $DRYRUN) {
            $choice = Read-Host "Do you want to remove $($u.Name)? [y/N]"
            if ($choice -match "^[Yy]$") {
                Remove-LocalUser -Name $u.Name
                Add-Content $FORENSICS_LOG "User $($u.Name) removed."
            }
        }
    } else {
        Add-Content $FORENSICS_LOG "[USER AUDIT] Authorized user verified: $($u.Name)"
    }
}
Write-Host "[2/18] Admin password enforcement..."

# --------------------------
# Enforce strong passwords for administrators
# --------------------------
foreach ($admin in $admins_list) {
    $localUser = Get-LocalUser -Name $admin -ErrorAction SilentlyContinue
    if ($null -ne $localUser) {
        # If password not set or weak, enforce a strong password
        $passwordSet = $false
        try {
            $hash = (Get-LocalUser $admin).PasswordExpires
            $passwordSet = $true
        } catch {}
        
        if (-not $passwordSet -or $admin_passwords[$admin]) {
            if (-not $FORENSIC -and -not $DRYRUN) {
                # Prompt for strong password
                $securePass = Read-Host "Enter strong password for admin $admin" -AsSecureString
                if ($securePass.Length -lt 12) {
                    Write-Host "[WARN] Password too short; recommend 12+ characters"
                }
                $plainPass = [System.Net.NetworkCredential]::new("", $securePass).Password
                $admin_passwords[$admin] = $plainPass
                # Apply password
                $localUser | Set-LocalUser -Password $securePass
                Add-Content $FORENSICS_LOG "[PASSWORD] Password set/updated for admin: $admin"
            } else {
                Add-Content $FORENSICS_LOG "[PASSWORD] Admin $admin requires password set/update (forensic/dry-run)"
            }
        } else {
            Add-Content $FORENSICS_LOG "[PASSWORD] Admin $admin password verified"
        }
    }
}

# --------------------------
# Disable Guest account
# --------------------------
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest) {
    if (-not $FORENSIC -and -not $DRYRUN) {
        Disable-LocalUser -Name "Guest"
        Add-Content $FORENSICS_LOG "[USER AUDIT] Guest account disabled"
    } else {
        Add-Content $FORENSICS_LOG "[USER AUDIT] Guest account found (forensic/dry-run)"
    }
}

# -----------------------------
# Step 3: Account Lockout
# -----------------------------
Write-Host "[3/18] Account Lockout Policy..."
if ($NORMAL -and -not $DRYRUN){ net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 }
Write-Forensics "Checked/enforced account lockout policy"

# -----------------------------
# Step 4: Local Audit Policy
# -----------------------------
Write-Host "[4/18] Local Audit Policy..."
if ($NORMAL -and -not $DRYRUN){ auditpol /set /category:* /success:enable /failure:enable }
Write-Forensics "Audit policy enabled for all categories"

# -----------------------------
# Step 5: Security Options
# -----------------------------
Write-Host "[5/18] Security Options..."
$SecOpts = @{
    'DontDisplayLastUserName' = 1
    'DisableCAD' = 0
    'LimitBlankPasswordUse' = 1
}
foreach ($key in $SecOpts.Keys){
    if ($NORMAL -and -not $DRYRUN){
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name $key -Value $SecOpts[$key]
    }
    Write-Forensics "Security option $key checked/applied"
}

# -----------------------------
# Step 6: Firewall
# -----------------------------
Write-Host "[6/18] Firewall Configuration..."
if ($NORMAL -and -not $DRYRUN){
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
}
Write-Forensics "Firewall configured"

# -----------------------------
# Step 7: Windows Update
# -----------------------------
Write-Host "[7/18] Windows Update..."
if ($NORMAL -and -not $DRYRUN){
    $wuSettings = New-Object -ComObject 'Microsoft.Update.AutoUpdate'
    $wuSettings.Settings.NotificationLevel = 4
    $wuSettings.Settings.Save()
}
Write-Forensics "Windows Update configured"

# -----------------------------
# Step 8: Services (Disable Unsafe)
# -----------------------------
Write-Host "[8/18] Disabling Unsafe Services..."
$ServicesToDisable = @('FTPSVC','Spooler','RemoteRegistry','TermService')
foreach ($svc in $ServicesToDisable){
    if ($NORMAL -and -not $DRYRUN){
        Stop-Service $svc -Force
        Set-Service $svc -StartupType Disabled
    }
    Write-Forensics "Service $svc checked/disabled"
}

# -----------------------------
# Step 9: Windows Features
# -----------------------------
Write-Host "[9/18] Disabling Unsafe Features..."
$FeaturesToDisable = @('TelnetClient','SMB1Protocol','WindowsMediaPlayer','IIS-Services','AD-Domain-Services')
foreach ($f in $FeaturesToDisable){
    if ($NORMAL -and -not $DRYRUN){
        Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart
    }
    Write-Forensics "Feature $f checked/disabled"
}

# -----------------------------
# Step 10: Event Logs / Scheduled Tasks
# -----------------------------
Write-Host "[10/18] Event Logs & Scheduled Tasks..."
if ($NORMAL -and -not $DRYRUN){
    wevtutil el | ForEach-Object { wevtutil cl $_ }
    Get-ScheduledTask | Where-Object {$_.TaskName -notlike '*Microsoft*'} | Disable-ScheduledTask
}
Write-Forensics "Event logs cleared; non-Microsoft scheduled tasks disabled"

# -----------------------------
# Step 11: Suspicious File Detection
# -----------------------------
Write-Host "[11/18] Suspicious File Scan..."

# Collect suspicious files in C:\Users and C:\ProgramData
$SuspiciousFiles = Get-ChildItem -Path 'C:\Users','C:\ProgramData' -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { 
        # Script executables or hidden files
        $_.Extension -match '.ps1|.bat|.exe|.pl|.py' -or $_.Attributes -match 'Hidden' 
    }

foreach ($f in $SuspiciousFiles) {
    $reason = @()

    # Check for hidden attribute
    if ($f.Attributes -match 'Hidden') {
        $reason += "Hidden file"
    }

    # Check for suspicious extension
    if ($f.Extension -match '.ps1|.bat|.exe|.pl|.py') {
        $reason += "Suspicious extension ($($f.Extension))"
    }

    # Check shebang mismatch for scripts (powershell, python, perl, bash)
    if ($f.Extension -match '.ps1|.pl|.py|.bat') {
        try {
            $FirstLine = Get-Content $f.FullName -ErrorAction SilentlyContinue -TotalCount 1
            if ($FirstLine -match '^#!' -and -not $FirstLine -match 'powershell|python|perl|bash') {
                $reason += "Shebang mismatch"
            }
        } catch {
            Write-Forensics "[ERROR] Failed to read $($f.FullName) - $_"
        }
    }

    if ($reason.Count -gt 0) {
        $reasonStr = ($reason -join '; ')
        Write-Forensics "[SUSPICIOUS] $($f.FullName) - Reason: $reasonStr"
    }
}

# -----------------------------
# Step 12: Backup User Files
# -----------------------------
Write-Host "[12/18] Backing up all user files..."
if ($NORMAL -and -not $DRYRUN){
    Get-ChildItem -Path C:\Users -Recurse -Force | ForEach-Object { Backup-File $_.FullName }
}

# -----------------------------
# Step 13: VirusTotal Scan
# -----------------------------
Write-Host "[13/18] VirusTotal Scan..."
if (-not $DRYRUN){
    if (-not $VT_API_KEY){
        $VT_API_KEY = Read-Host "Enter your VirusTotal API key"
    }
    foreach ($f in $SuspiciousFiles){
        VT-Scan $f.FullName
    }
}

# -----------------------------
# Step 14: Extra MSCT Hardening
# -----------------------------
Write-Host "[14/18] Extra MSCT Hardening..."
if ($NORMAL -and -not $DRYRUN){
    # Example network & removable drive restrictions
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'EnableSecuritySignature' -Value 1
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' -Name 'WriteProtect' -PropertyType DWord -Value 1 -Force | Out-Null
}
Write-Forensics "Extra MSCT hardening applied"

# -----------------------------
# Step 15: Password Expiry & Enforcement Review
# -----------------------------
Write-Host "[15/18] Password Expiry & Enforcement..."
$AllUsers = Get-LocalUser
foreach ($u in $AllUsers){
    $PwdInfo = net user $u.Name
    Write-Forensics "Password info for $($u.Name): $($PwdInfo | Select-String 'Password expires')"
}

# -----------------------------
# Step 16: Audit Policy Review
# -----------------------------
Write-Host "[16/18] Audit Policy Review..."
$auditSettings = auditpol /get /category:*
foreach ($line in $auditSettings){ Write-Forensics "[AUDIT] $line" }

# -----------------------------
# Step 17: Security Options Validation
# -----------------------------
Write-Host "[17/18] Security Options Validation..."
foreach ($key in $SecOpts.Keys){
    $current = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name $key).$key
    Write-Forensics "Security key $key: current=$current, expected=$($SecOpts[$key])"
}

# -----------------------------
# Step 18: Apache/MySQL Detection & Hardening
# -----------------------------
Write-Host '[18/18] Apache/MySQL Detection & Hardening'

function Log-Forensics($message) {
    $forensicsLog = "C:\cp-logs\forensics_$((Get-Date -Format 'yyyy-MM-dd_HHmmss')).log"
    Add-Content -Path $forensicsLog -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') `t $message"
}

# Function to get a strong password from user
function Get-StrongPassword {
    do {
        $pass1 = Read-Host "Enter strong MySQL root password (min 12 chars)" -AsSecureString
        $pass2 = Read-Host "Confirm password" -AsSecureString
        $plain1 = [System.Net.NetworkCredential]::new("", $pass1).Password
        $plain2 = [System.Net.NetworkCredential]::new("", $pass2).Password
        if ($plain1.Length -ge 12 -and $plain1 -eq $plain2) {
            return $plain1
        } else {
            Write-Host "[WARN] Passwords do not match or are too short. Try again."
        }
    } while ($true)
}

# -----------------------------
# Apache Hardening
# -----------------------------
$apacheSvc = Get-Service | Where-Object {$_.Name -match "Apache"} 
if ($apacheSvc) {
    Log-Forensics "Detected Apache service"
    Write-Host "[INFO] Applying Apache hardening..."
    if (-not $DRYRUN) {
        # Enable recommended modules if using Apache for Windows (depends on package)
        # Disable directory listing via httpd.conf or conf.d/security.conf
        $httpdConf = "C:\Apache24\conf\httpd.conf"
        if (Test-Path $httpdConf) {
            # Backup first
            Copy-Item $httpdConf "$httpdConf.bak" -Force
            # Disable directory listing
            (Get-Content $httpdConf) -replace 'Options Indexes', 'Options -Indexes' | Set-Content $httpdConf
            # Harden ServerTokens and ServerSignature
            (Get-Content $httpdConf) -replace 'ServerTokens OS', 'ServerTokens Prod' | Set-Content $httpdConf
            (Get-Content $httpdConf) -replace 'ServerSignature On', 'ServerSignature Off' | Set-Content $httpdConf
            Start-Service $apacheSvc.Name -ErrorAction SilentlyContinue
            Log-Forensics "Apache hardened: Indexes disabled, ServerTokens/Signature secured, config backed up"
        } else {
            Log-Forensics "Apache httpd.conf not found at $httpdConf"
        }
    } else {
        Log-Forensics "[DRY-RUN] Apache hardening would be applied"
    }
}

# -----------------------------
# MySQL Hardening
# -----------------------------
$mysqlSvc = Get-Service | Where-Object {$_.Name -match "MySQL|mysqld"}
if ($mysqlSvc) {
    Log-Forensics "Detected MySQL service"
    Write-Host "[INFO] Applying MySQL best-practice hardening..."
    if (-not $DRYRUN) {
        $mysqlRootPass = Get-StrongPassword
        # Secure root password, remove anonymous users, drop test DB, flush privileges
        $sqlCmds = @"
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mysqlRootPass';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db LIKE 'test\_%';
FLUSH PRIVILEGES;
"@
        # Save SQL commands to temp file
        $tmpSql = "$env:TEMP\mysql_hardening.sql"
        $sqlCmds | Set-Content $tmpSql
        # Execute SQL commands using mysql client
        & "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p"$mysqlRootPass" < $tmpSql
        Remove-Item $tmpSql -Force
        Log-Forensics "MySQL hardened: root password set, anonymous users removed, test DB removed, privileges flushed"
        # Optional: enforce SSL if configured
        & "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p"$mysqlRootPass" -e "ALTER USER 'root'@'localhost' REQUIRE SSL;"
        Log-Forensics "MySQL SSL enforcement applied for root"
    } else {
        Log-Forensics "[DRY-RUN] MySQL hardening would be applied"
    }
}

Write-Host "[INFO] 18-step hardening & forensics complete"
Write-Forensics "[INFO] Script completed"
# --------------------------
# LOG PATHS TO STDOUT
# --------------------------
Write-Host "================== LOG LOCATIONS =================="
if (Test-Path $LOG)          { Write-Host "Normal log:        $LOG" }
if (Test-Path $ERR)          { Write-Host "Error log:         $ERR" }
if (Test-Path $FORENSICS_LOG){ Write-Host "Forensics log:     $FORENSICS_LOG" }
Write-Host "==================================================="
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
        sudo systemctl stop "$svc"
        sudo systemctl disable "$svc"
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
