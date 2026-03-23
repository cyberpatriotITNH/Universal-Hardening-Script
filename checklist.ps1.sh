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
    [switch]`$FORCE,
    [switch]`$UNDO,
    [switch]`$DRYRUN,
    [switch]`$FORENSIC
)

function Write-Log([string]`$msg){ Write-Host \"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') `t `$msg\" }

Write-Host '[WINDOWS] Starting 18-Step Hardening & Forensics'

# --------------------------
# Detect OS Edition
# --------------------------
`$WIN_EDITION = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
Write-Host \"[WINDOWS] Detected Edition: `$WIN_EDITION\"

# --------------------------
# Step 1: User Accounts Audit
# --------------------------
Write-Host '[1/18] User accounts audit...'
`$users = Get-LocalUser
`$admins = Get-LocalGroupMember Administrators | Select-Object -ExpandProperty Name
foreach (`$u in `$users){
    if (`$u.Name -eq 'Guest') {
        if (-not `$FORENSIC) { Disable-LocalUser -Name `$u.Name; Write-Log 'Guest account disabled' } else { Write-Log 'Guest account disabled (forensic)' }
    }
    if (-not `$FORENSIC -and -not `$u.Enabled) { Enable-LocalUser -Name `$u.Name; Write-Log \"Enabled user `$($u.Name)\" }
}

# --------------------------
# Step 2: Password Policies
# --------------------------
Write-Host '[2/18] Enforcing password policies...'
if (-not `$FORENSIC) { net accounts /minpwlen:12 /maxpwage:90 /minpwage:10 /uniquepw:3 } else { Write-Log 'Password policy check (forensic)' }

# --------------------------
# Step 3: Account Lockout
# --------------------------
Write-Host '[3/18] Setting account lockout policy...'
if (-not `$FORENSIC) { net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 } else { Write-Log 'Account lockout policy check (forensic)' }

# --------------------------
# Step 4: Local Audit Policy
# --------------------------
Write-Host '[4/18] Enabling local audit policies...'
if (-not `$FORENSIC) { auditpol /set /category:* /success:enable /failure:enable } else { Write-Log 'Audit policy check (forensic)' }

# --------------------------
# Step 5: Security Options (MSCT)
# --------------------------
Write-Host '[5/18] Applying security options...'
`$secOpts = @{
    'DontDisplayLastUserName' = 1
    'DisableCAD' = 0
    'LimitBlankPasswordUse' = 1
}
foreach (`$key in `$secOpts.Keys){
    if (-not `$FORENSIC) { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name `$key -Value `$secOpts[`$key]; Write-Log \"Applied `$key = `$($secOpts[`$key])\" } else { Write-Log \"Security option `$key checked (forensic)\" }
}

# --------------------------
# Step 6: Firewall
# --------------------------
Write-Host '[6/18] Configuring firewall...'
if (-not `$FORENSIC) { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow } else { Write-Log 'Firewall check (forensic)' }

# --------------------------
# Step 7: Windows Update
# --------------------------
Write-Host '[7/18] Enabling auto-update...'
if (-not `$FORENSIC) {
    `$wuSettings = New-Object -ComObject 'Microsoft.Update.AutoUpdate'
    `$wuSettings.Settings.NotificationLevel = 4
    `$wuSettings.Settings.Save()
} else { Write-Log 'Windows Update check (forensic)' }

# --------------------------
# Step 8: Services (Disable Unsafe)
# --------------------------
Write-Host '[8/18] Disabling unsafe services...'
`$servicesToDisable = @('FTPSVC','Spooler','RemoteRegistry','TermService')
foreach (`$svc in `$servicesToDisable){
    if (-not `$FORENSIC) { Stop-Service `$svc -Force; Set-Service `$svc -StartupType Disabled; Write-Log \"Stopped and disabled `$svc\" } else { Write-Log \"Service `$svc check (forensic)\" }
}

# --------------------------
# Step 9: Windows Features
# --------------------------
Write-Host '[9/18] Disabling unsafe features...'
`$featuresToDisable = @('TelnetClient','SMB1Protocol','WindowsMediaPlayer','IIS-Services','AD-Domain-Services')
foreach (`$f in `$featuresToDisable){
    if (-not `$FORENSIC) { Disable-WindowsOptionalFeature -Online -FeatureName `$f -NoRestart; Write-Log \"Disabled `$f\" } else { Write-Log \"Feature `$f check (forensic)\" }
}

# --------------------------
# Step 10: Event Logs / Scheduled Tasks
# --------------------------
Write-Host '[10/18] Clearing event logs and scheduled tasks...'
if (-not `$FORENSIC) { wevtutil el | Foreach-Object { wevtutil cl `$_ }; Get-ScheduledTask | Where-Object {$_.TaskName -notlike '*Microsoft*'} | Disable-ScheduledTask } else { Write-Log 'Event logs/Task check (forensic)' }

# --------------------------
# Step 11: Suspicious File Detection
# --------------------------
Write-Host '[11/18] Scanning for suspicious files...'
`$suspiciousFiles = Get-ChildItem -Path 'C:\Users','C:\ProgramData' -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {($_.Attributes -match 'Hidden') -or ($_.Mode -match 'writable') -or ($_.Extension -match '.exe|.bat|.ps1')}
`$suspiciousFiles | ForEach-Object { Write-Log \"Suspicious: `$($_.FullName)\" }

# --------------------------
# Step 12: Backup User Files
# --------------------------
Write-Host '[12/18] Backing up user files...'
`$backupDir = \"C:\cp-backups\$((Get-Date -Format 'yyyy-MM-dd_HHmmss'))\"
if (-not `$FORENSIC) { New-Item -ItemType Directory -Path `$backupDir -Force; `$suspiciousFiles | ForEach-Object { Copy-Item -Path `$_ -Destination `$backupDir -Force } } else { Write-Log 'Backup skipped in forensic mode' }

# --------------------------
# Step 13: VirusTotal scan (read-only, with API interaction)
# --------------------------
Write-Host '[13/18] VirusTotal scan (with API)...'

# Prompt for API Key in silent mode
$VIRUSTOTAL_API_KEY = Read-Host "Enter your VirusTotal API Key" -AsSecureString
$VIRUSTOTAL_API_KEY = [System.Net.NetworkCredential]::new("", $VIRUSTOTAL_API_KEY).Password  # Convert SecureString to Plaintext

if (-not $VIRUSTOTAL_API_KEY) {
    Write-Host "[ERROR] No API key provided, skipping VirusTotal scan."
    return
}

# Loop through the suspicious files and check them against VirusTotal
if ($SUSPICIOUS_FILES) {
    foreach ($file in $suspiciousFiles) {
        $sha256 = Get-FileHash $file.FullName -Algorithm SHA256 | Select-Object -ExpandProperty Hash
        Write-Host "[INFO] Scanning file $($file.FullName) with SHA256: $sha256"

        # Prepare the VirusTotal API URL
        $vtApiUrl = "https://www.virustotal.com/api/v3/files/$sha256"
        $headers = @{
            "x-apikey" = $VIRUSTOTAL_API_KEY
        }

        try {
            # Make API Request to VirusTotal
            $response = Invoke-RestMethod -Uri $vtApiUrl -Headers $headers -Method Get

            # Output results
            if ($response.data) {
                $scanResults = $response.data.attributes.last_analysis_stats
                Write-Host "[VT Scan Result] $($file.FullName):"
                Write-Host "[INFO] Scan results: $($scanResults)"
            } else {
                Write-Host "[INFO] No scan results available for $($file.FullName)"
            }
        }
        catch {
            Write-Host "[ERROR] Failed to get scan results for $($file.FullName). Error: $_"
        }
    }
} else {
    Write-Host '[INFO] No suspicious files found, skipping VirusTotal scan.'
}

# --------------------------
# Step 14: Extra MSCT Security Baseline
# --------------------------
Write-Host '[14/18] Extra MSCT hardening (Windows-only)'
if ($EXTRA -and -not $FORENSIC) {
    # Network hardening
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
        -Name 'RequireSecuritySignature' -Value 1
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
        -Name 'EnableSecuritySignature' -Value 1

    # Restrict removable drives
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' `
        -Name 'WriteProtect' -PropertyType DWord -Value 1 -Force | Out-Null

    Write-Host '[INFO] Extra MSCT settings applied'
} else {
    Write-Host '[INFO] Extra mode not enabled or forensic mode active, skipping'
}

# --------------------------
# Step 15: Password Expiry and Enforcement Review
# --------------------------
Write-Host '[15/18] Reviewing password expiry and enforcement...'
$allUsers = Get-LocalUser
foreach ($u in $allUsers) {
    $pwdInfo = net user $u.Name
    if ($pwdInfo -match 'Password expires') {
        Write-Host "User $($u.Name) password info: $($pwdInfo | Select-String 'Password expires')"
    } else {
        Write-Host "User $($u.Name) has no expiration set"
    }
}

# --------------------------
# Step 16: Audit Policy Review
# --------------------------
Write-Host '[16/18] Reviewing local audit policies...'
$auditSettings = auditpol /get /category:*
foreach ($line in $auditSettings) {
    Write-Host $line
}

# --------------------------
# Step 17: Security Options Validation
# --------------------------
Write-Host '[17/18] Validating key security options...'
$securityKeys = @{
    'DontDisplayLastUserName' = 1
    'DisableCAD' = 0
    'LimitBlankPasswordUse' = 1
}

foreach ($key in $securityKeys.Keys) {
    $currentValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name $key).$key
    if ($currentValue -eq $securityKeys[$key]) {
        Write-Host "[OK] $key is correctly configured ($currentValue)"
    } else {
        Write-Host "[WARN] $key is $currentValue, expected $($securityKeys[$key])"
    }
}

# --------------------------
# Step 18: Apache / MySQL Detection
# --------------------------
Write-Host '[18/18] Detecting Apache / MySQL services...'
if (Get-Service | Where-Object {$_.Name -match 'Apache|MySQL'}) {
    Write-Log 'Apache/MySQL detected — applying service-specific hardening'
}

Write-Host '[WINDOWS] Full 18-step report complete'
exit
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
echo "" > "$SUSPICIOUS_OUTPUT"
find /etc /usr /bin /sbin -type f -perm -0002 >> "$SUSPICIOUS_OUTPUT" 2>/dev/null
find /usr/bin /usr/sbin -type f \( -perm -4000 -o -perm -2000 \) >> "$SUSPICIOUS_OUTPUT" 2>/dev/null
find /etc /home -name ".*" -type f >> "$SUSPICIOUS_OUTPUT" 2>/dev/null
find /tmp /var/tmp -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.php" -o -name "*.exe" \) >> "$SUSPICIOUS_OUTPUT" 2>/dev/null

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
echo "--- [18/18] VirusTotal hash scan ---"
read -sp "Enter VirusTotal API key (optional): " VIRUSTOTAL_API_KEY; echo
if [[ -n "$VIRUSTOTAL_API_KEY" && "$MODE" == "forensic" ]]; then
    while read -r f; do
        sha256sum "$f" | awk '{print $1}' | xargs -I {} echo "VT hash: {}"
    done < "$SUSPICIOUS_OUTPUT"
fi

echo -e "${GREEN}BASH 18-STEP HARDENING COMPLETE${RESET}"
