#!/bin/bash
: '
:: ========================================
:: The B.E.A.S.T (Better Executable Application for Security and Threat intelligence) Polyglot Bash/PowerShell Script (Windows first)
:: Usage: ./checklist.ps1.sh [--normal|--forensic|--dry-run|--undo|--benchmark-only|--no-benchmark]
:: Linux extras:   --disable-recovery (hide GRUB recovery entries)
:: Windows extras: --clear-logs (clear event logs after archiving)  --disable-rdp (disable TermService)
:: --undo reads a journal in the directory the script was run from: run it from the same place.
:: ========================================
'

# Detect PowerShell environment
if [ -n "$PSVersionTable" ] || [ -n "$WINDIR" ]; then
# Bash args never reach PowerShell on their own: translate them to PowerShell switches.
PS_ARGS=(); PS_MODE_SET=false
for a in "$@"; do
    case "$a" in
        --normal)               PS_ARGS+=(-NORMAL);    PS_MODE_SET=true ;;
        --forensic|--forensics) PS_ARGS+=(-FORENSIC);  PS_MODE_SET=true ;;
        --dry-run)              PS_ARGS+=(-DRYRUN);    PS_MODE_SET=true ;;
        --undo)                 PS_ARGS+=(-UNDO);      PS_MODE_SET=true ;;
        --clear-logs)           PS_ARGS+=(-CLEARLOGS) ;;
        --disable-rdp)          PS_ARGS+=(-DISABLERDP) ;;
    esac
done
$PS_MODE_SET || PS_ARGS+=(-NORMAL)   # same default as the Linux side: normal (change) mode
# The script goes into a real .ps1 (UTF-8 BOM). Piping it through stdin breaks param()
# and lets Read-Host swallow the rest of the script as "input".
PS_TMP="$(mktemp --suffix=.ps1 2>/dev/null || mktemp)"
printf '\xEF\xBB\xBF' > "$PS_TMP"
cat >> "$PS_TMP" <<'PSEOF'
# ========================================
# CyberPatriot PowerShell Hardening Script
# All findings go to Forensics log
# System changes go to Normal log
# ========================================

param(
    [switch]$NORMAL,
    [switch]$FORENSIC,
    [switch]$DRYRUN,
    [switch]$UNDO,
    [switch]$CLEARLOGS,
    [switch]$DISABLERDP
)

# Master gate: true only in explicit normal (change) mode, never during a dry run.
# Forensic mode and dry-run mode must NEVER modify target files/system state.
$MAKE_CHANGES = ($MAKE_CHANGES)

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
    if (-not (Test-Path $LOG_DIR)) { return }   # dry-run creates no directories
    $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $FORENSICS_LOG -Value "$time `t $Message"
}

function Write-Normal([string]$Message){
    if (-not $DRYRUN) { Add-Content -Path $LOG -Value "$Message" }
}

function Backup-File([string]$Path, [switch]$Quiet){
    # Keeps the full path under $BACKUP_DIR (the old flat layout overwrote same-named files).
    if (Test-Path -LiteralPath $Path -PathType Leaf){
        $rel  = $Path -replace '^([A-Za-z]):', '$1'
        $dest = Join-Path $BACKUP_DIR $rel
        New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $Path -Destination $dest -Force -EA SilentlyContinue
        if (-not $Quiet) { Write-Forensics "[BACKUP] $Path -> $dest" }
        return $dest
    }
}

function Set-Reg([string]$Path, [string]$Name, [object]$Val, [string]$Type="DWord") {
    if (-not $MAKE_CHANGES) { Write-Normal "[DRY-RUN/FORENSIC] Would set $Path :: $Name = $Val"; return }
    $existed = $false; $old = $null; $kind = $Type
    try {
        $old  = (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name
        $kind = (Get-Item -Path $Path -EA Stop).GetValueKind($Name).ToString()
        $existed = $true
    } catch {}
    Add-Journal @{ type='reg'; name=$Name; path=$Path; existed=$existed; old=$old; kind=$kind }
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Val -Type $Type -Force -EA SilentlyContinue
    Write-Normal "[REG] $Path :: $Name = $Val"
}

# -----------------------------
# Undo journal: every state change is recorded so -UNDO can reverse it.
# One persistent file (not per-run) so undo works from a later session.
# -----------------------------
$JOURNAL = "C:\cp-backups\undo-journal.jsonl"
function Add-Journal([hashtable]$Entry) {
    if (-not $MAKE_CHANGES) { return }
    $Entry['ts'] = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    ($Entry | ConvertTo-Json -Compress -Depth 4) | Add-Content -Path $JOURNAL -Encoding UTF8
}

function Backup-Config([string]$Path) {
    $dest = Backup-File $Path -Quiet
    if ($dest) { Add-Journal @{ type='file'; name=(Split-Path $Path -Leaf); path=$Path; backup=$dest } }
}

function Disable-SvcJournaled([string]$Name) {
    $s = Get-Service -Name $Name -EA SilentlyContinue
    if (-not $s) { Write-Forensics "Service $Name not present"; return }
    if (-not $MAKE_CHANGES) { return }
    Add-Journal @{ type='service'; name=$Name; startType=[string]$s.StartType; status=[string]$s.Status }
    Stop-Service $Name -Force -EA SilentlyContinue
    Set-Service $Name -StartupType Disabled -EA SilentlyContinue
    Write-Normal "[SERVICE] $Name stopped and disabled (was $($s.StartType)/$($s.Status))"
}

function Invoke-Undo {
    Write-Host "=== UNDO: replaying $JOURNAL in reverse ===" -ForegroundColor Yellow
    if (-not (Test-Path $JOURNAL)) { Write-Host "[UNDO] No journal found; nothing to undo."; return }
    $entries = @(Get-Content $JOURNAL | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
    [array]::Reverse($entries)
    foreach ($e in $entries) {
        try {
            switch ($e.type) {
                'reg' {
                    if ($e.existed) {
                        if (-not (Test-Path $e.path)) { New-Item -Path $e.path -Force | Out-Null }
                        Set-ItemProperty -Path $e.path -Name $e.name -Value $e.old -Type $e.kind -Force -EA Stop
                    } else { Remove-ItemProperty -Path $e.path -Name $e.name -Force -EA SilentlyContinue }
                }
                'service'   { Set-Service -Name $e.name -StartupType $e.startType -EA Stop
                              if ($e.status -eq 'Running') { Start-Service $e.name -EA SilentlyContinue } }
                'feature'   { Enable-WindowsOptionalFeature -Online -FeatureName $e.name -NoRestart | Out-Null }
                'fwprofile' { Set-NetFirewallProfile -Profile $e.name -Enabled $e.enabled -DefaultInboundAction $e.inbound -DefaultOutboundAction $e.outbound }
                'fwrule'    { Remove-NetFirewallRule -DisplayName $e.name -EA SilentlyContinue }
                'user'      { if ($e.wasEnabled) { Enable-LocalUser -Name $e.name } }
                'userexp'   { Set-LocalUser -Name $e.name -PasswordNeverExpires ([bool]$e.old) }
                'lockout'   { net accounts /lockoutthreshold:$($e.threshold) /lockoutduration:$($e.duration) /lockoutwindow:$($e.window) | Out-Null }
                'auditpol'  { auditpol /restore /file:"$($e.file)" | Out-Null }
                'bcd'       { bcdedit /import "$($e.file)" | Out-Null }
                'file'      { Copy-Item -LiteralPath $e.backup -Destination $e.path -Force }
                'newfile'   { Remove-Item -LiteralPath $e.path -Force -EA SilentlyContinue }
                'wu'        { $w = New-Object -ComObject 'Microsoft.Update.AutoUpdate'; $w.Settings.NotificationLevel = [int]$e.level; $w.Settings.Save() }
                'mp'        { Set-MpPreference -DisableRealtimeMonitoring ([bool]$e.disableRealtime) }
                'ipv6'      { Enable-NetAdapterBinding -Name $e.name -ComponentID "ms_tcpip6" }
            }
            Write-Host "[UNDO] $($e.type): $($e.name)" -ForegroundColor Green
        } catch { Write-Host "[UNDO] FAILED $($e.type) $($e.name): $_" -ForegroundColor Red }
    }
    if (Get-Service sshd -EA SilentlyContinue) { Restart-Service sshd -EA SilentlyContinue }
    Move-Item $JOURNAL ("$JOURNAL.undone-" + (Get-Date -Format 'yyyyMMdd_HHmmss')) -Force
    Write-Host "UNDO COMPLETE. Not reversible: removed user accounts, cleared event logs, installed/updated software." -ForegroundColor Yellow
}

function Write-Alert([string]$Msg) {
    Write-Host "[ALERT] $Msg" -ForegroundColor Red
    Write-Forensics "[ALERT] $Msg"
}

function Write-Warn([string]$Msg) {
    Write-Host "[WARN] $Msg" -ForegroundColor Yellow
    Write-Normal "[WARN] $Msg"
}

# Suspicious files output path (populated in Step 12)
$SUSP_OUT = "$LOG_DIR\suspicious_$TIMESTAMP.txt"

# OpenSSH sshd_config path (used in SSH hardening steps)
$sshdConf = $null
foreach ($p in @("C:\ProgramData\ssh\sshd_config","$env:ProgramData\ssh\sshd_config")) {
    if (Test-Path $p) { $sshdConf = $p; break }
}

if ($UNDO) { Invoke-Undo; exit 0 }

# -----------------------------
# Step 1: User/Admin Audit
# -----------------------------
Write-Host "=== Step 1/18: User/Admin Audit ==="
if ($FORENSIC) {
    Write-Host "[INFO] Forensic mode: user/admin audit skipped (no prompts, no comparisons)"
    Write-Forensics "[INFO] User/Admin audit skipped in forensic mode"
    $admins_list = @()
    $users_list = @()
    $admin_passwords = @{}
    $allAuthorized = @()
} else {
$tmpFile = "$env:TEMP\authorized_users.txt"
@"
# Authorized Administrators:
# admin1
# password: <password from README>
# admin2
# password: <password from README>
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

$adminNames = @()
try { $adminNames = @(Get-LocalGroupMember -Group 'Administrators' -EA Stop | ForEach-Object { $_.Name -replace '^.*\\','' }) } catch {}
foreach ($u in $foundUsers){
    Write-Forensics "[USER AUDIT] User: $($u.Name), Enabled: $($u.Enabled), Admin: $($adminNames -contains $u.Name)"
    if (-not ($allAuthorized -contains $u.Name)){
        Write-Forensics "[ALERT] Unauthorized user found: $($u.Name)"
        if (-not $DRYRUN){
            $choice = Read-Host "Remove user $($u.Name)? PERMANENT, --undo cannot bring it back [y/N]"
            if ($choice -match "^[Yy]$") {
                Write-Normal "[USER] Pre-removal record: Name=$($u.Name) SID=$($u.SID) Enabled=$($u.Enabled) Description=$($u.Description)"
                Remove-LocalUser -Name $u.Name
                Write-Normal "[USER] Removed unauthorized user $($u.Name)"
            }
        }
    }
}
} # end else ($FORENSIC)

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
        Add-Journal @{ type='user'; name='Guest'; wasEnabled=[bool]$guest.Enabled }
        Disable-LocalUser -Name "Guest"
        Write-Normal "[USER] Guest account disabled"
    }
    Write-Forensics "[USER AUDIT] Guest account exists"
}

# -----------------------------
# Step 4: Account Lockout Policy
# -----------------------------
Write-Host "=== Step 4/18: Account Lockout Policy ==="
if ($MAKE_CHANGES){
    $acc = (net accounts 2>$null | Out-String)
    $th = $null; $du = $null; $wi = $null
    if ($acc -match '(?im)^\s*Lockout threshold[^:]*:\s*(\S+)')         { $raw = $Matches[1]; $th = if ($raw -match '^\d+$') { $raw } else { '0' } }
    if ($acc -match '(?im)^\s*Lockout duration[^:]*:\s*(\d+)')           { $du = $Matches[1] }
    if ($acc -match '(?im)^\s*Lockout observation window[^:]*:\s*(\d+)') { $wi = $Matches[1] }
    if ($null -ne $th -and $null -ne $du -and $null -ne $wi) {
        Add-Journal @{ type='lockout'; name='lockout'; threshold=$th; duration=$du; window=$wi }
    } else { Write-Warn "[UNDO] Could not read current lockout policy (non-English Windows?); change will not be undoable" }
    net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
}
Write-Forensics "Checked/enforced account lockout policy"

# -----------------------------
# Step 5: Local Audit Policy
# -----------------------------
Write-Host "=== Step 5/18: Local Audit Policy ==="
if ($MAKE_CHANGES){
    $apFile = Join-Path $BACKUP_DIR 'auditpol-backup.csv'
    auditpol /backup /file:"$apFile" | Out-Null
    if (Test-Path $apFile) { Add-Journal @{ type='auditpol'; name='auditpol'; file=$apFile } }
    auditpol /set /category:* /success:enable /failure:enable
}
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
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' $key ($SecOpts[$key])
    Write-Forensics "Security option $key checked/applied"
}

# -----------------------------
# Step 7: Firewall
# -----------------------------
Write-Host "=== Step 7/18: Firewall Configuration ==="
if ($MAKE_CHANGES){
    Get-NetFirewallProfile -Profile Domain,Private,Public | ForEach-Object {
        Add-Journal @{ type='fwprofile'; name=[string]$_.Name; enabled=[string]$_.Enabled; inbound=[string]$_.DefaultInboundAction; outbound=[string]$_.DefaultOutboundAction }
    }
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Normal "[FIREWALL] Firewall configured"
}
Write-Forensics "Firewall status checked"

# -----------------------------
# Step 8: Windows Update
# -----------------------------
Write-Host "=== Step 8/18: Windows Update ==="
if ($MAKE_CHANGES){
    $wuSettings = New-Object -ComObject 'Microsoft.Update.AutoUpdate'
    Add-Journal @{ type='wu'; name='wu'; level=[int]$wuSettings.Settings.NotificationLevel }
    $wuSettings.Settings.NotificationLevel = 4
    $wuSettings.Settings.Save()
    Write-Normal "[UPDATE] Windows Update configured"
}
Write-Forensics "Windows Update status checked"

# -----------------------------
# Step 9: Services Hardening
# -----------------------------
Write-Host "=== Step 9/18: Services Hardening ==="
# TermService (RDP) is NOT disabled by default: the port audit below expects 3389, and
# disabling it on a remotely managed box locks you out. Opt in with --disable-rdp.
$ServicesToDisable=@('FTPSVC','Spooler','RemoteRegistry')
if ($DISABLERDP) { $ServicesToDisable += 'TermService' }
else { Write-Forensics "[INFO] TermService (RDP) left alone; pass --disable-rdp to disable it" }
foreach ($svc in $ServicesToDisable){
    Write-Forensics "Service $svc checked"
    Disable-SvcJournaled $svc
}

# -----------------------------
# Step 10: Windows Features Hardening
# -----------------------------
Write-Host "=== Step 10/18: Windows Features ==="
$FeaturesToDisable=@('TelnetClient','SMB1Protocol','WindowsMediaPlayer','IIS-WebServerRole')
foreach ($f in $FeaturesToDisable){
    $feat = Get-WindowsOptionalFeature -Online -FeatureName $f -EA SilentlyContinue
    if (-not $feat) { Write-Forensics "Feature $f not available on this edition"; continue }
    Write-Forensics "Feature $f state=$($feat.State)"
    if ($MAKE_CHANGES -and $feat.State -eq 'Enabled') {
        Add-Journal @{ type='feature'; name=$f }
        Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart | Out-Null
        Write-Normal "[FEATURE] $f disabled"
    }
}

# -----------------------------
# Step 11: Event Logs & Scheduled Tasks
# -----------------------------
Write-Host "=== Step 11/18: Event Logs & Scheduled Tasks ==="
if ($MAKE_CHANGES){
    # Always archive the key logs first: clearing them destroys evidence.
    $evtDir = Join-Path $BACKUP_DIR 'eventlogs'
    New-Item -ItemType Directory -Path $evtDir -Force | Out-Null
    foreach ($ch in @('Security','System','Application','Windows PowerShell','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-Sysmon/Operational')) {
        $evtFile = Join-Path $evtDir (($ch -replace '[\\/ ]','_') + '.evtx')
        wevtutil epl "$ch" "$evtFile" 2>$null
        if (Test-Path $evtFile) { Write-Normal "[EVENTS] Archived $ch -> $evtFile" }
    }
    if ($CLEARLOGS) {
        wevtutil el | ForEach-Object { wevtutil cl $_ 2>$null }
        Write-Normal "[EVENTS] Cleared all event logs (archives in $evtDir; NOT undoable)"
    } else {
        Write-Normal "[EVENTS] Logs archived, not cleared (pass --clear-logs to clear)"
    }
}
# Third-party scheduled tasks are no longer bulk-disabled (that broke legitimate software).
# They are inventoried and flagged in R5-C below.
Write-Forensics "Event logs archived; scheduled tasks audited in R5-C"

# -----------------------------
# ------------------------------
# Step 12: Suspicious File Scan
# ------------------------------
Write-Host "=== Step 12/18: Suspicious File Scan ==="

# Polyglot / masquerading detection: check first line for shebang mismatch
function Test-Polyglot {
    param([string]$FilePath)
    try {
        $firstLine = (Get-Content -Path $FilePath -TotalCount 1 -ErrorAction Stop)
        if ($firstLine -match '^#!') {
            $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
            $shebang = $firstLine.ToLower()
            # Map extensions to expected shebangs
            $extToShebang = @{
                '.pl' = 'perl'
                '.py' = 'python'
                '.sh' = 'bash|sh'
                '.rb' = 'ruby'
                '.php' = 'php'
            }
            if ($extToShebang.ContainsKey($ext)) {
                $expected = $extToShebang[$ext]
                if ($shebang -notmatch $expected) {
                    return "POLYGLOT: extension $ext but shebang says: $firstLine"
                }
            }
            # Also flag any shebang in non-script extensions
            $scriptExts = @('.pl','.py','.sh','.rb','.php','.ps1','.bat')
            if ($ext -notin $scriptExts -and $shebang -match 'bash|sh|perl|python|ruby|php|cmd|powershell') {
                return "POLYGLOT: non-script extension but shebang present: $firstLine"
            }
        }
    } catch { }
    return $null
}

$SuspiciousFiles = Get-ChildItem -Path 'C:\Users','C:\ProgramData' -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
    # Only files, not directories
    -not $_.PSIsContainer -and (
        # Script extensions
        $_.Extension -match '\.ps1|\.bat|\.exe|\.pl|\.py|\.sh|\.rb|\.php' -or
        # Hidden files that are ALSO executable or have script shebang
        ($_.Attributes -match 'Hidden' -and (
            $_.Extension -match '\.exe|\.dll|\.ps1|\.bat|\.cmd|\.vbs|\.js|\.wsf' -or
            (Test-Polyglot $_.FullName)
        ))
    )
}

foreach ($f in $SuspiciousFiles){
    $reasons=@()

    # Check for polyglot/masquerading
    $polyglotReason = Test-Polyglot $f.FullName
    if ($polyglotReason) { $reasons += $polyglotReason }

    # Extension-based flags
    if ($f.Extension -match '\.ps1|\.bat|\.exe|\.pl|\.py|\.sh|\.rb|\.php'){ 
        $reasons += "Suspicious extension ($($f.Extension))" 
    }

    # Hidden + executable (not just hidden alone)
    if ($f.Attributes -match 'Hidden' -and $f.Extension -match '\.exe|\.dll|\.ps1|\.bat|\.cmd'){ 
        $reasons += "Hidden executable" 
    }

    if ($reasons.Count -gt 0) {
        $reasonStr = ($reasons -join '; ')
        Write-Forensics "[SUSPICIOUS] $($f.FullName) - $reasonStr"
    }
}


# -----------------------------
# Step 13: Backup User Files
# -----------------------------
Write-Host "=== Step 13/18: Backing up User Files ==="
if ($MAKE_CHANGES){
    Get-ChildItem -Path C:\Users -Recurse -Force -File -EA SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\AppData\\' -and $_.Length -lt 100MB } |
        ForEach-Object { $null = Backup-File $_.FullName -Quiet }
    Write-Normal "[BACKUP] C:\Users files (excluding AppData and files over 100MB) copied to $BACKUP_DIR"
}
Write-Forensics "User files backup checked"

# -----------------------------
# Step 14: VirusTotal Scan
# -----------------------------
Write-Host "=== Step 14/18: VirusTotal Scan ==="
$vtList = @($SuspiciousFiles | Where-Object { $_ })
if (-not $DRYRUN -and $vtList.Count -gt 0){
    if (-not $VT_API_KEY){ $VT_API_KEY = $env:VT_API_KEY }
    if (-not $VT_API_KEY){ $VT_API_KEY = Read-Host "Enter VirusTotal API key (blank to skip lookups)" }
    $vtMax = 40; $vtDone = 0
    foreach ($f in $vtList){
        if ($vtDone -ge $vtMax) { Write-Forensics "[VT] Capped at $vtMax lookups ($($vtList.Count) candidates)"; break }
        try { $sha256 = (Get-FileHash $f.FullName -Algorithm SHA256 -EA Stop).Hash }
        catch { Write-Forensics "[ERROR] Failed to hash $($f.FullName)"; continue }
        Write-Forensics "[VT SCAN] $($f.FullName) SHA256=$sha256"
        if (-not $VT_API_KEY) { continue }
        $vtDone++
        try {
            $r  = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$sha256" -Headers @{ 'x-apikey' = $VT_API_KEY } -Method Get -EA Stop
            $st = $r.data.attributes.last_analysis_stats
            Write-Forensics "[VT RESULT] $($f.FullName) malicious=$($st.malicious) suspicious=$($st.suspicious) harmless=$($st.harmless) undetected=$($st.undetected)"
            if ($st.malicious -gt 0) { Write-Alert "VirusTotal: $($f.FullName) flagged malicious by $($st.malicious) engines" }
        } catch {
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if     ($code -eq 404) { Write-Forensics "[VT RESULT] $($f.FullName) not known to VirusTotal" }
            elseif ($code -eq 429) { Write-Warn "[VT] Rate limited, waiting 60s"; Start-Sleep -Seconds 60 }
            else                   { Write-Forensics "[ERROR] VT lookup failed for $($f.FullName): $($_.Exception.Message)" }
        }
        Start-Sleep -Seconds 16   # free tier allows 4 requests/minute
    }
}

# -----------------------------
# Step 15: Extra MSCT Hardening
# -----------------------------
Write-Host "=== Step 15/18: Extra Hardening ==="
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'EnableSecuritySignature' 1
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' 'WriteProtect' 1
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
    if ($MAKE_CHANGES){
        $httpdConf = "C:\Apache24\conf\httpd.conf"
        if (Test-Path $httpdConf){
            Backup-Config $httpdConf
            (Get-Content $httpdConf) -replace 'Options Indexes','Options -Indexes' | Set-Content $httpdConf
            (Get-Content $httpdConf) -replace 'ServerTokens OS','ServerTokens Prod' | Set-Content $httpdConf
            (Get-Content $httpdConf) -replace 'ServerSignature On','ServerSignature Off' | Set-Content $httpdConf
            Restart-Service $apacheSvc.Name -ErrorAction SilentlyContinue
            Write-Normal "[APACHE] Hardened httpd.conf and restarted"
        }
    }
}

# MySQL
$mysqlSvc = Get-Service | Where-Object {$_.Name -match "MySQL|mysqld"}
if ($mysqlSvc){
    Write-Forensics "Detected MySQL service"
    if ($MAKE_CHANGES){
        $mysqlExe = (Get-Command mysql.exe -EA SilentlyContinue).Source
        if (-not $mysqlExe) { $mysqlExe = Get-ChildItem "C:\Program Files\MySQL\MySQL Server *\bin\mysql.exe" -EA SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName }
        if (-not $mysqlExe) { Write-Warn "[MYSQL] mysql.exe not found; skipping MySQL hardening" }
        else {
            # Old code logged in with the NEW password before setting it, put the password on the
            # command line, wrote it to a temp .sql file, and used '<' (a PowerShell parse error
            # that stopped the entire script from running).
            $curPass   = Read-Host "Current MySQL root password (blank if none)" -AsSecureString
            $newPass   = Read-Host "New strong MySQL root password" -AsSecureString
            $curPlain  = [System.Net.NetworkCredential]::new("", $curPass).Password
            $plainPass = [System.Net.NetworkCredential]::new("", $newPass).Password
            $sqlPass   = $plainPass.Replace('\','\\').Replace("'","''")
            $sqlCmds = @"
ALTER USER 'root'@'localhost' IDENTIFIED BY '$sqlPass';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db LIKE 'test\_%';
FLUSH PRIVILEGES;
"@
            $env:MYSQL_PWD = $curPlain
            try { $sqlCmds | & $mysqlExe -u root } finally { Remove-Item Env:MYSQL_PWD -EA SilentlyContinue }
            Write-Normal "[MYSQL] Root password changed, anonymous/test DB removed (NOT undoable)"
        }
    }
}


# ============================================================
# [R1-A] TCP/IP STACK HARDENING
# Windows: Tcpip registry params + ASLR MoveImages + WDigest
# ============================================================
Write-Host "--- [R1-A] TCP/IP Stack Hardening ---" -ForegroundColor Magenta
$tcpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
Set-Reg $tcpPath "IPEnableRouter"          0   # disable IP forwarding
Set-Reg $tcpPath "SynAttackProtect"        2   # SYN flood protection (tcp_syncookies equiv)
Set-Reg $tcpPath "TcpMaxPortsExhausted"    5
Set-Reg $tcpPath "TcpMaxHalfOpen"          100
Set-Reg $tcpPath "TcpMaxHalfOpenRetried"   80
Set-Reg $tcpPath "DisableIPSourceRouting"  2   # accept_source_route = 0
Set-Reg $tcpPath "EnableICMPRedirect"      0   # accept_redirects = 0
Set-Reg $tcpPath "EnableDeadGWDetect"      0
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting" 2
# ASLR (randomize_va_space = 2 equiv)
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "MoveImages" 1
# DEP must not be disabled (suid_dumpable = 0 equiv)
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" 0
# Disable WDigest plaintext creds in memory (ptrace_scope equiv)
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" 0
Write-Forensics "[R1-A] TCP/IP stack hardening applied"

# ============================================================
# [R1-B] BOOT HARDENING
# Windows: bcdedit timeout=5, recoveryenabled=No, nx=OptIn
# ============================================================
Write-Host "--- [R1-B] Boot Hardening ---" -ForegroundColor Magenta
if ($MAKE_CHANGES) {
    $bcdFile = Join-Path $BACKUP_DIR 'bcd-export.bak'
    bcdedit /export "$bcdFile" 2>&1 | Out-Null
    if (Test-Path $bcdFile) { Add-Journal @{ type='bcd'; name='bcd'; file=$bcdFile } }
    $r1 = bcdedit /timeout 5 2>&1
    $r2 = bcdedit /set "{default}" recoveryenabled No 2>&1
    $r3 = bcdedit /set "{default}" nx OptIn 2>&1
    Write-Normal "[BOOT] bcdedit timeout: $r1"
    Write-Normal "[BOOT] bcdedit recovery: $r2"
    Write-Normal "[BOOT] bcdedit nx: $r3"
}
Write-Forensics "[R1-B] Boot hardening applied"

# ============================================================
# [R2-A] DISABLE USB STORAGE
# Windows: USBSTOR Start=4 (driver disabled)
# ============================================================
Write-Host "--- [R2-A] Disable USB Storage ---" -ForegroundColor Magenta
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" "Start" 4
Write-Normal "[USB] USBSTOR Start=4 (driver disabled)"
Write-Forensics "[R2-A] USB storage disabled"

# ============================================================
# [R2-B] DISABLE CRASH DUMPS
# Windows: CrashDumpEnabled=0, WER disabled
# ============================================================
Write-Host "--- [R2-B] Disable Crash Dumps ---" -ForegroundColor Magenta
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" 1
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"      "CrashDumpEnabled" 0
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"      "AutoReboot" 1
Disable-SvcJournaled "WerSvc"
Write-Forensics "[R2-B] Crash dumps disabled"

# ============================================================
# [R2-C] FIREWALL ALLOW-LIST (TCP Wrappers equivalent)
# Windows: log Public inbound ALLOW rules; ensure SSH explicitly allowed
# ============================================================
Write-Host "--- [R2-C] Firewall Allow-List Review ---" -ForegroundColor Magenta
Get-NetFirewallRule -Direction Inbound -Action Allow -EA SilentlyContinue |
    Where-Object { $_.Profile -match "Public" -and $_.DisplayName -notlike "BEAST*" } |
    ForEach-Object { Write-Forensics "[FW RULE] Public inbound ALLOW: $($_.DisplayName)" }
if ($MAKE_CHANGES) {
    if (Get-Service -Name sshd -EA SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName "BEAST-Allow-SSH" -EA SilentlyContinue
        New-NetFirewallRule -DisplayName "BEAST-Allow-SSH" -Direction Inbound `
            -Protocol TCP -LocalPort 22 -Action Allow -Profile Any -EA SilentlyContinue | Out-Null
        Add-Journal @{ type='fwrule'; name='BEAST-Allow-SSH' }
        Write-Normal "[TCPWRAP] SSH explicitly allowed; all other Public inbound logged"
    } else {
        Write-Normal "[TCPWRAP] sshd not installed: no SSH allow rule added (port 22 stays closed)"
    }
}
Write-Forensics "[R2-C] Firewall allow-list reviewed"

# ============================================================
# [R3-A] EMPTY PASSWORD CHECK
# Windows: Get-LocalUser PasswordRequired=$false + disable
# ============================================================
Write-Host "--- [R3-A] Empty Password Check ---" -ForegroundColor Magenta
$emptyFound = $false
Get-LocalUser | Where-Object { $_.Enabled -and (-not $_.PasswordRequired) } | ForEach-Object {
    Write-Alert "No password required for account: $($_.Name)"
    $emptyFound = $true
    if ($MAKE_CHANGES) {
        Add-Journal @{ type='userexp'; name=$_.Name; old=[bool]$_.PasswordNeverExpires }
        $_ | Set-LocalUser -PasswordNeverExpires $false -UserMayChangePassword $true -EA SilentlyContinue
        if ($allAuthorized -notcontains $_.Name) {
            Add-Journal @{ type='user'; name=$_.Name; wasEnabled=$true }
            Disable-LocalUser -Name $_.Name -EA SilentlyContinue
            Write-Normal "[LOCKED] Disabled no-password account: $($_.Name)"
        }
    }
}
if (-not $emptyFound) { Write-Normal "[OK] No accounts with missing password requirement" }

# ============================================================
# [R3-B] AUTO SECURITY UPDATES
# Windows: WindowsUpdate policy registry
# ============================================================
Write-Host "--- [R3-B] Automatic Security Updates ---" -ForegroundColor Magenta
$wuPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
Set-Reg $wuPol "DisableWindowsUpdateAccess" 0
Set-Reg ($wuPol + "\AU") "NoAutoUpdate"    0
Set-Reg ($wuPol + "\AU") "AUOptions"       4
Write-Forensics "[R3-B] Auto security updates enforced"

# ============================================================
# [R3-C] ADMIN GROUP / NOPASSWD AUDIT
# Windows: list Administrators group + PasswordNeverExpires accounts
# ============================================================
Write-Host "--- [R3-C] Admin Group Audit ---" -ForegroundColor Magenta
try {
    (Get-LocalGroupMember -Group "Administrators" -EA Stop) | ForEach-Object {
        Write-Alert "Admin group member: $($_.Name)  Type=$($_.ObjectClass)"
        Write-Forensics "[ADMIN MEMBER] $($_.Name)  Type=$($_.ObjectClass)"
    }
} catch { Write-Warn "Could not enumerate Administrators group" }
Get-LocalUser | Where-Object { $_.PasswordNeverExpires -and $_.Enabled } | ForEach-Object {
    Write-Alert "PasswordNeverExpires account: $($_.Name)"
    Write-Forensics "[NOEXPIRY] $($_.Name)  PasswordNeverExpires=True"
}

# ============================================================
# [R4-A] LISTENING PORT AUDIT
# Windows: Get-NetTCPConnection -State Listen
# ============================================================
Write-Host "--- [R4-A] Listening Port Audit ---" -ForegroundColor Magenta
$expectedPorts = @(22, 3389)
Get-NetTCPConnection -State Listen -EA SilentlyContinue | ForEach-Object {
    $port = $_.LocalPort
    $proc = (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name
    Write-Forensics "[PORT] $($_.LocalAddress):$port  PID=$($_.OwningProcess)  Process=$proc"
    if ($expectedPorts -notcontains $port) {
        Write-Alert "Unexpected listening port: $($_.LocalAddress):$port ($proc)"
    }
}
Write-Normal "[PORTS] Port audit complete"

# ============================================================
# [R4-B] ANTIVIRUS SCAN
# Windows: Windows Defender Update-MpSignature + Start-MpScan
# ============================================================
Write-Host "--- [R4-B] Antivirus Scan (Defender) ---" -ForegroundColor Magenta
if ($MAKE_CHANGES) {
    $mp = Get-MpComputerStatus -EA SilentlyContinue
    if ($mp) {
        Write-Forensics "[DEFENDER] RealTime=$($mp.RealTimeProtectionEnabled)  AVEnabled=$($mp.AntivirusEnabled)"
        Add-Journal @{ type='mp'; name='defender-realtime'; disableRealtime=(-not [bool]$mp.RealTimeProtectionEnabled) }
        Set-MpPreference -DisableRealtimeMonitoring $false -EA SilentlyContinue
        Write-Normal "[DEFENDER] Updating signatures..."
        Update-MpSignature -EA SilentlyContinue
        Start-MpScan -ScanType QuickScan -EA SilentlyContinue
        foreach ($sp in @("C:\Users","C:\Temp","C:\Windows\Temp","C:\ProgramData")) {
            if (Test-Path $sp) { Start-MpScan -ScanType CustomScan -ScanPath $sp -EA SilentlyContinue }
        }
        Get-MpThreat -EA SilentlyContinue | ForEach-Object {
            Write-Alert "DEFENDER THREAT: $($_.ThreatName)  Resources=$($_.Resources)"
        }
        Write-Normal "[DEFENDER] Scan complete"
    } else { Write-Warn "Windows Defender not available" }
}
Write-Forensics "[R4-B] AV scan complete"

# ============================================================
# [R4-C] DISABLE IPv6
# Windows: DisabledComponents=0xFF + Disable-NetAdapterBinding ms_tcpip6
# ============================================================
Write-Host "--- [R4-C] Disable IPv6 ---" -ForegroundColor Magenta
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" 0xFF
if ($MAKE_CHANGES) {
    Get-NetAdapter -EA SilentlyContinue | ForEach-Object {
        $b = Get-NetAdapterBinding -Name $_.Name -ComponentID "ms_tcpip6" -EA SilentlyContinue
        if ($b -and $b.Enabled) {
            Add-Journal @{ type='ipv6'; name=[string]$_.Name }
            Disable-NetAdapterBinding -Name $_.Name -ComponentID "ms_tcpip6" -EA SilentlyContinue
            Write-Normal "[IPv6] Disabled on: $($_.Name)"
        }
    }
}
Write-Forensics "[R4-C] IPv6 disabled"

# ============================================================
# [R5-A] FULL SSH HARDENING
# Windows: OpenSSH sshd_config full pass + login banner
# ============================================================
Write-Host "--- [R5-A] Full SSH Hardening ---" -ForegroundColor Magenta
if ($sshdConf -and $MAKE_CHANGES) {
    Backup-Config $sshdConf
    $content = Get-Content $sshdConf
    $sshdSettings = @{
        "PermitRootLogin"         = "no"
        "PermitEmptyPasswords"    = "no"
        "MaxAuthTries"            = "3"
        "LoginGraceTime"          = "30"
        "AllowTcpForwarding"      = "no"
        "X11Forwarding"           = "no"
        "ClientAliveInterval"     = "300"
        "ClientAliveCountMax"     = "2"
        "IgnoreRhosts"            = "yes"
        "HostbasedAuthentication" = "no"
        "PrintLastLog"            = "yes"
    }
    foreach ($key in $sshdSettings.Keys) {
        $val = $sshdSettings[$key]
        if ($content -match "^#?\s*$key\s") {
            $content = $content -replace "^#?\s*$key.*", "$key $val"
        } else { $content += "$key $val" }
    }
    $bannerFile = "C:\ProgramData\ssh\beast_banner.txt"
    if (-not (Test-Path $bannerFile)) { Add-Journal @{ type='newfile'; name='beast_banner'; path=$bannerFile } }
    "Authorized access only. All activity is monitored and logged." | Set-Content $bannerFile -EA SilentlyContinue
    if ($content -match "^#?\s*Banner\s") {
        $content = $content -replace "^#?\s*Banner.*", "Banner $bannerFile"
    } else { $content += "Banner $bannerFile" }
    $content | Set-Content $sshdConf
    Restart-Service sshd -EA SilentlyContinue
    Write-Normal "[SSH] sshd_config hardened and banner added"
} elseif (-not $sshdConf) { Write-Warn "[SSH] sshd_config not found - OpenSSH may not be installed" }
Write-Forensics "[R5-A] Full SSH hardening complete"

# ============================================================
# [R5-B] LOGIN BANNER
# Windows: LegalNoticeCaption + LegalNoticeText registry
# ============================================================
Write-Host "--- [R5-B] Login Banner ---" -ForegroundColor Magenta
$banner = "Authorized access only. All activity is monitored and logged. Unauthorized access is prohibited."
$polPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-Reg $polPath "LegalNoticeCaption" "AUTHORIZED ACCESS ONLY" "String"
Set-Reg $polPath "LegalNoticeText"    $banner                   "String"
Write-Forensics "[R5-B] Login banner set"

# ============================================================
# [R5-C] SCHEDULED TASKS AUDIT (Cron equivalent)
# Windows: Get-ScheduledTask full inventory + flag interpreter tasks
# ============================================================
Write-Host "--- [R5-C] Scheduled Tasks Audit ---" -ForegroundColor Magenta
Write-Forensics "[SCHED AUDIT] $(Get-Date)"
Get-ScheduledTask | ForEach-Object {
    $t = $_
    $acts = ($t.Actions | ForEach-Object { ($_.Execute + " " + $_.Arguments).Trim() }) -join " ; "
    $trigs = ($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ","
    $line = "[SCHED] $($t.TaskPath)$($t.TaskName)  State=$($t.State)  Triggers=$trigs  Actions=$acts"
    Write-Forensics $line
    if ($acts -match "powershell|wscript|cscript|cmd\.exe|mshta|regsvr32" -and
        $t.TaskPath -notlike "\Microsoft\*") {
        Write-Alert "Non-MS scheduled task runs interpreter: $($t.TaskName) -> $acts"
    }
}
Write-Normal "[R5-C] Scheduled task audit complete"

Write-Host "[INFO] 18-step hardening & forensics complete"
Write-Forensics "[INFO] Script completed"
PSEOF
if command -v cygpath >/dev/null 2>&1; then PS_WIN="$(cygpath -w "$PS_TMP")"; else PS_WIN="$PS_TMP"; fi
powershell -NoProfile -ExecutionPolicy Bypass -File "$PS_WIN" "${PS_ARGS[@]}"
PS_RC=$?
rm -f "$PS_TMP"
exit $PS_RC   # never fall through into the Linux section on Windows
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
BACKUP_DIR="$PWD/cp-backups/$TIMESTAMP"
UNDO_JOURNAL="$PWD/cp-backups/undo-journal.txt"
mkdir -p "$LOG_DIR" "$BACKUP_DIR"
LOG="$LOG_DIR/hardening_$TIMESTAMP.log"
ERR="$LOG_DIR/errors_$TIMESTAMP.log"
FORENSICS_LOG="$LOG_DIR/forensics_$TIMESTAMP.log"
SUSPICIOUS_OUTPUT="$LOG_DIR/suspicious_files_$TIMESTAMP.txt"

#exec > >(tee -i "$LOG") 2> >(tee -a "$ERR" >&2)

RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; CYAN="\e[36m"; RESET="\e[0m"

# --------------------
# Process CLI Arguments
# --------------------
BENCH=true
BENCH_ONLY=false
DISABLE_RECOVERY=false
for arg in "$@"; do
    [[ "$arg" == "--disable-recovery" ]] && DISABLE_RECOVERY=true
    [[ "$arg" == "--no-benchmark" ]] && BENCH=false
    [[ "$arg" == "--benchmark-only" ]] && BENCH_ONLY=true
    [[ "$arg" == "--dry-run" ]] && DRYRUN=true
    [[ "$arg" =~ --forensic|--forensics ]] && MODE="forensic"
    [[ "$arg" == "--undo" ]] && UNDO=true
done

$BENCH_ONLY && BENCH=true

# Master gate: skip any action that changes files/system state whenever
# running in forensic mode or dry-run mode.
SKIP_CHANGES=false
[[ "$DRYRUN" == true || "$MODE" == "forensic" ]] && SKIP_CHANGES=true

# --------------------
# Undo Functionality
# --------------------
REMOVED_USERS=()
# Persistent journal (tab separated), one line per change, so --undo works from a LATER run.
# (The old version kept its state in bash arrays, which are gone when the process exits,
# so --undo restored nothing.)
journal() { $SKIP_CHANGES && return 0; local IFS=$'\t'; printf '%s\n' "$*" >> "$UNDO_JOURNAL"; }
backup_file() {
    local src="$1" dst
    dst="$BACKUP_DIR/$(echo "${src#/}" | tr '/' '_').bak"   # full path in the name: no basename collisions
    [[ -e "$dst" ]] && return 0                             # keep the FIRST (pre-change) copy
    if [[ -f "$src" ]]; then
        sudo cp -p "$src" "$dst" && journal file "$src" "$dst"
    else
        journal newfile "$src"                              # did not exist before: undo deletes it
    fi
}
undo_script() {
    echo -e "${YELLOW}UNDO MODE: replaying $UNDO_JOURNAL in reverse...${RESET}"
    if [[ ! -s "$UNDO_JOURNAL" ]]; then
        echo -e "${RED}No journal at $UNDO_JOURNAL. Run --undo from the directory the script was run in.${RESET}"
        exit 1
    fi
    while IFS=$'\t' read -r -u 3 kind a b c; do
        case "$kind" in
            file)    sudo cp -p "$b" "$a" && echo "[UNDO] restored $a" ;;
            newfile) sudo rm -f "$a" && echo "[UNDO] removed $a" ;;
            mask)    sudo systemctl unmask "$a" && echo "[UNDO] unmasked $a" ;;
            svc)     [[ "$b" == enabled ]] && sudo systemctl enable "$a"
                     [[ "$c" == active ]]  && sudo systemctl start "$a"
                     echo "[UNDO] service $a (enabled=$b active=$c)" ;;
            user)    sudo adduser --disabled-password --gecos "" "$a" \
                         && echo "[UNDO] re-created $a with a locked password; home archive (if any) in $b" ;;
        esac
    done 3< <(tac "$UNDO_JOURNAL")
    sudo sysctl --system >/dev/null 2>&1
    grep -q "/etc/default/grub" "$UNDO_JOURNAL" && sudo update-grub 2>/dev/null
    for svc in ssh sshd; do sudo systemctl reload "$svc" 2>/dev/null && break; done
    sudo mv "$UNDO_JOURNAL" "$UNDO_JOURNAL.undone-$(date +%s)"
    echo -e "${GREEN}UNDO COMPLETE${RESET} (not reversed: apt installs/upgrades, ufw rules, password aging, account locks)"
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

##########################
# [0/18] BENCHMARK: read-only security baseline (runs before ANY change)
##########################
BENCH_PRE="$LOG_DIR/benchmark_pre_$TIMESTAMP.txt"
BENCH_POST="$LOG_DIR/benchmark_post_$TIMESTAMP.txt"
BENCH_REPORT="$LOG_DIR/benchmark_report_$TIMESTAMP.txt"

# Run command with privilege, never prompt. rc 126 = no privilege available.
_bench_priv() {
    if [[ $EUID -eq 0 ]]; then "$@"
    elif sudo -n true 2>/dev/null; then sudo -n "$@"
    else return 126
    fi
}

_B_OUT=""; _B_PASS=0; _B_FAIL=0; _B_SKIP=0; BENCH_PCT=0

# _rec <id> <description> <rc>   rc: 0=pass, 1=fail, anything else=skip
_rec() {
    local st
    case "$3" in
        0) st=PASS; ((_B_PASS++)) ;;
        1) st=FAIL; ((_B_FAIL++)) ;;
        *) st=SKIP; ((_B_SKIP++)) ;;
    esac
    echo "$st|$1|$2" >> "$_B_OUT"
    case "$st" in
        PASS) echo -e "  ${GREEN}[PASS]${RESET} $1 $2" ;;
        FAIL) echo -e "  ${RED}[FAIL]${RESET} $1 $2" ;;
        *)    echo -e "  ${YELLOW}[SKIP]${RESET} $1 $2" ;;
    esac
}

_b_sysctl() {  # id key expected
    local v; v=$(sysctl -n "$2" 2>/dev/null)
    [[ -z "$v" ]] && { _rec "$1" "sysctl $2 = $3 (not available)" 2; return; }
    [[ "$v" == "$3" ]]; _rec "$1" "sysctl $2 = $3 (is $v)" $?
}

_SSHD_T=""
_b_sshd_load() { _SSHD_T=$(_bench_priv sshd -T 2>/dev/null | tr 'A-Z' 'a-z'); }
_b_sshd() {  # id key expected-regex
    local k="${2,,}" v=""
    if [[ -n "$_SSHD_T" ]]; then
        v=$(awk -v k="$k" '$1==k{print $2; exit}' <<< "$_SSHD_T")
    elif [[ -r "$SSHD" ]]; then
        v=$(awk -v k="$k" 'tolower($1)==k{v=tolower($2)} END{print v}' "$SSHD")
    fi
    [[ -z "$v" ]] && { _rec "$1" "sshd $2 (not determinable)" 2; return; }
    [[ "$v" =~ ^($3)$ ]]; _rec "$1" "sshd $2 matches $3 (is $v)" $?
}

_unit_exists() { systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1\.service"; }
_b_svc_off() {  # id unit
    if ! _unit_exists "$2"; then _rec "$1" "service $2 not installed" 0; return; fi
    if systemctl is-active --quiet "$2" || systemctl is-enabled --quiet "$2" 2>/dev/null; then
        _rec "$1" "service $2 running/enabled (should be off)" 1
    else
        _rec "$1" "service $2 disabled" 0
    fi
}
_b_svc_on() {  # id unit
    if _unit_exists "$2" && systemctl is-active --quiet "$2"; then
        _rec "$1" "service $2 active" 0
    else
        _rec "$1" "service $2 not active/installed" 1
    fi
}

_b_perm() {  # id file max-octal-perm
    [[ -e "$2" ]] || { _rec "$1" "$2 missing" 2; return; }
    local p; p=$(stat -c %a "$2")
    (( (8#$p & ~8#$3) == 0 )); _rec "$1" "$2 perms <= $3 (is $p)" $?
}

run_benchmark() {  # phase outfile
    local phase="$1" out v rc t0=$SECONDS
    _B_OUT="$2"; : > "$_B_OUT"
    _B_PASS=0; _B_FAIL=0; _B_SKIP=0
    echo -e "${CYAN}--- [BENCHMARK:$phase] read-only security baseline ---${RESET}"

    # ---- Accounts ----
    out=$(_bench_priv awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null); rc=$?
    if [[ $rc -ne 0 ]]; then _rec B-ACC-01 "no empty-password accounts (need root)" 2
    elif [[ -n "$out" ]]; then _rec B-ACC-01 "empty password: $(echo $out)" 1
    else _rec B-ACC-01 "no empty-password accounts" 0; fi

    out=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd 2>/dev/null)
    [[ -z "$out" ]]; _rec B-ACC-02 "no extra UID 0 accounts${out:+ ($(echo $out))}" $?

    _bench_priv grep -rqs NOPASSWD /etc/sudoers /etc/sudoers.d; rc=$?
    case $rc in
        0) _rec B-ACC-03 "sudoers contains NOPASSWD" 1 ;;
        1) _rec B-ACC-03 "no NOPASSWD in sudoers" 0 ;;
        *) _rec B-ACC-03 "sudoers NOPASSWD check (need root)" 2 ;;
    esac

    v=$(awk '$1=="PASS_MAX_DAYS"{print $2}' /etc/login.defs 2>/dev/null)
    [[ "$v" =~ ^[0-9]+$ ]] && (( v <= 90 )); _rec B-ACC-04 "login.defs PASS_MAX_DAYS <= 90 (is ${v:-unset})" $?
    v=$(awk '$1=="PASS_MIN_DAYS"{print $2}' /etc/login.defs 2>/dev/null)
    [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 )); _rec B-ACC-05 "login.defs PASS_MIN_DAYS >= 1 (is ${v:-unset})" $?

    grep -Eqs '^[^#]*pam_(pwquality|cracklib)\.so' /etc/pam.d/common-password
    _rec B-ACC-06 "PAM password quality module enabled" $?
    grep -Eqs '^[^#]*pam_(faillock|tally2)\.so' /etc/pam.d/common-auth /etc/pam.d/common-account
    _rec B-ACC-07 "PAM account lockout module enabled" $?

    # ---- File permissions ----
    _b_perm B-FIL-01 /etc/passwd 644
    _b_perm B-FIL-02 /etc/group 644
    _b_perm B-FIL-03 /etc/shadow 640
    _b_perm B-FIL-04 /etc/gshadow 640
    out=$(find /etc /usr /bin /sbin -xdev -type f -perm -0002 2>/dev/null | head -5)
    [[ -z "$out" ]]; _rec B-FIL-05 "no world-writable files in /etc /usr /bin /sbin${out:+ (e.g. $(echo $out | cut -d' ' -f1))}" $?

    # ---- SSH ----
    _b_sshd_load
    _b_sshd B-SSH-01 PermitRootLogin "no|prohibit-password|without-password"
    _b_sshd B-SSH-02 PermitEmptyPasswords "no"
    _b_sshd B-SSH-03 MaxAuthTries "[1-4]"
    _b_sshd B-SSH-04 X11Forwarding "no"
    _b_sshd B-SSH-05 IgnoreRhosts "yes"
    _b_sshd B-SSH-06 HostbasedAuthentication "no"
    _b_sshd B-SSH-07 LoginGraceTime "([1-9]|[1-5][0-9]|60)"

    # ---- Kernel / network sysctl ----
    _b_sysctl B-SYS-01 net.ipv4.ip_forward 0
    _b_sysctl B-SYS-02 net.ipv4.tcp_syncookies 1
    _b_sysctl B-SYS-03 net.ipv4.conf.all.accept_redirects 0
    _b_sysctl B-SYS-04 net.ipv4.conf.all.accept_source_route 0
    _b_sysctl B-SYS-05 net.ipv4.conf.all.send_redirects 0
    _b_sysctl B-SYS-06 net.ipv4.conf.all.rp_filter 1
    _b_sysctl B-SYS-07 net.ipv4.conf.all.log_martians 1
    _b_sysctl B-SYS-08 net.ipv4.icmp_echo_ignore_broadcasts 1
    _b_sysctl B-SYS-09 kernel.randomize_va_space 2
    _b_sysctl B-SYS-10 kernel.sysrq 0
    _b_sysctl B-SYS-11 kernel.dmesg_restrict 1
    _b_sysctl B-SYS-12 kernel.yama.ptrace_scope 1
    _b_sysctl B-SYS-13 fs.suid_dumpable 0

    # ---- Network exposure ----
    if command -v ss >/dev/null 2>&1; then
        out=$(ss -tln 2>/dev/null | awk 'NR>1{print $4}' | grep -Ev '^(127\.|\[::1\]|::1)|:22$' | sort -u | tr '\n' ' ')
        [[ -z "${out// /}" ]]; _rec B-NET-01 "no non-loopback listeners besides :22${out:+ ($out)}" $?
    else
        _rec B-NET-01 "listener audit (ss missing)" 2
    fi
    if ! command -v ufw >/dev/null 2>&1; then
        _rec B-NET-02 "ufw installed and active" 1
    else
        out=$(_bench_priv ufw status 2>/dev/null); rc=$?
        if [[ $rc -ne 0 ]]; then _rec B-NET-02 "ufw status (need root)" 2
        elif grep -q "Status: active" <<< "$out"; then _rec B-NET-02 "ufw active" 0
        else _rec B-NET-02 "ufw installed but inactive" 1; fi
    fi

    # ---- Services ----
    if command -v systemctl >/dev/null 2>&1; then
        _b_svc_on  B-SVC-01 fail2ban
        _b_svc_on  B-SVC-02 auditd
        _b_svc_off B-SVC-03 rpcbind
        _b_svc_off B-SVC-04 cups
        _b_svc_off B-SVC-05 avahi-daemon
    else
        _rec B-SVC-00 "service checks (systemctl missing)" 2
    fi
    dpkg -s unattended-upgrades &>/dev/null; _rec B-SVC-06 "unattended-upgrades installed" $?
    ! dpkg -s telnetd &>/dev/null; _rec B-SVC-07 "telnetd not installed" $?
    ! dpkg -s rsh-server &>/dev/null; _rec B-SVC-08 "rsh-server not installed" $?

    # ---- Misc config ----
    grep -Eqs '^(install usb-storage /bin/true|blacklist usb-storage)' /etc/modprobe.d/*.conf
    _rec B-CFG-01 "usb-storage blacklisted" $?
    grep -Eqs '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf /etc/security/limits.d/*.conf
    _rec B-CFG-02 "core dumps limited (hard core 0)" $?
    [[ -s /etc/issue.net ]] && ! grep -Eqs '\\[mrsv]|Ubuntu|Debian|Linux' /etc/issue.net
    _rec B-CFG-03 "login banner set, no OS info leak (/etc/issue.net)" $?

    local tot=$((_B_PASS + _B_FAIL)) pct=0
    (( tot > 0 )) && pct=$(( _B_PASS * 100 / tot ))
    BENCH_PCT=$pct
    echo "SCORE|$_B_PASS|$_B_FAIL|$_B_SKIP|$pct" >> "$_B_OUT"
    echo -e "${CYAN}[BENCHMARK:$phase] score ${pct}% (${_B_PASS} pass, ${_B_FAIL} fail, ${_B_SKIP} skip) in $((SECONDS - t0))s, saved: $_B_OUT${RESET}"
}

compare_benchmark() {
    {
        echo "BENCHMARK REPORT - $TIMESTAMP"
        echo "Before: ${PRE_PCT}% (${PRE_PASS} pass, ${PRE_FAIL} fail, ${PRE_SKIP} skip)"
        echo "After:  ${BENCH_PCT}% (${_B_PASS} pass, ${_B_FAIL} fail, ${_B_SKIP} skip)"
        echo "Change: $((BENCH_PCT - PRE_PCT)) points"
        echo
        awk -F'|' '
            NR==FNR { if ($1!="SCORE") pre[$2]=$1; next }
            $1!="SCORE" { post[$2]=$1; d[$2]=$3 }
            END {
                for (i in post) {
                    if (pre[i]=="FAIL" && post[i]=="PASS") print "FIXED       " i " " d[i]
                    else if (pre[i]=="PASS" && post[i]=="FAIL") print "REGRESSED   " i " " d[i]
                    else if (post[i]=="FAIL") print "STILL-FAIL  " i " " d[i]
                }
            }' "$BENCH_PRE" "$BENCH_POST" | sort
    } | tee "$BENCH_REPORT" | tee -a "$FORENSICS_LOG"
}

if $BENCH; then
    run_benchmark pre "$BENCH_PRE"
    PRE_PASS=$_B_PASS; PRE_FAIL=$_B_FAIL; PRE_SKIP=$_B_SKIP; PRE_PCT=$BENCH_PCT
    echo "[BENCH] pre-hardening score ${PRE_PCT}% (${PRE_PASS} pass, ${PRE_FAIL} fail, ${PRE_SKIP} skip)" >> "$FORENSICS_LOG"
    if $BENCH_ONLY; then
        echo -e "${GREEN}BENCHMARK-ONLY: no changes made.${RESET}"
        exit 0
    fi
fi

echo -e "${YELLOW}--- Running full 18-step hardening ---${RESET}"

##########################
# Step 1: USER / ADMIN AUDIT
##########################
echo "--- [1/18] USER/AUTHORIZED ADMIN AUDIT ---"
INVOKING_USER=${SUDO_USER:-$USER}
if [[ "$MODE" == "forensic" ]]; then
    echo "[INFO] Forensic mode: user/admin audit skipped (no prompts, no comparisons)"
    declare -A ADMIN_PASSWORDS
    admins_list="$INVOKING_USER "
    users_list=""
    all_authorized="$admins_list"
else
tmp_audit=$(mktemp /tmp/user_audit.XXXX)
cat > "$tmp_audit" <<EOL
# Authorized Administrators:
# $INVOKING_USER
# admin2
# password: <password from README>
# Authorized Users:
# user1
# user2
EOL
nano "$tmp_audit"

declare -A ADMIN_PASSWORDS
users_list=""; admins_list="$INVOKING_USER "
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
# If nano exited without adding real entries, default to current invoking user only
if [[ -z "$(echo $admins_list | xargs)" || "$admins_list" == "$INVOKING_USER " ]] && [[ -z "$users_list" ]]; then
    echo "[WARN] Authorized user list empty or only invoking user - using $INVOKING_USER as sole admin"
fi

all_authorized="$admins_list $users_list"
REMOVED_USERS=()
echo -e "${YELLOW}Auditing system users...${RESET}"
for user in $(awk -F: '$3>=1000 && $3<60000 {print $1}' /etc/passwd); do
    if [[ ! " $all_authorized " =~ " $user " ]]; then
        echo "ALERT: Unauthorized user detected: $user"
        if [[ "$DRYRUN" == false ]]; then
            read -p "Remove $user? Home is archived to $BACKUP_DIR first. [y/N]: " choice
            if [[ "$choice" =~ ^[Yy]$ ]]; then
                sudo deluser --remove-home --backup --backup-to "$BACKUP_DIR" "$user" \
                    && { REMOVED_USERS+=("$user"); journal user "$user" "$BACKUP_DIR"; }
            fi
        fi
    fi
done
fi

##########################
# Step 2: ADMIN PASSWORD ENFORCEMENT
##########################
echo "--- [2/18] Admin password audit ---"
for admin in $admins_list; do
    [[ "$admin" == "$INVOKING_USER" ]] && continue
    current_hash=$(getent shadow "$admin" | cut -d: -f2)
    if [[ -z "$current_hash" || "$current_hash" == "!" || "$current_hash" == "*" ]]; then
        echo "Admin $admin has no password set!"
        if [[ "$MODE" != "forensic" && "$DRYRUN" == false ]]; then
            read -rsp "Enter new password for $admin: " new_pass; echo
            echo "$admin:$new_pass" | sudo chpasswd
        fi
    fi
done

##########################
# Step 3: SYSTEM UPDATE CHECK
##########################
echo "--- [3/18] Updating system ---"
$SKIP_CHANGES && echo "[DRY-RUN/FORENSIC] Skipping apt update/upgrade." || { sudo apt update -y && sudo apt upgrade -y; }

##########################
# Step 4: PAM/SSH HARDENING
##########################
echo "--- [4/18] PAM/SSH hardening ---"
$SKIP_CHANGES || {
    backup_file "$PAM_DIR/common-password"
    backup_file "$SSHD"
    # pam_pwquality is the maintained module (pam_cracklib is gone on current Debian/Ubuntu).
    # Installing the package wires it into common-password via pam-auth-update.
    dpkg -s libpam-pwquality &>/dev/null || sudo apt-get install -y libpam-pwquality
    PWQ=/etc/security/pwquality.conf
    backup_file "$PWQ"
    for kv in "minlen=12" "dcredit=-1" "ucredit=-1" "lcredit=-1" "ocredit=-1" "retry=3"; do
        k="${kv%%=*}"; v="${kv#*=}"
        if grep -qE "^[#[:space:]]*${k}[[:space:]]*=" "$PWQ" 2>/dev/null; then
            sudo sed -i -E "s|^[#[:space:]]*${k}[[:space:]]*=.*|${k} = ${v}|" "$PWQ"
        else
            echo "${k} = ${v}" | sudo tee -a "$PWQ" > /dev/null
        fi
    done
    # Also match an already-ACTIVE PermitRootLogin line (the old sed only touched commented ones).
    sudo sed -i -E 's|^[#[:space:]]*(PermitRootLogin)[[:space:]].*|\1 no|' "$SSHD"
}

##########################
# Step 5: FIREWALL CONFIG
##########################
echo "--- [5/18] Firewall setup ---"
$SKIP_CHANGES || {
    command -v ufw &>/dev/null || sudo apt-get install -y ufw
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    echo "y" | sudo ufw enable
}

##########################
# Step 6: FAIL2BAN
##########################
echo "--- [6/18] Fail2Ban installation/check ---"
$SKIP_CHANGES || { dpkg -s fail2ban &>/dev/null || sudo apt-get install -y fail2ban; sudo systemctl enable --now fail2ban; }

##########################
# Step 7: BACKGROUND UPDATES
##########################
echo "--- [7/18] System updates ---"
echo "[INFO] Packages already upgraded in step 3; unattended upgrades configured in R3-B"

##########################
# Step 8: ACCOUNT POLICIES
##########################
echo "--- [8/18] Password policies ---"
$SKIP_CHANGES || {
    # Was: chage on $USER, which is root under sudo. Set the defaults for new accounts and
    # apply aging to the existing human accounts instead.
    backup_file /etc/login.defs
    for kv in "PASS_MAX_DAYS 90" "PASS_MIN_DAYS 1" "PASS_WARN_AGE 7"; do
        k="${kv%% *}"; v="${kv##* }"
        if grep -qE "^[#[:space:]]*${k}[[:space:]]" /etc/login.defs; then
            sudo sed -i -E "s|^[#[:space:]]*${k}[[:space:]].*|${k}\t${v}|" /etc/login.defs
        else
            printf '%s\t%s\n' "$k" "$v" | sudo tee -a /etc/login.defs > /dev/null
        fi
    done
    while IFS=: read -r u _ uid _ _ _ shell; do
        [[ "$shell" =~ (nologin|false)$ ]] && continue
        sudo chage --maxdays 90 --mindays 1 --warndays 7 "$u"
    done < <(awk -F: '$3>=1000 && $3<60000' /etc/passwd)
}

##########################
# Step 9: ACCOUNT LOCKOUT
##########################
echo "--- [9/18] Account lockout ---"
$SKIP_CHANGES || {
    # Was: "faillock --reset" on $USER, which configures nothing. Enable real lockout through
    # pam-auth-update (the supported way to edit the common-* stacks) when the distro ships the profile.
    if [[ -f /usr/share/pam-configs/faillock ]]; then
        for f in common-auth common-account; do backup_file "$PAM_DIR/$f"; done
        FLC=/etc/security/faillock.conf
        backup_file "$FLC"
        for kv in "deny=5" "unlock_time=900" "fail_interval=900"; do
            k="${kv%%=*}"; v="${kv#*=}"
            if grep -qE "^[#[:space:]]*${k}[[:space:]]*=" "$FLC" 2>/dev/null; then
                sudo sed -i -E "s|^[#[:space:]]*${k}[[:space:]]*=.*|${k} = ${v}|" "$FLC"
            else
                echo "${k} = ${v}" | sudo tee -a "$FLC" > /dev/null
            fi
        done
        sudo DEBIAN_FRONTEND=noninteractive pam-auth-update --enable faillock 2>>"$ERR"
        grep -q pam_faillock "$PAM_DIR/common-auth" \
            && echo "[LOCKOUT] pam_faillock enabled (5 tries, 15 min)" | tee -a "$FORENSICS_LOG" \
            || echo "[WARN] pam_faillock not active in common-auth (local PAM edits? enable manually)" | tee -a "$FORENSICS_LOG"
    else
        echo "[WARN] No faillock pam-config profile on this distro; account lockout NOT enabled" | tee -a "$FORENSICS_LOG"
    fi
}

##########################
# Step 10: LOCAL AUDIT POLICY
##########################
echo "--- [10/18] Audit policies ---"
$SKIP_CHANGES || { command -v auditctl &>/dev/null || sudo apt-get install -y auditd; sudo systemctl enable --now auditd; sudo auditctl -e 1; }

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
    $SKIP_CHANGES && continue
    systemctl list-unit-files "$svc.service" 2>/dev/null | grep -q "^$svc\.service" || continue
    svc_en=$(systemctl is-enabled "$svc" 2>/dev/null || echo disabled)
    svc_ac=$(systemctl is-active "$svc" 2>/dev/null || echo inactive)
    journal svc "$svc" "$svc_en" "$svc_ac"
    sudo systemctl stop "$svc"; sudo systemctl disable "$svc"
done

##########################
# Step 13: FEATURES
##########################
echo "--- [13/18] Disabling unnecessary features ---"
$SKIP_CHANGES || for unit in rpcbind.service rpcbind.socket; do
    journal mask "$unit"
    sudo systemctl mask "$unit"
done

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
    echo "$file|$reason" >> "$SUSPICIOUS_OUTPUT"
}

# Check if file is a polyglot (extension doesn't match shebang)
check_polyglot() {
    local file="$1"
    [[ ! -f "$file" ]] && return
    local magic
    IFS= read -r -n2 magic < "$file" 2>/dev/null
    [[ "$magic" != "#!" ]] && return
    local firstline
    IFS= read -r firstline < "$file" 2>/dev/null
    [[ ! "$firstline" =~ ^#! ]] && return

    local base="${file##*/}"
    local ext=""
    [[ "$base" == *.* ]] && ext="${base##*.}"
    local lowerline="${firstline,,}"

    case "$ext" in
        pl)  [[ "$lowerline" =~ perl ]] || echo "POLYGLOT: .pl file but shebang is: $firstline" ;;
        py)  [[ "$lowerline" =~ python ]] || echo "POLYGLOT: .py file but shebang is: $firstline" ;;
        sh)  [[ "$lowerline" =~ bash|sh ]] || echo "POLYGLOT: .sh file but shebang is: $firstline" ;;
        rb)  [[ "$lowerline" =~ ruby ]] || echo "POLYGLOT: .rb file but shebang is: $firstline" ;;
        php) [[ "$lowerline" =~ php ]] || echo "POLYGLOT: .php file but shebang is: $firstline" ;;
        "")  # No extension at all is normal for Unix scripts/binaries - not suspicious by itself
            ;;
        *)   # Non-script extension with a script shebang = polyglot
            if [[ "$lowerline" =~ bash|sh|perl|python|ruby|php ]]; then
                echo "POLYGLOT: non-script extension (.$ext) but shebang is: $firstline"
            fi
            ;;
    esac
}

# World-writable files
while IFS= read -r f; do
    log_suspicious "$f" "World-writable"
done < <(find /etc /usr /bin /sbin -type f -perm -0002 2>/dev/null)

# SUID/SGID files
while IFS= read -r f; do
    log_suspicious "$f" "SUID/SGID"
done < <(find /usr/bin /usr/sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

# Hidden files: ONLY flag if they are ALSO executable/scripts/polyglots
# Skip common config dotfiles and script's own dirs
while IFS= read -r f; do
    [[ "$f" == *"/cp-backups/"* ]] && continue
    [[ "$f" == *"/cp-logs/"* ]] && continue

    # Skip common harmless hidden config files
    basename=$(basename "$f")
    case "$basename" in
        .bashrc|.bash_profile|.bash_logout|.profile|.vimrc|.inputrc|\
        .gitconfig|.gitignore|.ssh_config|.selected_editor|\
        .Xauthority|.ICEauthority|.pki|.local|.config|.cache|\
        .myconfig|.mysql_history|.python_history|.lesshst|\
        .wgetrc|.curlrc|.npmrc|.yarnrc|.gemrc)
            continue ;;
    esac

    # Only flag hidden files if they have suspicious properties
    reasons=""

    # Check if executable
    if [[ -x "$f" ]]; then
        reasons="Hidden executable file"
    fi

    # Check if it's a script by extension
    if [[ "$f" =~ \.(sh|py|pl|rb|php|exe|bin|elf)$ ]]; then
        [[ -n "$reasons" ]] && reasons="$reasons; "
        reasons="${reasons}Hidden script/executable (.$ext)"
    fi

    # Check for polyglot
    polyglot_reason=$(check_polyglot "$f")
    if [[ -n "$polyglot_reason" ]]; then
        [[ -n "$reasons" ]] && reasons="$reasons; "
        reasons="${reasons}$polyglot_reason"
    fi

    # Only log if we found an actual reason beyond just "hidden"
    if [[ -n "$reasons" ]]; then
        log_suspicious "$f" "$reasons"
    fi
done < <(find /etc /home -name ".*" -type f 2>/dev/null)

# Scripts or executables in /tmp and /var/tmp (including polyglots)
while IFS= read -r f; do
    reasons="Suspicious extension ($(basename "$f"))"
    polyglot_reason=$(check_polyglot "$f")
    if [[ -n "$polyglot_reason" ]]; then
        reasons="$reasons; $polyglot_reason"
    fi
    log_suspicious "$f" "$reasons"
done < <(find /tmp /var/tmp -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.php" -o -name "*.exe" -o -name "*.rb" -o -name "*.bin" \) 2>/dev/null)

# Also scan for polyglots in ALL files (not just known extensions)
# This catches test.pl with #!/bin/bash anywhere on the system
while IFS= read -r f; do
    [[ "$f" == *"/cp-backups/"* ]] && continue
    [[ "$f" == *"/cp-logs/"* ]] && continue
    polyglot_reason=$(check_polyglot "$f")
    if [[ -n "$polyglot_reason" ]]; then
        # Avoid duplicates
        if ! grep -qF "$f|" "$SUSPICIOUS_OUTPUT" 2>/dev/null; then
            log_suspicious "$f" "$polyglot_reason"
        fi
    fi
done < <(find / /tmp /dev/shm -xdev -type f -size -100k     -not -path "/var/lib/dpkg/*"     -not -path "/var/lib/rpm/*"     -not -path "/usr/share/exploitdb/*"     -not -path "/usr/share/metasploit-framework/*"     2>/dev/null)

##########################
# Step 15: BACKUP SUSPICIOUS FILES
##########################
echo "--- [15/18] Backing up suspicious files ---"
$DRYRUN || while IFS='|' read -r f _; do [[ -f "$f" ]] && sudo cp -p "$f" "$BACKUP_DIR/suspicious_$(echo "${f#/}" | tr '/' '_')"; done < <(sort -u -t'|' -k1,1 "$SUSPICIOUS_OUTPUT")

##########################
# Step 16: READ README / Apache/MySQL Detection
##########################
echo "--- [16/18] Detecting Apache/MySQL & scanning README ---"
# Initialise: an unset $MYSQL_FOUND made "$MYSQL_FOUND && cmd" run cmd (mysql_secure_installation) anyway.
APACHE_FOUND=false; MYSQL_FOUND=false
# Look where a competition README actually lives (the old `find /` returned a random README).
README_PATH=$(find /home /root /opt -maxdepth 4 -type f \( -iname 'README' -o -iname 'README.txt' -o -iname 'README.md' -o -iname 'README.html' \) \
    -not -path '*/cp-logs/*' -not -path '*/node_modules/*' -not -path '*/Universal-Hardening-Script/*' 2>/dev/null | head -n1)
if [[ -z "$README_PATH" ]]; then
    read -p "README not found. Enter README URL (blank to skip): " README_URL
    if [[ -n "$README_URL" ]]; then
        README_PATH="$(mktemp /tmp/README.XXXXXX)"
        curl -sSL "$README_URL" -o "$README_PATH" || README_PATH=""
    fi
fi
if [[ -n "$README_PATH" ]] && grep -iq "apache" "$README_PATH"; then echo "[INFO] Apache mentioned in README"; APACHE_FOUND=true; fi
if [[ -n "$README_PATH" ]] && grep -iq "mysql" "$README_PATH"; then echo "[INFO] MySQL mentioned in README"; MYSQL_FOUND=true; fi

##########################
# Step 17: SERVICE-SPECIFIC HARDENING
##########################
echo "--- [17/18] Apache/MySQL hardening ---"
$SKIP_CHANGES || {
    if [[ "$APACHE_FOUND" == true ]]; then
        sudo a2enmod security2 headers
        sudo systemctl restart apache2
    fi
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

    VIRUSTOTAL_API_KEY="${VIRUSTOTAL_API_KEY:-${VT_API_KEY:-}}"
    if [[ -z "$VIRUSTOTAL_API_KEY" ]]; then read -rsp "Enter VirusTotal API Key (blank to skip): " VIRUSTOTAL_API_KEY; echo; fi
    if [[ -z "$VIRUSTOTAL_API_KEY" ]]; then
        echo "[ERROR] No API key provided, skipping VirusTotal scan." | tee -a "$FORENSICS_LOG"
    elif ! command -v jq >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
        echo "[ERROR] jq and curl are required for VirusTotal lookups, skipping." | tee -a "$FORENSICS_LOG"
    else
        vt_count=0
        while IFS= read -r line; do
            if (( vt_count >= 40 )); then echo "[VT] Capped at 40 lookups" | tee -a "$FORENSICS_LOG"; break; fi
            file=$(echo "$line" | cut -d'|' -f1)
            reason=$(echo "$line" | cut -d'|' -f2)
            file=$(echo "$file" | sed 's|\\|/|g')
            [[ -f "$file" ]] || continue
            vt_count=$((vt_count + 1))
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

##########################
# [R1-A] KERNEL HARDENING via sysctl
##########################
echo "--- [R1-A] Kernel hardening (sysctl) ---"
$SKIP_CHANGES || {
    SYSCTL_CONF="/etc/sysctl.d/99-beast-hardening.conf"
    backup_file "$SYSCTL_CONF"
    sudo tee "$SYSCTL_CONF" > /dev/null << 'SYSCTL_EOF'
# BEAST hardening - kernel parameters
# Network: disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
# Ignore ICMP broadcast and bogus error responses
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Disable source routing and redirects
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Log martian packets
net.ipv4.conf.all.log_martians = 1
# ASLR
kernel.randomize_va_space = 2
# Disable magic SysRq
kernel.sysrq = 0
# Restrict dmesg access
kernel.dmesg_restrict = 1
# Restrict ptrace
kernel.yama.ptrace_scope = 1
# Disable core dumps for SUID programs
fs.suid_dumpable = 0
SYSCTL_EOF
    sudo sysctl -p "$SYSCTL_CONF" 2>>"$ERR" && echo "[SYSCTL] Kernel hardening applied" || echo "[WARN] sysctl apply had errors (see error log)"
    echo "[SYSCTL] Kernel hardening parameters written to $SYSCTL_CONF" | tee -a "$FORENSICS_LOG"
}
$SKIP_CHANGES && echo "[DRY-RUN/FORENSIC] Would apply sysctl kernel hardening"

##########################
# [R1-B] GRUB TIMEOUT + PERMISSIONS
##########################
echo "--- [R1-B] GRUB timeout & permissions ---"
$SKIP_CHANGES || {
    GRUB_CFG="/etc/default/grub"
    if [[ -f "$GRUB_CFG" ]]; then
        backup_file "$GRUB_CFG"
        # Set timeout to 5s max
        sudo sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/' "$GRUB_CFG"
        # Hiding recovery entries removes the admin's way out of a broken boot: opt-in only.
        if $DISABLE_RECOVERY; then
            sudo sed -i 's/^#GRUB_DISABLE_RECOVERY=.*/GRUB_DISABLE_RECOVERY="true"/' "$GRUB_CFG"
            grep -q "^GRUB_DISABLE_RECOVERY" "$GRUB_CFG" || echo 'GRUB_DISABLE_RECOVERY="true"' | sudo tee -a "$GRUB_CFG" > /dev/null
        else
            echo "[GRUB] recovery entries kept (pass --disable-recovery to hide them)"
        fi
        sudo update-grub 2>>"$ERR" && echo "[GRUB] Config updated" || echo "[WARN] update-grub failed"
        # Lock down grub.cfg permissions
        [[ -f /boot/grub/grub.cfg ]] && sudo chmod 600 /boot/grub/grub.cfg && echo "[GRUB] grub.cfg permissions set to 600"
    fi
    echo "[GRUB] GRUB hardening complete" | tee -a "$FORENSICS_LOG"
}
$SKIP_CHANGES && echo "[DRY-RUN/FORENSIC] Would harden GRUB config"

##########################
# [R2-A] DISABLE USB STORAGE
##########################
echo "--- [R2-A] Disable USB storage module ---"
$SKIP_CHANGES || {
    USB_BLACKLIST="/etc/modprobe.d/beast-disable-usb.conf"
    backup_file "$USB_BLACKLIST"
    echo "install usb-storage /bin/true" | sudo tee "$USB_BLACKLIST" > /dev/null
    echo "blacklist usb-storage" | sudo tee -a "$USB_BLACKLIST" > /dev/null
    sudo rmmod usb-storage 2>/dev/null && echo "[USB] usb-storage unloaded" || echo "[USB] usb-storage not loaded (ok)"
    echo "[USB] usb-storage disabled via modprobe blacklist" | tee -a "$FORENSICS_LOG"
}
$SKIP_CHANGES && echo "[DRY-RUN/FORENSIC] Would blacklist usb-storage"

##########################
# [R2-B] CORE DUMP DISABLE (limits.conf + systemd)
##########################
echo "--- [R2-B] Disable core dumps ---"
$SKIP_CHANGES || {
    LIMITS_CONF="/etc/security/limits.conf"
    backup_file "$LIMITS_CONF"
    grep -q "hard core 0" "$LIMITS_CONF" || echo "* hard core 0" | sudo tee -a "$LIMITS_CONF" > /dev/null
    grep -q "soft core 0" "$LIMITS_CONF" || echo "* soft core 0" | sudo tee -a "$LIMITS_CONF" > /dev/null
    # systemd coredump disable
    sudo mkdir -p /etc/systemd/coredump.conf.d
    echo -e "[Coredump]\nStorage=none\nProcessSizeMax=0" | sudo tee /etc/systemd/coredump.conf.d/disable.conf > /dev/null
    echo "[COREDUMP] Core dumps disabled" | tee -a "$FORENSICS_LOG"
}
$SKIP_CHANGES && echo "[DRY-RUN/FORENSIC] Would disable core dumps"

##########################
# [R2-C] TCP WRAPPERS - hosts.deny / hosts.allow
##########################
echo "--- [R2-C] TCP Wrappers (hosts.deny) ---"
$SKIP_CHANGES || {
    # TCP wrappers only matter for services linked against libwrap (sshd no longer is on current
    # Debian/Ubuntu); a blanket "ALL: ALL" anywhere else is just a lockout hazard.
    if command -v tcpd >/dev/null 2>&1 || ldd "$(command -v sshd 2>/dev/null || echo /bin/true)" 2>/dev/null | grep -q libwrap; then
        backup_file /etc/hosts.deny
        backup_file /etc/hosts.allow
        grep -q "sshd: ALL" /etc/hosts.allow 2>/dev/null || echo "sshd: ALL" | sudo tee -a /etc/hosts.allow > /dev/null
        grep -q "ALL: ALL" /etc/hosts.deny 2>/dev/null || echo "ALL: ALL" | sudo tee -a /etc/hosts.deny > /dev/null
        echo "[TCPWRAP] hosts.allow permits sshd; hosts.deny set to deny all else" | tee -a "$FORENSICS_LOG"
    else
        echo "[TCPWRAP] libwrap/tcpd not in use on this system; skipped (ufw is the active control)" | tee -a "$FORENSICS_LOG"
    fi
}
$SKIP_CHANGES && echo "[DRY-RUN/FORENSIC] Would configure TCP wrappers"

##########################
# [R3-A] EMPTY PASSWORD ACCOUNTS CHECK & LOCK
##########################
echo "--- [R3-A] Empty password check ---"
EMPTY_PW_FOUND=false
while IFS=: read -r user pw rest; do
    if [[ "$pw" == "" ]]; then
        echo "[ALERT] Empty password for user: $user" | tee -a "$FORENSICS_LOG"
        EMPTY_PW_FOUND=true
        if ! $SKIP_CHANGES; then
            sudo passwd -l "$user" && echo "[LOCKED] $user locked" | tee -a "$FORENSICS_LOG"
        fi
    fi
done < <(sudo cat /etc/shadow 2>/dev/null)
$EMPTY_PW_FOUND || echo "[OK] No empty passwords found"

##########################
# [R3-B] UNATTENDED UPGRADES (auto security patches)
##########################
echo "--- [R3-B] Unattended upgrades setup ---"
$SKIP_CHANGES || {
    dpkg -s unattended-upgrades &>/dev/null || sudo apt-get install -y unattended-upgrades
    sudo dpkg-reconfigure -plow unattended-upgrades --frontend=noninteractive 2>/dev/null || true
    UA_CONF="/etc/apt/apt.conf.d/20auto-upgrades"
    if [[ ! -f "$UA_CONF" ]]; then
        cat << 'APT_CONF' | sudo tee "$UA_CONF" > /dev/null
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT_CONF
    fi
    sudo systemctl enable --now unattended-upgrades 2>/dev/null || true
    echo "[AUTOUPGRADE] Unattended upgrades enabled" | tee -a "$FORENSICS_LOG"
}
$SKIP_CHANGES && echo "[DRY-RUN/FORENSIC] Would enable unattended upgrades"

##########################
# [R3-C] CHECK SUDOERS FOR NOPASSWD ENTRIES
##########################
echo "--- [R3-C] Sudoers NOPASSWD audit ---"
{
    grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read -r line; do
        echo "[ALERT] NOPASSWD sudoers entry: $line" | tee -a "$FORENSICS_LOG"
    done
} || true
echo "[SUDOERS] Audit complete"

##########################
# [R4-A] LISTENING PORT AUDIT
##########################
echo "--- [R4-A] Listening port audit ---"
{
    echo "[PORT AUDIT] $(date)" | tee -a "$FORENSICS_LOG"
    ss -tlnp 2>/dev/null | tee -a "$FORENSICS_LOG" | while read -r line; do
        echo "$line"
    done
    # Flag unexpected listening ports (not 22/ssh)
    ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -v '0.0.0.0:22\|127.0.0.1:22\|\[::\]:22\|:::22' | while read -r addr; do
        echo "[ALERT] Unexpected listening port: $addr" | tee -a "$FORENSICS_LOG"
    done
} || true

##########################
# [R4-B] INSTALL & RUN CLAMAV
##########################
echo "--- [R4-B] ClamAV antivirus scan ---"
$SKIP_CHANGES || {
    if ! command -v clamscan &>/dev/null; then
        echo "[CLAM] Installing ClamAV..."
        sudo apt-get install -y clamav clamav-daemon 2>>"$ERR"
    fi
    # Update signatures (non-blocking, best-effort)
    sudo systemctl stop clamav-freshclam 2>/dev/null || true
    sudo freshclam --quiet 2>>"$ERR" || echo "[CLAM] freshclam update failed (offline?)"
    # Quick scan of /tmp and /home
    echo "[CLAM] Scanning /tmp and /home..."
    clamscan --recursive --quiet --infected /tmp /home 2>>"$ERR" | tee -a "$FORENSICS_LOG" | while read -r line; do
        echo "[CLAM RESULT] $line"
    done
    echo "[CLAM] Scan complete" | tee -a "$FORENSICS_LOG"
}
$SKIP_CHANGES && echo "[DRY-RUN/FORENSIC] Would install ClamAV and scan /tmp /home"

##########################
# [R4-C] DISABLE IPv6 (if not needed)
##########################
echo "--- [R4-C] Disable IPv6 ---"
$SKIP_CHANGES || {
    GRUB_CFG="/etc/default/grub"
    if grep -q "ipv6.disable=1" "$GRUB_CFG" 2>/dev/null; then
        echo "[IPv6] Already disabled via GRUB"
    else
        # Use sysctl to disable at runtime (safer than GRUB edit)
        grep -q "net.ipv6.conf.all.disable_ipv6" /etc/sysctl.d/99-beast-hardening.conf 2>/dev/null || {
            echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.d/99-beast-hardening.conf > /dev/null
            echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.d/99-beast-hardening.conf > /dev/null
            sudo sysctl -p /etc/sysctl.d/99-beast-hardening.conf 2>>"$ERR" | tail -2
        }
    fi
    echo "[IPv6] IPv6 disabled via sysctl" | tee -a "$FORENSICS_LOG"
}
$SKIP_CHANGES && echo "[DRY-RUN/FORENSIC] Would disable IPv6"

##########################
# [R5-A] FULL SSH HARDENING
##########################
echo "--- [R5-A] Full SSH hardening ---"
$SKIP_CHANGES || [[ ! -f "$SSHD" ]] || {
    backup_file "$SSHD"
    declare -A SSH_SETTINGS=(
        ["PermitRootLogin"]="no"
        ["PasswordAuthentication"]="yes"
        ["PermitEmptyPasswords"]="no"
        ["X11Forwarding"]="no"
        ["MaxAuthTries"]="3"
        ["LoginGraceTime"]="30"
        ["AllowTcpForwarding"]="no"
        ["ClientAliveInterval"]="300"
        ["ClientAliveCountMax"]="2"
        ["UsePAM"]="yes"
        ["PrintLastLog"]="yes"
        ["IgnoreRhosts"]="yes"
        ["HostbasedAuthentication"]="no"
    )
    for key in "${!SSH_SETTINGS[@]}"; do
        val="${SSH_SETTINGS[$key]}"
        if grep -qE "^#?${key}" "$SSHD"; then
            sudo sed -i "s|^#\?${key}.*|${key} ${val}|" "$SSHD"
        else
            echo "${key} ${val}" | sudo tee -a "$SSHD" > /dev/null
        fi
        echo "[SSH] Set $key = $val"
    done
    DROPIN=/etc/ssh/sshd_config.d/00-beast-hardening.conf
    # sshd uses the FIRST value it sees and Include'd drop-ins are read before later lines, so
    # cloud-init style drop-ins silently override edits to the main file. Mirror the settings
    # in a drop-in that sorts first.
    if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$SSHD" && [[ -d /etc/ssh/sshd_config.d ]]; then
        backup_file "$DROPIN"
        for key in "${!SSH_SETTINGS[@]}"; do echo "${key} ${SSH_SETTINGS[$key]}"; done | sudo tee "$DROPIN" > /dev/null
        echo "[SSH] Wrote drop-in $DROPIN"
    fi
    SSH_SVC=ssh
    systemctl list-units --type=service 2>/dev/null | grep -q "sshd.service" && SSH_SVC=sshd
    if sudo sshd -t 2>>"$ERR"; then
        sudo systemctl reload "$SSH_SVC" 2>>"$ERR" && echo "[SSH] $SSH_SVC reloaded" || echo "[WARN] $SSH_SVC reload failed"
    else
        echo "[ERROR] sshd config failed validation (sshd -t): restoring backups, sshd NOT reloaded" | tee -a "$FORENSICS_LOG"
        SSHD_BAK="$BACKUP_DIR/$(echo "${SSHD#/}" | tr '/' '_').bak"
        [[ -f "$SSHD_BAK" ]] && sudo cp -p "$SSHD_BAK" "$SSHD"
        sudo rm -f "$DROPIN"
    fi
    echo "[SSH] Full SSH hardening applied" | tee -a "$FORENSICS_LOG"
}
$SKIP_CHANGES && echo "[DRY-RUN/FORENSIC] Would apply full SSH hardening"

##########################
# [R5-B] LOGIN BANNERS (issue / issue.net / motd)
##########################
echo "--- [R5-B] Login banners ---"
$SKIP_CHANGES || {
    BANNER="Authorized access only. All activity is monitored and logged. Unauthorized access is prohibited."
    echo "$BANNER" | sudo tee /etc/issue > /dev/null
    echo "$BANNER" | sudo tee /etc/issue.net > /dev/null
    echo "$BANNER" | sudo tee /etc/motd > /dev/null
    grep -q "^Banner" "$SSHD" && sudo sed -i 's|^Banner.*|Banner /etc/issue.net|' "$SSHD" || \
        echo "Banner /etc/issue.net" | sudo tee -a "$SSHD" > /dev/null
    echo "[BANNER] Login banners configured" | tee -a "$FORENSICS_LOG"
}
$SKIP_CHANGES && echo "[DRY-RUN/FORENSIC] Would set login banners"

##########################
# [R5-C] CRON AUDIT - suspicious cron entries
##########################
echo "--- [R5-C] Cron audit ---"
{
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs; do
        [[ -d "$crondir" ]] || continue
        find "$crondir" -type f 2>/dev/null | while read -r cronfile; do
            grep -v "^#\|^$" "$cronfile" 2>/dev/null | grep -E "^[0-9*@]" | while read -r entry; do
                echo "[CRON ENTRY] $cronfile: $entry" | tee -a "$FORENSICS_LOG"
            done
        done
    done
    # User crontabs
    crontab -l 2>/dev/null | grep -v "^#\|^$" | while read -r entry; do
        echo "[CRON] $USER crontab: $entry" | tee -a "$FORENSICS_LOG"
    done
    echo "[CRON] Cron audit complete"
} || true

##########################
# [POST] BENCHMARK: re-score after hardening, diff against baseline
##########################
if $BENCH && ! $SKIP_CHANGES; then
    run_benchmark post "$BENCH_POST"
    compare_benchmark
fi

##########################
# Step 19: AI LOG ANALYSIS (Qwen2.5-Coder-1.5B via Ollama)
##########################
echo "--- [19/19] AI analysis of session logs (Qwen2.5-Coder-1.5B) ---"
AI_LOG_DIR="$LOG_DIR/AI-cp-logs"
mkdir -p "$AI_LOG_DIR"
AI_LOG="$AI_LOG_DIR/ai_analysis_$TIMESTAMP.log"
AI_MODEL="qwen2.5-coder:1.5b-instruct"

ai_log_analysis() {
    if ! command -v ollama >/dev/null 2>&1; then
        echo "[AI] ollama not installed, skipping AI analysis" | tee -a "$FORENSICS_LOG"
        return
    fi

    if ! curl -s -m 3 http://127.0.0.1:11434/api/version >/dev/null 2>&1; then
        nohup ollama serve >/tmp/ollama-serve.log 2>&1 &
        disown
        sleep 3
    fi

    if ! curl -s -m 3 http://127.0.0.1:11434/api/version >/dev/null 2>&1; then
        echo "[AI] ollama service unreachable, skipping AI analysis" | tee -a "$FORENSICS_LOG"
        return
    fi

    if ! ollama list 2>/dev/null | grep -q "$AI_MODEL"; then
        echo "[AI] Model $AI_MODEL not pulled, skipping AI analysis (run: ollama pull $AI_MODEL)" | tee -a "$FORENSICS_LOG"
        return
    fi

    local combined
    combined=$(
        {
            echo "=== FORENSICS LOG ==="
            [[ -f "$FORENSICS_LOG" ]] && tail -c 6000 "$FORENSICS_LOG"
            echo
            echo "=== SUSPICIOUS FILES ==="
            [[ -f "$SUSPICIOUS_OUTPUT" ]] && tail -c 3000 "$SUSPICIOUS_OUTPUT"
            echo
            echo "=== HARDENING LOG ==="
            [[ -f "$LOG" ]] && tail -c 3000 "$LOG"
            echo
            echo "=== ERROR LOG ==="
            [[ -f "$ERR" ]] && tail -c 1500 "$ERR"
            echo
            echo "=== BENCHMARK ==="
            if [[ -f "$BENCH_REPORT" ]]; then tail -c 2000 "$BENCH_REPORT"; elif [[ -f "$BENCH_PRE" ]]; then tail -c 2000 "$BENCH_PRE"; fi
        }
    )

    local prompt="You are a security analyst reviewing CyberPatriot hardening script output. Summarize key findings, flag anything suspicious or high-risk (backdoors, malicious cron, unauthorized sudoers, unexpected listening ports, suspicious files), and give a short prioritized action list. Be concise.

LOGS:
$combined"

    echo "[AI] Sending logs to $AI_MODEL for analysis..." | tee -a "$FORENSICS_LOG"

    local response
    response=$(jq -n --arg model "$AI_MODEL" --arg prompt "$prompt" \
        '{model: $model, prompt: $prompt, stream: false}' | \
        timeout 180 curl -s -X POST http://127.0.0.1:11434/api/generate -d @-)

    local analysis
    analysis=$(echo "$response" | jq -r '.response // empty' 2>/dev/null)

    if [[ -z "$analysis" ]]; then
        echo "[AI] No response from model, skipping" | tee -a "$FORENSICS_LOG"
        return
    fi

    {
        echo "AI Log Analysis - $TIMESTAMP"
        echo "Model: $AI_MODEL"
        echo "======================================"
        echo "$analysis"
    } > "$AI_LOG"

    echo "[AI] Analysis written to $AI_LOG" | tee -a "$FORENSICS_LOG"
}

ai_log_analysis
