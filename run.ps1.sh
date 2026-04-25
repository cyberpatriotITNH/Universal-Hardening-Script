#!/bin/bash
: '
:: ========================================
:: B.E.A.S.T Installer - run.ps1.sh
:: Downloads and installs checklist.ps1.sh
:: Works on Linux (bash) and Windows (Git Bash / WSL)
:: ========================================
'

RAW_URL="https://raw.githubusercontent.com/cyberpatriotITNH/Universal-Hardening-Script/main/checklist.ps1.sh"

# --------------------
# Windows detection
# --------------------
if [ -n "$WINDIR" ]; then
    _TEMP_PS=$(mktemp "${TEMP:-/tmp}/XXXXXXXXXX.ps1")
    cat > "$_TEMP_PS" << 'END_PS'
$RAW_URL = "https://raw.githubusercontent.com/cyberpatriotITNH/Universal-Hardening-Script/main/checklist.ps1.sh"
$dest    = "$env:USERPROFILE\checklist.ps1.sh"

Write-Host "Downloading checklist to $dest ..."
Invoke-WebRequest -Uri $RAW_URL -OutFile $dest -UseBasicParsing

# Verify bash is available (Git for Windows / WSL)
$bashExe = (Get-Command bash -ErrorAction SilentlyContinue)
if (-not $bashExe) {
    Write-Host "ERROR: bash not found. Install Git for Windows or WSL and re-run."
    exit 1
}
$bashPath = $bashExe.Source

# Persist a PowerShell function that invokes the script via bash
$profileDir = Split-Path $PROFILE
if (!(Test-Path $profileDir)) { New-Item -ItemType Directory -Path $profileDir -Force | Out-Null }
$funcLine = "function checklist { & '$bashPath' '$dest' @args }"
if (!(Select-String -Path $PROFILE -Pattern 'function checklist' -ErrorAction SilentlyContinue)) {
    Add-Content -Path $PROFILE -Value $funcLine
}
Write-Host "Installed checklist at $dest"
Write-Host "Run with: checklist [--normal|--forensic|--dry-run|--undo]"
Write-Host "(Restart your PowerShell session or run: . `$PROFILE)"
END_PS
    powershell -NoProfile -ExecutionPolicy Bypass -File "$_TEMP_PS"
    _EXIT=$?
    rm -f "$_TEMP_PS"
    exit $_EXIT
fi

# --------------------
# Linux / macOS install
# --------------------
INSTALL_PATH="/usr/local/bin/checklist"
echo "Downloading checklist to $INSTALL_PATH ..."

if ! sudo curl -fsSL "$RAW_URL" -o "$INSTALL_PATH"; then
    echo "ERROR: Download failed. Check your internet connection and try again."
    exit 1
fi
sudo chmod +x "$INSTALL_PATH"

# Add alias to ~/.bashrc if not already present
ALIAS_LINE="alias checklist='sudo $INSTALL_PATH'"
if ! grep -qxF "$ALIAS_LINE" ~/.bashrc; then
    echo "$ALIAS_LINE" >> ~/.bashrc
fi

echo "Installed checklist at $INSTALL_PATH"
echo "Run with: checklist [--normal|--forensic|--dry-run|--undo]"
echo "(You may need to run: source ~/.bashrc)"
