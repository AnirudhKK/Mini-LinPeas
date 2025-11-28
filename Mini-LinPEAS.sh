#!/bin/bash

# ==============================================================================
#  Mini-LinPeas: Lightweight Privilege Escalation Enumerator
#  Author: Gemini
#  Description: Enumerates SUID, Capabilities, Sudo -l, and System Info
# ==============================================================================

# --- Color Definitions ---
# Using ANSI escape codes for coloring output similar to LinPEAS
C_RESET='\033[0m'
C_RED='\033[1;31m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[1;34m'
C_MAGENTA='\033[1;35m'
C_CYAN='\033[1;36m'
C_BG_RED='\033[41m\033[1;37m' # White text on Red background for Critical

# --- Helper Functions ---

print_banner() {
    echo -e "${C_GREEN}"
    echo "  _     _       ____  _____" 
    echo " | |   (_)_ __ |  _ \| ____|  Mini-LinPEAS"
    echo " | |   | | '_ \| |_) |  _|    Privilege Escalation Checker"
    echo " | |___| | | | |  __/| |___   Fast & Formatted"
    echo " |_____|_|_| |_|_|   |_____|  "
    echo -e "${C_RESET}"
}

print_section() {
    echo -e "\n${C_YELLOW}═════════════════════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}[+] $1 ${C_RESET}"
    echo -e "${C_YELLOW}═════════════════════════════════════════════════════════════════════════════${C_RESET}"
}

print_info() {
    echo -e "${C_CYAN}[i]${C_RESET} $1"
}

print_good() {
    echo -e "${C_GREEN}[+]${C_RESET} $1"
}

print_bad() {
    echo -e "${C_RED}[!]${C_RESET} $1"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${C_RED}[!] Command '$1' not found on this system.${C_RESET}"
        return 1
    fi
    return 0
}

# ==============================================================================
#  MAIN EXECUTION
# ==============================================================================

print_banner

# --- 1. Basic System Information ---
print_section "Basic System Information"
echo -e "${C_MAGENTA}Hostname:${C_RESET} $(hostname)"
echo -e "${C_MAGENTA}OS:${C_RESET} $(cat /etc/issue 2>/dev/null | cut -d'\\' -f1 | tr -d '\n')"
echo -e "${C_MAGENTA}Kernel:${C_RESET} $(uname -a)"
echo -e "${C_MAGENTA}Current User:${C_RESET} $(id)"

# --- 2. Sudo Permissions (sudo -l) ---
print_section "Sudo Permissions (sudo -l)"
print_info "Checking if user can run anything as root without password..."

if check_command "sudo"; then
    # We try to run sudo -l. If it asks for a password, it might hang or fail.
    # This attempts to run it non-interactively.
    SUDO_OUT=$(sudo -n -l 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "$SUDO_OUT" | grep -v "User" --color=always
        echo -e "\n${C_GREEN}>> Check GTFOBins for any binaries listed above!${C_RESET}"
    else
        echo -e "${C_RED}User cannot run sudo without password or sudo requires interaction.${C_RESET}"
    fi
fi

# --- 3. SUID Bit Set Files ---
print_section "SUID Files (Potential Vectors)"
print_info "Searching for binaries with the SUID bit set..."
# Find files with SUID bit, ignore error messages
find / -perm -u=s -type f 2>/dev/null | while read -r file; do
    # Highlight known dangerous binaries in RED
    if [[ "$file" =~ (nmap|vim|nano|find|bash|awk|cp|less|more|man|wget|curl|python|perl|ruby|lua|php|tar) ]]; then
        echo -e "${C_RED}$file${C_RESET} ${C_YELLOW}<-- INTERESTING!${C_RESET}"
    else
        echo -e "$file"
    fi
done

# --- 4. File Capabilities ---
print_section "File Capabilities"
print_info "Searching for files with capabilities set (getcap)..."
if check_command "getcap"; then
    getcap -r / 2>/dev/null | while read -r line; do
        # Highlight interesting capabilities
        if [[ "$line" =~ (cap_setuid|cap_dac_read_search|cap_sys_admin) ]]; then
             echo -e "${C_RED}$line${C_RESET} ${C_YELLOW}<-- DANGEROUS CAPABILITY!${C_RESET}"
        else
            echo "$line"
        fi
    done
else
    print_bad "getcap is not installed. Skipping capabilities check."
fi

# --- 5. Cron Jobs ---
print_section "Cron Jobs"
print_info "Listing /etc/crontab and /etc/cron.d contents..."
if [ -f /etc/crontab ]; then
    echo -e "${C_MAGENTA}--- /etc/crontab ---${C_RESET}"
    cat /etc/crontab
fi

echo -e "\n${C_MAGENTA}--- /etc/cron.d/ ---${C_RESET}"
ls -la /etc/cron.d/ 2>/dev/null

# --- 6. World Writable Files (High Value) ---
print_section "World Writable Files (Filtered)"
print_info "Checking for world-writable files in sensitive directories (/etc, /usr)..."
find /etc /usr -type f -not -path '*/proc/*' -perm -0002 -exec ls -l {} \; 2>/dev/null | head -n 20
echo -e "${C_CYAN}... (Output truncated to top 20)${C_RESET}"

print_section "Scan Complete"
echo -e "${C_GREEN}Enumeration finished.${C_RESET}"
