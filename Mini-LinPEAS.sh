#!/bin/bash

# ==============================================================================
#  Custom-LinPEAS: Context-Aware Privilege Escalation Enumerator
#  Based on vectors from: Broker, CozyHosting, Builder, Busqueda, Dog, BoardLight
# ==============================================================================

# --- Color Definitions ---
C_RESET='\033[0m'
C_RED='\033[1;31m'      # Danger/Critical
C_GREEN='\033[1;32m'    # Good/Safe
C_YELLOW='\033[1;33m'   # Section Header
C_BLUE='\033[1;34m'     # Info
C_BOLD='\033[1m'

print_banner() {
    echo -e "${C_GREEN}"
    echo "   ____            _                    "
    echo "  / ___|   _ ___| |_ ___  _ __ ___    "
    echo " | |  | | | / __| __/ _ \| '_ \` _ \   "
    echo " | |__| |_| \__ \ || (_) | | | | | |  "
    echo "  \____\__,_|___/\__\___/|_| |_| |_|  "
    echo "  Context-Aware Privilege Escalation  "
    echo -e "${C_RESET}"
}

print_section() {
    echo -e "\n${C_YELLOW}════════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}[+] $1 ${C_RESET}"
    echo -e "${C_YELLOW}════════════════════════════════════════════════════════════════${C_RESET}"
}

check_command() {
    command -v "$1" &> /dev/null
}

# ==============================================================================
#  1. BASIC SYSTEM & USER INFO
#  Relevant to: All (Kernel exploits, group membership)
# ==============================================================================
print_banner
print_section "System Information"
echo -e "${C_BLUE}Hostname:${C_RESET} $(hostname)"
echo -e "${C_BLUE}OS Release:${C_RESET} $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
echo -e "${C_BLUE}Kernel:${C_RESET} $(uname -a)"
echo -e "${C_BLUE}Current User:${C_RESET} $(id)"
echo -e "${C_BLUE}Path:${C_RESET} $PATH"

# ==============================================================================
#  2. SUDO PERMISSIONS (The #1 Vector)
#  Relevant to: Broker, CozyHosting, Busqueda, Dog
# ==============================================================================
print_section "Sudo Permissions (sudo -l)"
if check_command "sudo"; then
    echo -e "${C_BLUE}[i] Attempting listing (passwordless)...${C_RESET}"
    SUDO_OUT=$(sudo -n -l 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "${C_RED}$SUDO_OUT${C_RESET}"
        echo -e "\n${C_GREEN}>> CHECK GTFOBINS for the binaries listed above!${C_RESET}"
        
        # Specific check for LD_PRELOAD or ProxyCommand vectors (CozyHosting)
        if echo "$SUDO_OUT" | grep -q "ssh"; then
             echo -e "${C_RED}[!] SSH found in sudoers. Check GTFOBins for ProxyCommand exploit (Refer to CozyHosting).${C_RESET}"
        fi
    else
        echo -e "${C_YELLOW}[!] User cannot run sudo without password or root interaction required.${C_RESET}"
    fi
else
    echo "sudo command not found."
fi

# ==============================================================================
#  3. SUID & GUID FILES
#  Relevant to: BoardLight (Enlightenment exploit), Busqueda (Custom scripts)
# ==============================================================================
print_section "SUID Binary Enumeration"
echo -e "${C_BLUE}[i] Searching for SUID bits...${C_RESET}"
# Find files with SUID, ignore errors, filter out common noise
find / -perm -4000 -type f 2>/dev/null | grep -v -E "snap|/proc|/sys" | while read -r file; do
    # Highlight known dangerous binaries often used in GTFOBins
    if [[ "$file" =~ (nmap|vim|nano|find|bash|awk|cp|less|more|man|wget|curl|python|perl|ruby|lua|php|tar|enlightenment|pkexec|polkit) ]]; then
        echo -e "${C_RED}$file${C_RESET} ${C_BOLD}<-- CRITICAL (Potential GTFOBin or CVE)${C_RESET}"
    else
        echo "$file"
    fi
done

# ==============================================================================
#  4. FILE CAPABILITIES
#  Standard enumeration
# ==============================================================================
print_section "File Capabilities"
if check_command "getcap"; then
    getcap -r / 2>/dev/null | grep -v "snap"
else
    echo "getcap not found."
fi

# ==============================================================================
#  5. STORED CREDENTIALS & APP CONFIGS
#  Relevant to: Builder (Jenkins), Dog (CMS), CozyHosting (Spring), Busqueda (Git)
# ==============================================================================
print_section "Interesting Config Files & Credentials"

# Check for Jenkins (Builder)
if [ -d "/var/jenkins_home" ] || [ -d "/var/lib/jenkins" ]; then
    echo -e "${C_RED}[!] Jenkins Directory Found! Check users.xml and credentials.xml${C_RESET}"
    find /var/jenkins_home /var/lib/jenkins -name "*.xml" 2>/dev/null | grep "users"
fi

# Check for Spring Boot / Java Properties (CozyHosting)
echo -e "${C_BLUE}[i] Searching for application.properties (Spring Boot/Java)...${C_RESET}"
find /opt /var/www /home -name "application.properties" 2>/dev/null | while read -r file; do
    echo -e "${C_RED}[!] Found Spring Config: $file${C_RESET}"
    grep -i "password" "$file" --color=always
done

# Check for PHP Configs / CMS (Dog, BoardLight)
echo -e "${C_BLUE}[i] Searching for PHP settings/config files...${C_RESET}"
find /var/www /home -name "*settings.php" -o -name "conf.php" -o -name "config.php" 2>/dev/null | while read -r file; do
    echo -e "${C_YELLOW}[*] Potential CMS Config: $file${C_RESET}"
    # Just show the line with 'pass' to be safe, don't cat whole file
    grep -i "pass" "$file" | head -n 5
done

# Check for Git Credentials (Busqueda)
echo -e "${C_BLUE}[i] Searching for .git config files...${C_RESET}"
find /var/www /home /opt -name "config" 2>/dev/null | grep ".git/config" | while read -r file; do
    echo -e "${C_YELLOW}[*] Git Config found: $file${C_RESET}"
    grep "url =" "$file" # Often contains http://user:pass@domain
done

# ==============================================================================
#  6. CUSTOM SCRIPTS & OPT DIRECTORY
#  Relevant to: Busqueda (Python script hijacking), Dog (Bee script)
# ==============================================================================
print_section "Custom Scripts & /opt Enumeration"
echo -e "${C_BLUE}[i] Listing contents of /opt (common location for CTF scripts)...${C_RESET}"
ls -laR /opt 2>/dev/null

echo -e "\n${C_BLUE}[i] Checking for writable files in /usr/local/bin or /opt...${C_RESET}"
find /usr/local/bin /opt -writable -type f 2>/dev/null

# ==============================================================================
#  7. INTERNAL PORTS (Listening)
#  Relevant to: Broker (ActiveMQ localhost), BoardLight (MySQL localhost)
# ==============================================================================
print_section "Internal Listening Ports"
# Quick check for ports listening on localhost that aren't exposed externally
if check_command "ss"; then
    ss -tulpn | grep "127.0.0.1"
elif check_command "netstat"; then
    netstat -tulpn | grep "127.0.0.1"
fi
