#!/bin/bash
# ====================================================================
# HAKIMIX FRAMEWORK - KALI LINUX AUTOMATED INSTALLER SCRIPT
# Created by: Hakimi
# ====================================================================

echo -e "\e[1;36m"
echo "  ┌─────────────────────────────────────────────────────────────┐"
echo "  │           HAKIMIX - KALI LINUX ONE-CLICK SETUP SCRIPT       │"
echo "  │                     Created by: HAKIMI                      │"
echo "  └─────────────────────────────────────────────────────────────┘"
echo -e "\e[0m"

echo -e "\e[1;33m[+] Step 1: Updating System Repositories...\e[0m"
sudo apt update -y

echo -e "\e[1;33m[+] Step 2: Installing Core Python & Network Packages...\e[0m"
sudo apt install -y python3-pip python3-venv git curl wget net-tools dnsutils whois libcap2-bin

echo -e "\e[1;33m[+] Step 3: Installing Python Requirements for HAKIMIX...\e[0m"
pip install -r requirements.txt --break-system-packages

echo -e "\e[1;33m[+] Step 4: Installing Anonymity & Network Tools...\e[0m"
sudo apt install -y proxychains4 tor macchanger dnscrypt-proxy

echo -e "\e[1;33m[+] Step 5: Installing Reconnaissance & OSINT Tools...\e[0m"
sudo apt install -y theharvester subfinder amass recon-ng whatweb
pip install sherlock-project holehe ignorant --break-system-packages

echo -e "\e[1;33m[+] Step 6: Installing Web Vulnerability Scanners...\e[0m"
sudo apt install -y nuclei nikto sqlmap wapiti wpscan commix ffuf gobuster masscan rustscan hydra exploitdb rkhunter chkrootkit set

echo -e "\e[1;32m"
echo "===================================================================="
echo "  [SUCCESS] All tools and requirements for HAKIMIX are installed!"
echo "  To launch HAKIMIX, run: python3 main.py"
echo "===================================================================="
echo -e "\e[0m"
