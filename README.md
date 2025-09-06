# CyberSecurity-portfolio-
CyberSecurity portfolio showcasing penetration testing and analysis project 

📝 1. Markdown File for GitHub Repo (README.md)
🛡️ Penetration Test: Metasploitable2

🔍 Overview
This project simulates a full-scope penetration test using Kali Linux against the vulnerable Metasploitable2 machine. It covers reconnaissance, exploitation, post-exploitation, and reporting — all documented with logs, payloads, and CVSS scoring.

🧰 Tools Used
- Kali Linux
- Nmap
- Nikto
- Gobuster
- Nmap Script 
- Metasploit
- Linux kernel exploit 

🧪 Attack Phases

Reconnaissance
`bash
nmap -sV -p- 192.168.237.4 -oN nmapfullscan.txt
`
Discovered open ports: 21 (FTP), 22 (SSH), 80 (HTTP), 139/445 (Samba)

Scanning
`bash
nikto -h http://192.168.237.4
gobuster dir -u http://192.168.237.4 -w /usr/share/wordlists/dirb/common.txt
`
Found /mutillidae/ vulnerable web app

Exploitation – SQL Injection
Target: login.php  
Payload: ' OR '1'='1  
Result: Authentication bypass


Privilege Escalation – Dirty COW (CVE-2016-5195)
Compiled and executed exploit to gain root access  
`bash
whoami
root
`

📊 CVSS Summary
| Vulnerability         | CVSS Score | Risk Level 
|----------------------|------------|------------
| SQL Injection         | 9.8        | High       
| Remote Code Execution | 10.0       | Critical   
| Privilege Escalation  | 7.8        | High       
                     
