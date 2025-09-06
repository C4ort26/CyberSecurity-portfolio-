# CyberSecurity-portfolio-
CyberSecurity portfolio showcasing penetration testing and analysis project 


# 👋 Hi, I'm Comfort Baiye

Junior Cybersecurity analyst passionate about ethical hacking, penetration testing, and digital defense. I specialize in tools like Kali Linux, Metasploit,nmap script,and Nmap.  
This portfolio showcases my hands-on experience through real-world simulations and technical write-ups.

📝 1. Markdown File for GitHub Repo (README.md)
🛡️ Penetration Test: Metasploitable2

🔍 Overview 

Target**: Metasploitable2  
**Attacker Machine**: Kali Linux  
**Goal**: Simulate a full-scope penetration test and document findings

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
                     


FINAL REPORT ON PENETRATION TESTING PROJECT 
 
Attacker machine: Kali Linux:- 192.168.237.3/24 (VirtualBox)
Target machine: Metasploitable2:- 192.168.237.4/24(VirtualBox)
Both machines should be on the same host-only network or NAT network.
Target: Metasploitable2 (192.168.237.4)
Tester: Comfort Baiye
 Date: August 30, 2025
Tools Used: Nmap, Metasploit, OWASP ZAP, Nmap Script, Linux kernel exploit etc

1. Executive Summary
This penetration test was conducted on a vulnerable lab system (Metasploitable2, ip address 192.168.237.4) to simulate real-world attack scenarios in a safe environment. The goal was to identify exploitable vulnerabilities, assess their risk levels, and provide actionable remediation guidance.
Objective:
To perform a penetration test on the Metasploitable2 environment in order to identify security vulnerabilities.
Overall Risk Posture:
The target environment was found to be highly vulnerable, with multiple critical-severity weaknesses that could allow an attacker to take full control. 
 Key Findings:
3 High-risk vulnerabilities (Remote Code Execution, SQL Injection, FTP Backdoor)
2 Medium-risk vulnerabilities (XSS, Weak SSH credentials)
1 Low-risk issue (Information Disclosure)
Business Impact: If exploited in a production environment, these vulnerabilities could lead to full system compromise, data leakage, and unauthorized access.

2. Methodology
The test followed a structured approach based on industry standards (OWASP, PTES):
Assessment Type: This was a simulated penetration test on an isolated lab environment.
      Phases:
🔍 Reconnaissance
This is about gathering as much information as possible about the target without actively trying to exploit it.
Passive Reconnaissance
The tools to be used (whois, nslookup, dig, Shodan, theHarvester) for the passive reconnaissance phase are powerful tools for gathering information on public-facing websites and organizations. However, since my target, Metasploitable 2, is a virtual machine on an isolated private network. It doesn't have a public domain name, and its IP address isn't listed on the internet.
Why these tools listed above won't work for this project:
whois, nslookup, dig: These tools query public DNS and registration databases. Since my target is a private IP, there is no public record for them to find.
Shodan: This is a search engine for internet-connected devices. It crawls public IP addresses. My private, non-internet-connected Metasploitable 2 machine is not on Shodan's radar.
theHarvester: This tool gathers information like email addresses, subdomains, and hostnames from public sources. Again, since my target is not a public organization, there is nothing for it to find.
Conclusion: For this specific lab project, passive reconnaissance is not a practical step, because my target (Metasploitable2) is a virtual machine.This is why passive reconnaissance was skipped for this particular lab project.
Active Reconnaissance:
Use Nmap to scan the target:
nmap -sV -p- 192.168.56.101
-sV: Detect service versions
-p-: Scan all 65535 ports
Look for vulnerable services like:
FTP (port 21)
Telnet (port 23)
Samba (port 139/445)
MySQL (port 3306)
VNC (port 5900)
 nmap -sV -p- <192.168.237.4>

🛡️ Vulnerability Assessment
Nmap scripts (--script vuln)

💥 Exploitation
Metasploit modules (vsftpd_234_backdoor, samba/usermap_script)

🧠 Post-Exploitation
Privilege escalation via local_exploit_suggester
Enumeration of /etc/passwd, /etc/shadow
Credential dumping with hashdump
🌐 Web Application Testing
OWASP ZAP scan on Mutillidae and DVWA
Manual fuzzing for XSS and SQLi

3. Findings
🔴 3.1 FTP Backdoor (vsftpd 2.3.4)
CVE: CVE-2011-2523
CVSS: 10.0 (Critical)
Impact: Remote root shell access
Evidence:
Exploit used: exploit/unix/ftp/vsftpd_234_backdoor
Shell opened: command shell session 1 opened
Screenshot: 


[Insert your shell screenshot her]
Remediation: Upgrade vsftpd to a secure version; disable anonymous FTP.

🟠 3.2 Samba RCE (Usermap Script)
CVE: CVE-2007-2447
CVSS: 9.3 (High)
Impact: Remote code execution
Evidence:
Exploit used: exploit/multi/samba/usermap_script
Shell access confirmed
Screenshot: [Insert shell or Metasploit output]
Remediation: Patch Samba to latest version; restrict access to port 445.

🟡 3.3 SQL Injection in DVWA
CVE: N/A (Custom app)
CVSS: 7.5 (High)
Impact: Database access, data manipulation
Evidence:
Payload: ' OR '1'='1
Screenshot: [Insert DVWA login bypass or data dump]
Remediation: Use parameterized queries; sanitize user inputs.

🟠 3.4 XSS in Mutillidae
CVSS: 6.1 (Medium)
Impact: Session hijacking, defacement
Evidence:
Payload: <script>alert('XSS')</script>
Screenshot: [Insert alert box or ZAP alert]
Remediation: Encode output; use CSP headers.

🟡 3.5 Weak SSH Credentials
CVSS: 5.0 (Medium)
Impact: Unauthorized access
Evidence:
Hydra brute-force: msfadmin:msfadmin
Screenshot: []
Remediation: Enforce strong passwords; disable root login.

🟢 3.6 Information Disclosure via /etc/passwd
CVSS: 3.5 (Low)
Impact: User enumeration
Evidence:
Output: cat /etc/passwd
Screenshot: [Insert terminal output]
Remediation: Restrict file access; monitor for enumeration attempts.
Scope: The assessment was limited to the single Metasploitable2 virtual machine with the ip address:- 192.168.237.4

4. Risk Summary
Vulnerability
CVSS Score
Severity
Status
FTP Backdoor
10.0
High
Exploited
Samba RCE
9.3
High
Exploited
SQL Injection
7.5
High
Confirmed
XSS
6.1
Medium
Confirmed
Weak SSH Credentials
5.0
Medium
Exploited
Information Disclosure
3.5
Low
Confirmed


5. Remediation Recommendations
Issue
Recommendation
FTP Backdoor
Upgrade vsftpd; disable anonymous access
Samba RCE
Patch Samba; restrict port 445
SQL Injection
Use parameterized queries
XSS
Sanitize inputs; apply output encoding
Weak SSH Credentials
Enforce password complexity; use key-based auth
Information Disclosure
Harden file permissions


6. Appendices
Tools Used: Nmap, Metasploit, OWASP ZAP,
Screenshots:
Logs: [Include terminal outputs or ZAP alerts]
References: OWASP Top 10, CVE Details, NIST CVSS Calculator.

 Lateral Movement (if multi-host lab)
Scan the internal network:
ip a
nmap -sP 192.168.237.4/24
Use credentials or exploits to pivot to other machines.
Example: Use SSH with stolen credentials:
ssh user@192.168.236.4
There is only one host, therefore there is no lateral movement.

🧹 Step 7: Clean Up (Optional)
If you want to be stealthy:
history -c
rm -rf /tmp/*

🧠 Summary














