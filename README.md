# CyberSecurity Portfolio

Showcasing penetration testing and analysis projects.

---

## 👋 Hi, I'm Comfort Baiye

Junior Cybersecurity Analyst passionate about ethical hacking, penetration testing, and digital defense.  
I specialize in tools like Kali Linux, Metasploit, Nmap scripts, and more.  
This portfolio showcases my hands-on experience through real-world simulations and technical write-ups.

---

## 📋 Contents

- Penetration Test: Metasploitable2
- Attack Phases & Tools
- Risk & Findings
- Methodology
- Remediation
- Appendices

---

## 🛡️ Penetration Test Project: Metasploitable2

### 🔍 Overview

- **Target:** Metasploitable2  
- **Attacker Machine:** Kali Linux  
- **Goal:** Simulate a full-scope penetration test and document findings

This project simulates a full-scope penetration test using Kali Linux against the vulnerable Metasploitable2 machine. It covers reconnaissance, exploitation, post-exploitation, and reporting.

---

## 🧰 Tools Used

- Kali Linux
- Nmap
- Nikto
- Gobuster
- Metasploit
- Linux kernel exploits
- OWASP ZAP

---

## 🧪 Attack Phases

### 1. Reconnaissance

```
nmap -sV -p- 192.168.237.4 -oN nmapfullscan.txt
```
Discovered open ports: 21 (FTP), 22 (SSH), 80 (HTTP), 139/445 (Samba)

### 2. Scanning

```
ikto -h http://192.168.237.4
gobuster dir -u http://192.168.237.4 -w /usr/share/wordlists/dirb/common.txt
```
Found `/mutillidae/` vulnerable web app.

### 3. Exploitation – SQL Injection

- **Target:** login.php  
- **Payload:** `' OR '1'='1`  
- **Result:** Authentication bypass

### 4. Privilege Escalation – Dirty COW (CVE-2016-5195)

Compiled and executed exploit to gain root access.

```
whoami
root
```

---

## 📊 CVSS Summary

| Vulnerability         | CVSS Score | Risk Level  |
|----------------------|:----------:|:-----------:|
| SQL Injection        | 9.8        | High        |
| Remote Code Execution| 10.0       | Critical    |
| Privilege Escalation | 7.8        | High        |

---

## 📝 Final Report

### Environment

- **Attacker Machine:** Kali Linux (192.168.237.3/24, VirtualBox)
- **Target Machine:** Metasploitable2 (192.168.237.4/24, VirtualBox)
- Both machines on the same host-only/NAT network

### Tools Used

Nmap, Metasploit, OWASP ZAP, Linux kernel exploit, etc.

### 1. Executive Summary

This penetration test simulated real-world attack scenarios on Metasploitable2 (192.168.237.4).  
**Objective:** Identify security vulnerabilities.  
**Risk Posture:** Highly vulnerable, with multiple critical weaknesses.  
**Key Findings:**
- 3 High-risk vulnerabilities (Remote Code Execution, SQL Injection, FTP Backdoor)
- 2 Medium-risk vulnerabilities (XSS, Weak SSH credentials)
- 1 Low-risk issue (Information Disclosure)

**Business Impact:**  
If exploited in production, vulnerabilities could lead to system compromise, data leakage, and unauthorized access.

### 2. Methodology

- Based on OWASP, PTES standards
- **Assessment Type:** Simulated penetration test

#### Phases:

- **Reconnaissance** (Skipped passive due to lab setup)
- **Active Reconnaissance:** Nmap scan for vulnerable services

```
nmap -sV -p- <192.168.237.4>
```

- **Vulnerability Assessment:** Nmap scripts (`--script vuln`)
- **Exploitation:** Metasploit modules (vsftpd_234_backdoor, samba/usermap_script)
- **Post-Exploitation:** Privilege escalation, enumeration, credential dumping
- **Web Application Testing:** OWASP ZAP scan, manual fuzzing

---

## 🔎 Findings

### 3.1 FTP Backdoor (vsftpd 2.3.4)

- **CVE:** CVE-2011-2523
- **CVSS:** 10.0 (Critical)
- **Impact:** Remote root shell access
- **Remediation:** Upgrade vsftpd, disable anonymous FTP.

### 3.2 Samba RCE (Usermap Script)

- **CVE:** CVE-2007-2447
- **CVSS:** 9.3 (High)
- **Impact:** Remote code execution
- **Remediation:** Patch Samba, restrict port 445.

### 3.3 SQL Injection in DVWA

- **CVSS:** 7.5 (High)
- **Impact:** Database access, data manipulation
- **Remediation:** Use parameterized queries, sanitize inputs.

### 3.4 XSS in Mutillidae

- **CVSS:** 6.1 (Medium)
- **Impact:** Session hijacking, defacement
- **Remediation:** Output encoding, use CSP headers.

### 3.5 Weak SSH Credentials

- **CVSS:** 5.0 (Medium)
- **Impact:** Unauthorized access
- **Remediation:** Enforce strong passwords, disable root login.

### 3.6 Information Disclosure via /etc/passwd

- **CVSS:** 3.5 (Low)
- **Impact:** User enumeration
- **Remediation:** Restrict file access, monitor enumeration attempts.

---

## 🛠️ Risk Summary

| Vulnerability         | CVSS Score | Severity | Status    |
|----------------------|:----------:|:--------:|:---------:|
| FTP Backdoor         | 10.0       | High     | Exploited |
| Samba RCE            | 9.3        | High     | Exploited |
| SQL Injection        | 7.5        | High     | Confirmed |
| XSS                  | 6.1        | Medium   | Confirmed |
| Weak SSH Credentials | 5.0        | Medium   | Exploited |
| Info Disclosure      | 3.5        | Low      | Confirmed |

---

## 🛡️ Remediation Recommendations

| Issue                | Recommendation                          |
|----------------------|-----------------------------------------|
| FTP Backdoor         | Upgrade vsftpd, disable anonymous access|
| Samba RCE            | Patch Samba, restrict port 445          |
| SQL Injection        | Use parameterized queries               |
| XSS                  | Sanitize inputs, apply output encoding  |
| Weak SSH Credentials | Enforce password complexity             |
| Info Disclosure      | Harden file permissions                 |

---

## 📁 Appendices

- **Tools Used:** Nmap, Metasploit, OWASP ZAP
- **References:** OWASP Top 10, CVE Details, NIST CVSS Calculator

---

## 🧹 Clean Up (Optional)

```
history -c
rm -rf /tmp/*
```

---

## 🧠 Summary

This project demonstrates practical penetration testing skills, using industry-standard tools and methodologies, on a safe and controlled environment.

---