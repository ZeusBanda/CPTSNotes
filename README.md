# Network Enumeration with Nmap
## Discover Alive Hosts
```
nmap 10.129.2.0/24 -sn -oA alive_hosts | grep for | cut -d" " -f5
```

## Nmap host scans
```
nmap
nmap -sS -p- -A 10.129.2.1 -oA ss_host_scan
nmap -sT -p- -A 10.129.2.1 -oA st_host_scan
nmap -F -sU 10.129.2.1 -oA su_host-scan
```

## Vulnerability Scan
```
nmap 10.129.2.1 -p- -A --script vuln
```

## DNS Proxying
```
nmap -sS -p- -A 10.129.2.1 -oA ss_dns_host_scan --source-port 53
```

# Footprinting
## Infrastructure Enumeration

## Host Based Enumeration
### FTP
### SMB
### NFS
### DNS
### SMTP
### IMAP/POP3
### SNMP
### MySQL
### MSSQL
### Oracle TNS
### IPMI


## Remote Management Protocols
### Linux Remote Management Protocols
### Windows Remote Management Protocols

# Information Gathering - Web Edition

# Vulnerability Assessment

# File Transfers

# Shells & Payloads

# Password Attacks

# Attacking Common Services

# Pivoting, Tunneling, and Port Forwarding

# Active Directory Enumeration & Attacks

# Using Web Proxies

# Attacking Web Applications with Ffuf

# Login Brute Forcing

# SQL Injection Fundamentals

# SQLMap Essentials

# Cross-Site Scripting (XSS)

# File Inclusion

# File Upload Attacks

# Command Injections

# Web Attacks

# Attacking Common Applications

# Linux Privilege Escalation

# Windows Privilege Escalation

# Documentation & Reporting

# Attacking Enterprise Networks
