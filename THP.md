# THP Cheat Sheet

Overview cheatsheet made for myself while going through **eLearnSecurity's Threat Hunting Professional**. 

**Useful Links**
[The ThreatHunting Project](https://github.com/ThreatHuntingProject/ThreatHunting/tree/master/hunts)

# Network Traffic Hunting

## Hunting Tools
- Wireshark - [PA Toolkit Plugin](https://github.com/pentesteracademy/patoolkit)
- NetworkMiner
- RSA NetWitness Investigator

## ARP Theats
- Tens, hundreds etc of ARP broadcast messages in a small amount of time

- Two identical MAC addresses in the network with different IP addresses

- Gratuitous ARP packets sent by attacker
> **_Wireshark_** select View > Name Resolution > Resolve Physical Addresses
> Check Spam ARP Requests, timing etc

**Normal ARP**
```
Ethernet II, Src: (MACADDR), Dst: ff:ff:ff:ff:ff:ff:
Opcode: request (1)
Target MAC address: 00:00:00:00:00:00:
```
```
Ethernet II, Src: (MACADDR), Dst: 00:20:56:a2:f4:d0
Opcode: reply (2)
Sender MAC address: 00:20:56:a2:f4:d0
```
**Suspicious ARP**
```
Who has 10.10.10.1?	Tell 10.10.10.100
Who has 10.10.10.2?	Tell 10.10.10.100
Who has 10.10.10.3?	Tell 10.10.10.100
Who has 10.10.10.5? Tell 10.10.10.100
```
## ICMP Threats
- **Type 8** & **Code 0** indicate packet is an echo request

**Suspicious ICMP**
- Watch for sprays of ping requests
- Unusual type/codes within packets of the request. 
	- *IE: Time Stamp Requests*

## TCP Threats
*3-way handshack: SYN, SYN/ACK, ACK*
- SYN Packets sprays, smart TCP attacks, port scanning on single or multiple IPs
- Many TCP SYN packets without corresponding SYN/ACK packets

> [Wireshark TCP Reference](https://www.wireshark.org/docs/dfref/t/tcp.html)
> **_Wireshark_** Edit > Preferences > Protocols > TCP > *(Uncheck Box)*Relative sequence numbers

**Normal TCP**
```
Transmission Control Protocol, Seq: 0
Flags: 0x002 (SYN)
```
```
Transmission Control Protocol, Seq: 0, Ack: 1,
Flags: 0x012 (SYN, ACK)
[SEQ/ACK analysis]
[This is an ACK to the segment in frame: 2]
[The RTT to ACK the segment was: 0.0001100 seconds]
```
## DHCP Threats
DORA (DHCP Discover, DHCP Offer, DHCP Request, DHCP Acknowledgement)
*UDP Ports 67-68*
*Look for DHCP Server Identifier in Wireshark*

**DHCP**

```
User Datagram Protocol, Src Port: 68, Dst Port: 67
Bootstrap Protocol (Discover)
Options: (53) DHCP Message Type (Discover)
	Your (client) IP address: 0.0.0.0
	Length: 1
	DHCP: Discover (1)
```
```
Option: (53) DHCP Message Type (Offer)
	Length: 1
	DHCP: Offer (2)
```
## DNS Threats
- Port 53, should only be **UDP** not **TCP**
- DNS traffic should only go to DNS servers
- Should see DNS Responses to DNS Queries
> [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/d/dns.html)
> Look for DNS Queries with no DNS responses or vice versa.
> Zone Tranfers occur over TCP/53

## HTTP/HTTPS Threats
**HTTP**
Port 80, 8080 - plantext traffic, typically in FQDN format.

- Traffic should *not* be encrypted in common HTTP ports
- Search for URL encoded queries for sql injection, lfi-rfi activity
- User-Agent for possible scanners - *IE: sqlmap*
- TCP Spurious Retransmission -> Investigate [TCP Zero Window](https://wiki.wireshark.org/TCP%20ZeroWindow)

> **_Wireshark_** Statistics > Conversations >  TCP Tab
> **_Wireshark_** Statics > Protocol Hierarchy
> **_Wireshark_** File Export Objects > HTML
> **_Wireshark_** Statics > Endpoints
> **_Wireshark_** Statics > Conversions

Wireshark References
> HTTP Filters [here](https://www.wireshark.org/docs/dfref/h/http.html) and [here](https://www.wireshark.org/docs/dfref/h/http2.html)
> HTTPS Filters [here](https://www.wireshark.org/docs/dfref/s/ssl.html)

**HTTPS**
Ports 443, 8443 TCP Encrypted Traffic and in FQDN Format
- Look for traffic *not* encrypted and SSL packet details are empty
- Look for Server Key Exchange and Client key Exchange packet

**Normal HTTPS**
```
Content Type = Handshake
Handshake Protocol: Client Hello
Version: TLS 1.2
Cipher Suites: (11 suites)
Compression Method: (1 method)
```

## Unknown Traffic Threats
- Inspect protocols on network for strange protocols. *IE: IRC Chats, C2 Servers etc*
> **_Wireshark_** Analyze > Enable Protocols

# Webshell Analysis
- Reference suspicious files on servers/web servers
- Look for cmd.exe powershell.exe or eval()
- Analyze IIS and Apache logs
- Use baselines for locating new processes, drivers, intsalled applications, files/services
- Analyze suspicious JPEG images

**Webshell PHP Functions**
> eval()
> base64_decode()
> str_rot13()
> gzinflate()

**JPEG PHP Exif**
[exiftool(-k)](http://www.sno.phy.queensu.ca/~phil/exiftool/)
```
<?php
echo "Find file *.jpg :<br />\n List file may be negative :<br />\n";
$exifdata = array();
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator('.')) as $filename)
{
    //echo "$filename<br />\n";
        if      (strpos($filename,".jpg")==true or strpos($filename,".JPG")==true)
        {
                $exif = read_exif_data($filename);
/*1*/   if (isset($exif["Make"])) {
                        $exifdata["Make"] = ucwords(strtolower($exif["Make"]));
                        if (strpos($exifdata["Make"],"/e")==true) echo "$filename<br />\n";
                }
/*2*/   if (isset($exif["Model"])) {
                        $exifdata["Model"] = ucwords(strtolower($exif["Model"]));
                        if (strpos($exifdata["Model"],"/e")==true) echo "$filename<br />\n";
                }
/*3*/   if (isset($exif["Artist"])) {
                        $exifdata["Artist"] = ucwords(strtolower($exif["Artist"]));
                        if (strpos($exifdata["Artist"],"/e")==true) echo "$filename<br />\n";
                }
/*4*/   if (isset($exif["Copyright"])) {
                        $exifdata["Copyright"] = ucwords(strtolower($exif["Copyright"]));
                        if (strpos($exifdata["Copyright"],"/e")==true) echo "$filename<br />\n";
                }
/*5*/   if (isset($exif["ImageDescription"])) {
                        $exifdata["ImageDescription"] = ucwords(strtolower($exif["ImageDescription"]));
                        if (strpos($exifdata["ImageDescription"],"/e")==true) echo "$filename<br />\n";
                }
/*6*/   if (isset($exif["UserComment"])) {
                        $exifdata["UserComment"] = ucwords(strtolower($exif["UserComment"]));
                        if (strpos($exifdata["UserComment"],"/e")==true) echo "$filename<br />\n";
                }
        }
}
echo "Done!";
?>
```

**Linux Commands**
```
find. -type f -name '*.php' -mtime -1
find. -type f -name '*.txt' -mtime -1
find. -type f -name '*.php' | xargs grep -l "eval *("
find. -type f -name '*.txt' | xargs grep -l "eval *("
find. -type f -name '*.php' | xargs grep -l "base64_decode*("
```
```
find . -type f -name '*.php' | xargs grep -l "(mail|fsocketopen|pfsockopen|exec|system|passthru|eval|base64_decode) *\("
find . -type f -name '*.txt' | xargs grep -l "(mail|fsocketopen|pfsockopen|exec|system|passthru|eval|base64_decode) *\("
```
**Windows Commands**
[.ps1 scripts](https://github.com/securycore/ThreatHunting)
[Get-FullPathFileStacking.ps1](https://gist.github.com/anonymous/e8ced9c92a689e4cdb67fe0417cd272c)
[Get-TimeDiffFileStacking.ps1](https://gist.github.com/anonymous/dcfa7cb4933b30954737ccbf51024c1a)
[Get-W3WPChildren.ps1](https://gist.github.com/anonymous/140f4455ede789f7c3c3419946d1bd66)

```
get-childitem -recurse include "*.php" | select-string "(mail|fsockopen|pfsockopen|exec\b|system\b|passthru|eval\b|base64_decode)" | %{"$($_.filename):$($_.line)"}| Out-Gridview
```
**Webshell Toolkit**
[Log Parser Studio Tool](https://gallery.technet.microsoft.com/office/Log-Parser-Studio-cd458765) - IIS Web Logs


[Loki](https://github.com/loki-project/loki)
> MD5/SHA1/SHA256 hashes
> Yara rules
> Hard/soft filenames based on regular expressions

[NeoPI](https://github.com/Neohapsis/NeoPI)
> Python script - detect obfuscated/encrypted content

[BackdoorMan](https://github.com/cys3c/BackdoorMan)
> Python script - Detect malicious code in **PHP** scripts
> Detects shells via signature database
> Recognize web backdoors
> Use [shellray](https://shellray.com/)/[VirusTotal](https://virustotal.com/) and [UnPHP](http://www.unphp.net/)

[PHP-Malware-Finder](https://github.com/nbs-system/php-malware-finder)
> Find obfuscated code
> Yara Rules

[UnPHP](http://www.unphp.net/)
> Online PHP Obfuscator

[Web Shell Detector](http://www.shelldetector.com/)
> PHP, Perl, ASP and ASPX detection
> Signature database

[NPROCWATCH](http://udurrani.com/0fff/tl.html)
> Display new spawned processes after  NPROCWATCH was executed

*Others*
[Linux Malware Detect](https://www.rfxn.com/projects/linux-malware-detect/)
[Invoke-ExchangeWebShellHunter](https://github.com/FixTheExchange/Invoke-ExchangeWebShellHunter)

## Malware Analysis

**Windows Event Logs**

>Successful Logon (ID 4624)
>Failed Logon (ID 4625)
>Kerberos Authentication (ID 4768)
>Kerberos Service Ticket (ID 4776)
>Assignment of Administrator Rights (ID 4672)
>Unknown username or password (ID 529)
>Account logon time restriction violation (ID 530)
>Account currently disabled (ID 531)
>User account has expired (ID 532)
>User not allowed to logon to the computer (ID 533)
>User has not been granted the requested logon type (ID 534)
>The account's password has expired (ID 535)
>The NetLogon component is not active (ID 536)
>The logon attempt failed for other reasons (ID 537)
>Account lockout (ID 539)
>Log clearing (ID 1102 and 104)


**Detection Tools**

*PE Capture*
[PE Capture Service](http://www.novirusthanks.org/products/pe-capture-service/)
[NoVirusThanks](http://www.novirusthanks.org/products/pe-capture/)

[ProcScan](https://github.com/abhisek/RandomCode/tree/master/Malware/Process)
> Ruby script - x86-only memory analysis
[Meterpeter Payload Detection](https://github.com/DamonMohammadbagher/Meterpreter_Payload_Detection)
> Memory anaylsis for Meterpreter sessions

*Reflective Ijection Detection*
[Reflective Injection Detection](https://github.com/papadp/reflective-injection-detection)
[PowershellArsenal](https://github.com/mattifestation/PowerShellArsenal)
*NTQueryInformationThread Detection*
[Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

*Hash Fuzzing*
[SSDeep](https://github.com/ssdeep-project/ssdeep)

*Port Hashing*
[imphash](https://github.com/Neo23x0/ImpHash-Generator) - Generate PE 

*Execution Tracing*
[ShimCacheParser](https://github.com/mandiant/ShimCacheParser)
[AppCompatProcessor](https://github.com/mbevilacqua/appcompatprocessor)

**Memory Analysis**
- [Mandiant's Redline](https://www.fireeye.com/services/freeware/redline.html)
- [Volatility](https://github.com/volatilityfoundation/volatility): [Wiki](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage), [Windows Analysis](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal) and [Memory Samples](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)

## Powershell Tools
[Kansa](https://github.com/davehull/Kansa)
>Incident response, breach hunts, building baselines
> Reference links [here](http://trustedsignal.blogspot.com/search/label/Kansa) and [here](http://www.powershellmagazine.com/2014/07/18/kansa-a-powershell-based-incident-response-framework/)
[PSHunt](https://github.com/Infocyte/PSHunt)
>Scan remote endpoints for IOCS
[NOAH](https://github.com/giMini/NOAH)
