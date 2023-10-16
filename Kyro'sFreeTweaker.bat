@echo off
CLS
color 5
echo.
echo Kyro's Premium Tweaker
echo.

ECHO :?77?!        ^7?7?77?77?7.         ~?77?7: !?777777777777!~:.          :~!7??????7!~:
ECHO  ^JJJJ7      ^7JJJJ7:.7JJJJ?:      .7JJJJ7.  7JJJJJJJJJJJJJJJJ?~      .~?JJJJJJJJJJJJJJ7~.
ECHO  ^JJJJ7    ^7JJJJ!:    ~?JJJJ~    :?JJJJ~    7JJJJ!:::::^^!?JJJJ!    ^?JJJJ?7~^^^^~7?JJJJ?:
ECHO  ^JJJJ7  ^7JJJJ!:       :?JJJJ!  ~JJJJ?:     7JJJJ^        ^JJJJ?.  ~JJJJ?~.        .!JJJJJ^
ECHO  ^JJJJ?^7JJJJ7.          .!JJJJ7!JJJJ!.      7JJJJ^        ~JJJJ?. :JJJJ?:   ^~~~~:   ~JJJJ?.
ECHO  ^JJJJJJJJJJJ7:            ^?JJJJJJJ~        7JJJJ!^~~~~~~7JJJJ?^  ^JJJJ7    7JJJJ~    ?JJJJ:
ECHO  ^JJJJJJ?!?JJJJ!.           :?JJJJ?:         7JJJJJJJJJJJJJJ??!.   ^JJJJ?.   !????~   :?JJJJ.
ECHO  ^JJJJ?~. .!JJJJ?^           ~JJJJ!          7JJJJ7!!!7JJJJJ~       7JJJJ7.          :?JJJJ!
ECHO  ^JJJJ7     ^?JJJJ7.         !JJJJ!          7JJJJ^    ^?JJJJ!.     .7JJJJ?!^..  ..^!JJJJJ!
ECHO  ^JJJJ7      .!JJJJ?~        !JJJJ!          7JJJJ^     .7JJJJ?:      ~?JJJJJ??????JJJJJ7^
ECHO  ^JJJJ7        ^?JJJJ7:      !JJJJ!          7JJJJ^       ~?JJJJ!.     .^!??JJJJJJJJ?7!:
ECHO  .:::::         .::::::      .::::.          :::::.        .::::^.         .:^~~~~^:.
ECHO.

:: Check for admin privileges using PowerShell
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' (
    goto :gotAdmin
) else (
    echo Requesting administrative privileges...
    powershell -command "Start-Process -filepath '%0' -ArgumentList '-Admin' -verb RunAs"
    exit
)

:gotAdmin

:MainMenu
ECHO 1. FPS Tweaks
ECHO 2. Latency Tweaks
ECHO 3. KBM Tweaks
ECHO 4. Network Tweaks
ECHO 5. Remove Bloatware
ECHO 6. Discord
ECHO 7. Exit
ECHO 8. Win32PrioritySeparation
ECHO.

CHOICE /C 12345678 /M "Enter your choice:"

IF ERRORLEVEL 8 GOTO Win32PrioritySeparation
IF ERRORLEVEL 7 GOTO ExitScript
IF ERRORLEVEL 6 GOTO JoinDiscord
IF ERRORLEVEL 5 GOTO RemoveBloatware
IF ERRORLEVEL 4 GOTO NetworkTweaks
IF ERRORLEVEL 3 GOTO KBMTweaks
IF ERRORLEVEL 2 GOTO LatencyTweaks
IF ERRORLEVEL 1 GOTO FPSTweaks

:FPSTweaks
echo Running FPS Tweaks...
powercfg -setactive 5b5dc00d-28b0-4ae4-b541-0067b7e3b065
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DisableDynamicPstate /t REG_DWORD /d 1 /f
powercfg -change -standby-timeout-ac 0
powercfg -change -hibernate-timeout-ac 0
powercfg -change -monitor-timeout-ac 0
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v EnergyEstimationEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v PerfCalculateActualUtilization /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 4294967295 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v DisableCudaContextPreemption /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v DisablePreemption /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v DisableWriteCombining /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v ThreadPriority /t REG_DWORD /d 31 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\nvlddmkm" /v "0x1194f158" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\nvlddmkm" /v "0x11e91a61" /t REG_DWORD /d 4294967295 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\nvlddmkm" /v "0x115fb4e6" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" /v "RM1292711" /t REG_DWORD /d 3 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" /v "RM1441072" /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" /v "RM1457588" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" /v "OverrideMaxPerf" /t REG_DWORD /d 4294967295 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" /v "PowerSavingTweaks" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v EnableMMAgent /t REG_DWORD /d 0 /f
pause
goto MainMenu

:LatencyTweaks
echo Running Latency Tweaks...
bcdedit /deletevalue useplatformclock
bcdedit /deletevalue useplatformtick
bcdedit /set disabledynamictick yes
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v GlobalTimerResolutionRequests /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Throttle" /v PerfEnablePackageIdle /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d "5" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\iaStor\Parameters\Port0" /v "Aggressive Link Power Management (ALPM)" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\501a4d13-42af-4429-9fd1-a8218c268e20\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbhub" /v "DisableOnSoftRemove" /t REG_DWORD /d 1 /f
pause
goto MainMenu

:KBMTweaks
echo Running KBM Tweaks...

:: Ignore under 0ms
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f

:: Set repeat delay to 125ms
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatDelay" /t REG_SZ /d "100" /f

:: Set repeat rate to 25ms
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatRate" /t REG_SZ /d "25" /f

:: Enable the tweaks
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "On" /t REG_SZ /d "1" /f

echo KBM tweaks applied.
pause
goto MainMenu

:NetworkTweaks
echo Running Network Tweaks...
:: Disable NetBIOS over TCP/IP on all network adapters
for /f "tokens=*" %%a in ('wmic nicconfig where "TcpipNetbiosOptions=2" get Index /format:table ^| findstr /r [0-9]') do (
    set Index=%%a
    netsh interface ipv4 set interface !Index! dadnsregistered=disabled
    netsh interface ipv6 set interface !Index! dadnsregistered=disabled
)

REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "EnableDynamicPowerGating" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "EnableSavePowerNow" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "NicAutoPowerSaver" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "LatencySensitive" /t REG_SZ /d "True" /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\NDIS\Parameters" /v "EnableNicAutoPowerSaverInSleepStudy" /t REG_DWORD /d 0 /f\
netsh interface teredo set state disabled
netsh interface ipv6 set teredo client
netsh interface ipv6 set state disabled
netsh int tcp set global autotuninglevel=disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d 1 /f
netsh int tcp set global sack=disabled
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NonBestEffortLimit /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v RegistrationEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d 65536 /f
netsh int tcp set global rss = enabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndis\Parameters" /v "RssBaseCpu" /t REG_DWORD /d 1 /f
netsh int tcp set global windowsscaling=disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d 1 /f
netsh interface ipv4 set global mldnsresponder=disabled
:: Disable autotuning
netsh interface tcp set global autotuning=disabled

:: Disable Windows scaling heuristics
netsh interface tcp set heuristics disabled

:: Set congestion control provider to CTCP
netsh interface tcp set global congestionprovider=ctcp

:: Enable RSS
netsh int tcp set global rss=enabled

:: Enable RSC
netsh int tcp set global rsc=enabled

:: Set MTU to 1500
netsh interface ipv4 set subinterface "Local Area Connection" mtu=1500 store=persistent
netsh interface ipv6 set subinterface "Local Area Connection" mtu=1500 store=persistent

:: Enable ECN Capability
netsh interface tcp set global ecncapability=enabled

:: Enable checksum offloading
netsh int tcp set global checksum=enabled

:: Disable chimney offload
netsh int tcp set global chimney=disabled

:: Disable LSO (Large Send Offload)
netsh int tcp set global lso=disabled

:: Disable TCP 1323 timestamps
netsh int tcp set global timestamps=disabled

:: Set max connections per server
netsh int ipv4 set dynamicport tcp maxuserport=65534

:: Set max connections per server
netsh int ipv4 set dynamicport tcp minuserport=2000

:: Set local priority to 4, host priority to 5, DNS priority to 6, NetBT priority to 7
netsh interface ipv4 set interface "Local Area Connection" metric=4
netsh interface ipv4 set interface "Local Area Connection" metric=5 store=persistent
netsh interface ipv4 set interface "Local Area Connection" metric=6 store=persistent
netsh interface ipv4 set interface "Local Area Connection" metric=7 store=persistent

:: Set max syn retransmissions to 2
netsh interface tcp set global maxsynretransmissions=2

:: Disable non-SACK RTT Resiliency
netsh interface tcp set global nonsackrttresiliency=disabled

:: Set initial RTO to 2000 and minimum RTO to 300
netsh interface tcp set global initialRto=2000
netsh interface tcp set global initialRto=300 store=persistent

:: Set non-best effort limit to 0
netsh int tcp set global rwinlimit=0

:: Set network throttling and system responsiveness
netsh int tcp set global congestionprovider=none
netsh int tcp set global ecncapability=disabled

:: Disable TCP no delay
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpDelAckTicks" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f

:: Disable TCP delayed ACKs
:: Set LSO (Large Send Offload) size to 3
netsh interface ipv4 set global lsov2=3

:: Set TCP timed wait delay to 32
netsh interface ipv4 set global tcpmaxdataretransmissions=32

echo Network and TCP/IP settings configured successfully.
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d 0 /f


pause
goto MainMenu

:RemoveBloatware
echo Removing Bloatware...
:: Close OneDrive
echo Closing OneDrive process...
taskkill /f /im OneDrive.exe >NUL
ping 127.0.0.1 -n 5 >NUL

:: Uninstall OneDrive
echo Uninstalling OneDrive...
%SYSTEMROOT%\System32\OneDriveSetup.exe /uninstall >NUL

:: Remove OneDrive leftovers
echo Removing OneDrive leftovers...
rd /s /q "%USERPROFILE%\OneDrive" >NUL
rd /s /q "C:\OneDriveTemp" >NUL
rd /s /q "%LOCALAPPDATA%\Microsoft\OneDrive" >NUL
rd /s /q "%LOCALAPPDATA%\OneDrive" >NUL
rd /s /q "%PROGRAMDATA%\Microsoft OneDrive" >NUL 

:: Remove OneDrive from the Explorer Side Panel
echo Removing OneDrive from the Explorer Side Panel...
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >NUL
REG DELETE "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >NUL
echo.

:: Disable Windows services
echo Disabling Windows services...
:: Modify the registry to prevent updates
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "AUOptions" /t REG_DWORD /d 1 /f
:: Disable Windows Search (WSearch)
sc config WSearch start=disabled
:: Disable Windows Defender
sc config WinDefend start=disabled
:: Disable Windows Error Reporting Service
sc config WerSvc start=disabled
:: Disable Windows Update
sc config wuauserv start=disabled
:: Disable Windows Firewall
sc config MpsSvc start=disabled
:: Disable Print Spooler
sc config Spooler start=disabled
:: Disable Remote Registry
sc config RemoteRegistry start=disabled
:: Disable Themes
sc config Themes start=disabled
:: Disable Tablet PC Input Service
sc config TabletInputService start=disabled
:: Disable Remote Desktop Services
sc config TermService start=disabled
:: Disable Windows Insider Service
sc config WaaSMedicSvc start=disabled
:: Disable Connected User Experiences and Telemetry
sc config DiagTrack start=disabled
:: Disable Superfetch (SysMain)
sc config SysMain start=disabled
:: Disable Secondary Logon
sc config seclogon start=disabled
:: Disable Windows Security Center Service
sc config wscsvc start=disabled
:: Disable Windows Search (WSearch)
sc config WSearch start=disabled
echo.

:: Delete Microsoft Edge and associated files
echo Removing Microsoft Edge...
call :killdir C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe
call :killdir "C:\Program Files (x86)\Microsoft\Edge"
call :killdir "C:\Program Files (x86)\Microsoft\EdgeUpdate"
call :killdir "C:\Program Files (x86)\Microsoft\EdgeCore"
call :killdir "C:\Program Files (x86)\Microsoft\EdgeWebView"
echo.

:: Modify the registry to prevent Edge updates
echo Modifying registry to prevent Edge updates...
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d 1 /f
echo.

:: Remove Edge shortcuts
echo Removing Edge shortcuts...
call :delshortcut "C:\Users\Public\Desktop\Microsoft Edge.lnk"
call :delshortcut "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
call :delshortcut "%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk"
echo.

:: Additional cleanup
echo Performing additional cleanup...
rmdir /s /q "C:\Program Files (x86)\Microsoft\Temp" >NUL
:: End of the script
echo Script completed.
pause
goto MainMenu

:JoinDiscord
start https://discord.gg/p7QTppDeSa
goto MainMenu

:ExitScript
exit

:Win32PrioritySeparation
ECHO 1. 2A Smoother Gameplay
ECHO 2. 28 Less Delay
ECHO.

CHOICE /C 12 /M "Choose an option (1/2):"

IF ERRORLEVEL 2 GOTO LessDelay
IF ERRORLEVEL 1 GOTO SmootherGameplay

:SmootherGameplay
ECHO Setting Win32PrioritySeparation to 0x2A (Smoother Gameplay)...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x2A /f
pause
goto MainMenu

:LessDelay
ECHO Setting Win32PrioritySeparation to 0x28 (Less Delay)...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 0x28 /f
pause
goto MainMenu