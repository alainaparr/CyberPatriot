:: Make sure to run the file with elevated privileges aka "Run as administrator"
@echo off
::
:: 
 start "" https://cryptii.com/
 ::
:: Calls and runs the Windows_Defender_Hardner powershell script --- keep this and the Windows_Defender_Hardner script in the same directory or this will fail
:: ---------------------
SET ThisScriptsDirectory=%~dp0
SET PowerShellScriptPath=%ThisScriptsDirectory%Windows_Defender_Hardner.ps1
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%PowerShellScriptPath%""' -Verb RunAs}";
::
:: Calls and runs the Malwarebytes_Anti-Rootkit.ps1 powershell script --- keep this and the Malwarebytes_Anti-Rootkit.ps1 script in the same directory or this will fail
:: This will find and remove rootkits and fix any damage they caused 
:: --------------------------------
SET ThisScriptsDirectory=%~dp0
SET PowerShellScriptPath=%ThisScriptsDirectory%Malwarebytes_Anti-Rootkit.ps1
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%PowerShellScriptPath%""' -Verb RunAs}";
::
:: Change file associations to protect against common ransomware attacks
:: Note that if you legitimately use these extensions, like .bat, you will now need to execute them manually from cmd or powershel
:: Alternatively, you can right-click on them and hit 'Run as Administrator' but ensure it's a script you want to run :) 
:: ---------------------
ftype htafile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype wshfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype wsffile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype batfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype jsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype jsefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype vbefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype vbsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
::
::
:: Harden all version of MS Office itself against common malspam attacks & disables macros, enables protected view
:: ---------------------
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\19.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\19.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\19.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\19.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\19.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\19.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
::
:: Harden all version of MS Office itself against DDE malspam attacks & disables macros, enables protected view
:: ---------------------
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
::
:: Updates Password & Account Policies
:: ---------------------
:: Enable Password Expiration for Local Accounts
wmic UserAccount set PasswordExpires=True 
:: Disable the use of same password upon expiration, maximum value is 24
net accounts /uniquepw:5
:: Minimum password age
net accounts /minpwage:15 
:: Maximum password age
net accounts /maxpwage:99
:: Minimum password length
net accounts /minpwlen:10   
:: Account lockout duration
net accounts /lockoutduration:30
:: Maximum number of login attempts
net accounts /lockoutthreshold:7
:: Account Lockout Counter for Local Accounts i.e, account lockout observation window
net accounts /lockoutwindow:30
::
:: Configures Audit Policy
:: Will throw a "'Failure' is not recognized as an internal or external command, operable program or batch file." but still enables both so just ignore it ig?
:: ---------------------
:: Process Tracking: Success & Failure
auditpol /set /category:"Detailed Tracking" /Success:enable /failure:enable
:: Account Management: Success & Failure
auditpol /set /category:"Account Management" /Success:enable /failure:enable
:: Audit directory service access: Success & Failure
auditpol /set /category:"DS access" /Success:enable /failure:enable
:: Logon Events: Success & Failure
auditpol /set /category:"Logon/Logoff" /Success:enable /failure:enable
:: Account Logon Events: Success & Failure
auditpol /set /category:"Account Logon" /Success:enable /failure:enable
:: Audit object access: Success & Failure
auditpol /set /category:"Object access" /Success:enable /failure:enable
:: Audit policy change: Success & Failure
auditpol /set /category:"Policy change" /Success:enable /failure:enable
:: Audit privilege use: Success & Failure
auditpol /set /category:"Privilege use" /Success:enable /failure:enable
:: Audit system events: Success & Failure
auditpol /set /category:"System" /Success:enable /failure:enable
::
:: Changes security options
:: ---------------------
:: Enables Ctrl-Alt-Del for Logon Screen
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DisableCAD" /t REG_DWORD /d 0 /f
::
:: Shows all hidden files 
:: ---------------------
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V Hidden /T REG_DWORD /D 1 /F
:: Restarts expolorer process which is mandatory after making registry change
taskkill /f /im explorer.exe
start explorer.exe
::
:: Find's media and pciture files and compiles them is a txt file so you can go through and delete the relevant ones
:: ---------------------
color 0f
echo Flashing Disk to .flashed Files to reference....
dir /b /s "C:\Program Files\" > programfiles.flashed
dir /b /s "C:\Program Files (x86)\" >> programfiles.flashed
echo Program Files flashed
dir /b /s "C:\Users\" > users.flashed
dir /b /s "C:\Documents and Settings" >> users.flashed
echo User profiles flashed
dir /b /s "C:\" > c.flashed
echo C:\ Flashed
pause
echo Finding media files in C:\Users and/or C:\Documents and Settings...
findstr .mp3 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp3 > media_audio
findstr .ac3 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.ac3 >> media_audio
findstr .aac users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.aac >> media_audio
findstr .aiff users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.aiff >> media_audio
findstr .flac users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.flac >> media_audio
findstr .m4a users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m4a >> media_audio
findstr .m4p users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m4p >> media_audio
findstr .midi users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.midi >> media_audio
findstr .mp2 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp2 >> media_audio
findstr .m3u users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.m3u >> media_audio
findstr .ogg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.ogg >> media_audio
findstr .vqf users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.vqf >> media_audio
findstr .wav users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.wav >> media_audio
findstr .wma users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.wma >> media_video
findstr .mp4 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.mp4 >> media_video
findstr .avi users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.avi >> media_video
findstr .mpeg4 users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .mpeg4 >> media_video
REM BREAKLINE
findstr .gif users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.gif >> media_pics
findstr .png users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.png >> media_pics
findstr .bmp users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ *.bmp >> media_pics
findstr .jpg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .jpg >> media_pics
findstr .jpeg users.flashed >NUL
if %errorlevel%==0 where /r c:\Users\ .jpeg >> media_pics
C:\WINDOWS\system32\notepad.exe media_video
C:\WINDOWS\system32\notepad.exe media_audio
C:\WINDOWS\system32\notepad.exe media_pics
echo Finding Hacktools now...
findstr "Cain" programfiles.flashed
if %errorlevel%==0 (
echo Cain detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "nmap" programfiles.flashed
if %errorlevel%==0 (
echo Nmap detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "keylogger" programfiles.flashed
if %errorlevel%==0 (
echo Potential keylogger detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Armitage" programfiles.flashed
if %errorlevel%==0 (
echo Potential Armitage detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Metasploit" programfiles.flashed
if %errorlevel%==0 (
echo Potential Metasploit framework detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Shellter" programfiles.flashed
if %errorlevel%==0 (
echo Potential Shellter detected. Please take note, then press any key.
pause >NUL
)
cls
::
:: Windows auomatic updates
:: ---------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
::
:: Turns on UAC
:: ---------------------
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
::
:: Turns off RDP
:: ---------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
::
:: Enable exploit protection (EMET on Windows 10)
:: ---------------------
powershell.exe Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/ProcessMitigation.xml -OutFile ProcessMitigation.xml
powershell.exe Set-ProcessMitigation -PolicyFilePath ProcessMitigation.xml
del ProcessMitigation.xml
::
:: Prevent Local windows wireless exploitation: the Airstrike attack https://shenaniganslabs.io/2021/04/13/Airstrike.html
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f
::
:: Enable SMB/LDAP Signing
:: Sources:
:: http://eddiejackson.net/wp/?p=15812
:: https://en.hackndo.com/ntlm-relay/
:: ---------------------
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
:: 1- Negotiated; 2-Required
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 2 /f
reg add "HKLM\System\CurrentControlSet\Services\ldap" /v "LDAPClientIntegrity " /t REG_DWORD /d 1 /f
::
:: Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
:: Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
:: Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
::
:: Enable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f
::
:: Prioritize ECC Curves with longer keys
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v EccCurves /t REG_MULTI_SZ /d NistP384,NistP256 /f
:: Prevent Kerberos from using DES or RC4
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
:: Encrypt and sign outgoing secure channel traffic when possible
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
::

::
:: Enforce device driver signing
BCDEDIT /set nointegritychecks OFF
::
:: Prevents powershell from auto-closing after the script is executed. 
:: ---------------------
pause
