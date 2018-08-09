@echo off
rem
rem Home: http://www.mh-sec.de/audit/
rem simple windows audit script by Marc Heuse mh@mh-sec.de
rem GPLv3 
rem
for /f "delims=" %%a in ('hostname') do @set HOST=%%a
set ADIR=AUDIT-%HOST%
IF NOT EXIST baseline.inf GOTO :error1
echo Creating the directory %ADIR% and storing audit files there
mkdir %ADIR%
IF NOT EXIST %ADIR% GOTO :error2
cd %ADIR%

set > env.txt
whoami /ALL /FO List > current_user.txt
systeminfo > systeminfo.txt
ipconfig /all > ipconfig.txt
net use > net_use.txt
net file > net_file.txt
net share > net_share.txt
net view > net_view.txt
net user > net_user.txt
net accounts > net_accounts.txt
net localgroup > net_localgroup.txt
schtasks.exe /query /FO CSV /V > jobs.txt
for /F "tokens=2*" %%i in (' sc query ^|findstr SERVICE_NAME: ') DO sc qc "%%i" >> services_details.txt
for /F "tokens=2*" %%i in (' sc query ^|findstr SERVICE_NAME: ') DO sc sdshow "%%i" >> services_perms.txt
for /F "tokens=2*" %%i in (' sc query ^|findstr SERVICE_NAME: ') DO for /F "tokens=3*" %%j in (' sc qc %%i ^|findstr BINARY_PATH_NAME ') DO cacls "%%j" >> services_exe_perms.txt
tasklist > tasklist.txt
sc queryex > services.txt
netstat -ano > netstat.txt
gpresult /scope computer /z > gpresult.txt
auditpol /get /Category:* > auditpol.txt

icacls c:\*.* /C /T >> perm_c.txt
:: icacls c:\*.* /C >> perm_root.txt
:: icacls c:\windows /C /T >> perm_win.txt
:: icacls c:\program* /C /T >> perm_prg.txt

echo. > registry.txt
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\policies\Explorer" /v "NoDriveTypeAutorun" >> registry.txt
reg query "HKLM\Security\Policy" /s >> registry.txt
reg query "HKLM\Software\Microsoft\Driver Signing" /v "Policy" >> registry.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" /v "SecurityLevel" >> registry.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" /v "SetCommand" >> registry.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /s >> registry.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" >> registry.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "PasswordExpiryWarning" >> registry.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /s >> registry.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCAD" >> registry.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DontDisplayLastUserName" >> registry.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s >> registry.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /s >> registry.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices" /s >> registry.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /s >> registry.txt
reg query "HKLM\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v "AuthenticodeEnabled" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /s >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v "EveryoneIncludesAnonymous" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v "FullPrivilegeAuditing" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v "LimitBlankPasswordUse" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v "NoLMHash" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v "AddPrinterDrivers" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" /v "Machine" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" /v "Machine" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Session Manager" /v "SafeDllSearchMode" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Session Manager\Kernel" /v "ObCaseInsensitive" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Control\Session Manager\SubSystems" /v "optional" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DynamicBacklogGrowthDelta" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "EnableDynamicBacklog" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "MaximumDynamicBacklog" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "MinimumDynamicBacklog" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\IPSEC" /v "NoDefaultExempt" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\LDAP" /v "LDAPClientIntegrity" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\LDAP" /v "LDAPClientIntegrity" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /s >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "RequireSecuritySignature" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /s >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnablePlainTextPassword" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\Netbt\Parameters" /v "NoNameReleaseOnDemand" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /s >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "RequireStrongKey" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "SealSecureChannel" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "SignSecureChannel" >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /s >> registry.txt
reg query "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /s >> registry.txt
reg query "HKLM\System\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" >> registry.txt
reg query "HKLM\System\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "ScreenSaverGracePeriod" >> registry.txt
schtasks.exe /query /FO CSV /V > jobs.txt

secedit /analyze /cfg ..\baseline.inf /db secpolcheck.sdb /log secpolcheck.log

goto :endup

:error1
echo.
echo ERROR: baseline.inf was not found
goto :done
:error2
echo.
echo ERROR: could not create data directory
goto :done

:endup
cd ..
echo.
echo.
echo.
echo Please copy the %ADIR% directory and hand the contents over to the auditor.
echo.
:done
