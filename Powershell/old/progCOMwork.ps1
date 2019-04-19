\\add allowed server variables in the URL rewrite module
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='DomainApplicationName'}
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='RedirectingDomainName'}
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='Scheme'}


<Action Type="Powershell.ExecuteCommand">
            <Param Name="PSScript">
            \\add allowed server variables in the URL rewrite module
                Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='DomainApplicationName'}
                Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='RedirectingDomainName'}
                Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='Scheme'}
            \\PATH additions
                $newPath = 'D:\inetpub\vserver\UBITrialCustomerExperience\bin;D:\inetpub\vserver\ProgressiveCom\bin' 
                $oldPath = [Environment]::GetEnvironmentVariable('path', 'machine');
                [Environment]::SetEnvironmentVariable('path', "$($oldPath);$($newPath)",'Machine'); 
                $newPATHEXT = 'DLL' 
                $oldPATHEXT = [Environment]::GetEnvironmentVariable('PATHEXT', 'machine'); 
                [Environment]::SetEnvironmentVariable('PATHEXT', "$($oldPATHEXT);$($newPATHEXT)",'Machine');
            \\add local user
                Add-LocalGroupMember -Group L-Z-APPLICATIONS -member "IUSR"
            \\set strong crypto
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
			</Param>
		</Action>  
 


\\PATH additions
$newPath = 'D:\inetpub\vserver\UBITrialCustomerExperience\bin;D:\inetpub\vserver\ProgressiveCom\bin' 
$oldPath = [Environment]::GetEnvironmentVariable('path', 'machine');
[Environment]::SetEnvironmentVariable('path', "$($oldPath);$($newPath)",'Machine'); 
$newPATHEXT = 'DLL' 
$oldPATHEXT = [Environment]::GetEnvironmentVariable('PATHEXT', 'machine'); 
[Environment]::SetEnvironmentVariable('PATHEXT', "$($oldPATHEXT);$($newPATHEXT)",'Machine');





\\add local user
Add-LocalGroupMember -Group L-Z-APPLICATIONS -member "IUSR"

<Action Type="Security.AddToLocalGroup">
			<Param Name="Group" Comment="required, single">Local AD group</Param>
			<Param Name="Add" Comment="optional, list; format=domain\account">IUSR</Param>
		</Action>





\\set strong crypto
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord


<Action Type="Registry.AddValue">
			<Param Name="Hive" Comment="required, single; enum=HKEY_LOCAL_MACHINE,HKEY_CURRENT_USER,HKLM,HKCU">HKEY_LOCAL_MACHINE</Param>
			<Param Name="Key" Comment="required, single; format=registry\path">SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319</Param>
			<Param Name="Value" Comment="required, single">SchUseStrongCrypto</Param>
			<Param Name="Type" Comment="optional, single; enum=REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY; defaults to REG_SZ">REG_DWORD</Param>
			<Param Name="Data" Comment="required, single">1</Param>
        </Action>
<Action Type="Registry.AddValue">
        <Param Name="Hive" Comment="required, single; enum=HKEY_LOCAL_MACHINE,HKEY_CURRENT_USER,HKLM,HKCU">HKEY_LOCAL_MACHINE</Param>
        <Param Name="Key" Comment="required, single; format=registry\path">SOFTWARE\Microsoft\.NetFramework\v4.0.30319</Param>
        <Param Name="Value" Comment="required, single">SchUseStrongCrypto</Param>
        <Param Name="Type" Comment="optional, single; enum=REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY; defaults to REG_SZ">REG_DWORD</Param>
        <Param Name="Data" Comment="required, single">1</Param>
    </Action>






\\create webguard eventlog
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application' -Name 'WebGuard'

<Action Type="Registry.AddKey">
			<Param Name="Hive" Comment="required, single; enum=HKEY_LOCAL_MACHINE,HKEY_CURRENT_USER,HKLM,HKCU">HKEY_LOCAL_MACHINE</Param>
			<Param Name="Key" Comment="optional, list; key to add">SYSTEM\CurrentControlSet\Services\EventLog\Application\WebGuard</Param>
		</Action>


\\add value to new key
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\WebGuard' -Name EventMessageFile -Value 'C:\Windows\Microsoft.NET\Framework\v2.0.50727\EventLogMessages.dll'

<Action Type="Registry.AddValue">
			<Param Name="Hive" Comment="required, single; enum=HKEY_LOCAL_MACHINE,HKEY_CURRENT_USER,HKLM,HKCU">HKEY_LOCAL_MACHINE</Param>
			<Param Name="Key" Comment="required, single; format=registry\path">SYSTEM\CurrentControlSet\Services\EventLog\Application\WebGuard</Param>
			<Param Name="Value" Comment="required, single">EventMessageFile</Param>
			<Param Name="Type" Comment="optional, single; enum=REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY; defaults to REG_SZ">REG_SZ</Param>
			<Param Name="Data" Comment="required, single">C:\Windows\Microsoft.NET\Framework\v2.0.50727\EventLogMessages.dll</Param>
		</Action>
		