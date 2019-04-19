            #add allowed server variables in the URL rewrite module
			if ($(Get-Website | Where-Object { $_.Name -eq 'ProgressiveCom' }))
				{
                Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='DomainApplicationName'}
                Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='RedirectingDomainName'}
                Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='Scheme'}
				}
            #PATH additions
                $newPath = 'D:\inetpub\vserver\UBITrialCustomerExperience\bin;D:\inetpub\vserver\ProgressiveCom\bin' 
                $oldPath = [Environment]::GetEnvironmentVariable('path', 'machine');
                [Environment]::SetEnvironmentVariable('path', "$($oldPath);$($newPath)",'Machine'); 
                $newPATHEXT = 'DLL' 
                $oldPATHEXT = [Environment]::GetEnvironmentVariable('PATHEXT', 'machine'); 
                [Environment]::SetEnvironmentVariable('PATHEXT', "$($oldPATHEXT);$($newPATHEXT)",'Machine');
            #add local user
                Add-LocalGroupMember -Group L-Z-APPLICATIONS -member "IUSR"
            #registry check
                function Test-WEbconfigRegistry
					{
					$path = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp\Configuration'
					$value = 'MaxWebConfigFileSizeInKB'
					Try
					{
					Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object -ExpandProperty $value -ErrorAction STop | Out-Null
					Set-ItemProperty -Path $path -Name MaxWebConfigFileSizeInKB -Value 500 -ErrorAction Stop
					Write-Host "Key was already there and was updated.  Please verify in regedit"
					Return $true
					}
					Catch
					{
					$createpath = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp'
					New-Item -path $createpath -Name Configuration 
					New-ItemProperty -Path $path -Name MaxWebConfigFileSizeInKB -Value 500 -PropertyType DWORD
					Write-Host "key successfully CREATED and Updated Please Verify"
					Return $false
					}
					}
				Test-WEbconfigRegistry
				IISReset