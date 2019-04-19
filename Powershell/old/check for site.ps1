if ($(Get-Website | Where-Object { $_.Name -eq 'Dannett' }))
{
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='DomainApplicationName'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='RedirectingDomainName'}
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='Scheme'}
	write-host "exists"
 }   
	else {
        	write-host "doesn't exist"
    		}