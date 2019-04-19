#IMPORT IIS PS REQUIREMENTS BASED ON OS VERSION
if ([System.Version] (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion -ge [System.Version] "6.1") `
    {Import-Module WebAdministration -force} 
    else {
        Add-PSSnapin WebAdministration
    }
Stop-WebAppPool -Name ComparativeRater
Remove-WebAppPool ComparativeRater
remove-website -name ComparativeRater
Remove-Item -Path 'D:\inetpub\vserver\Raters' -Recurse -Force -Confirm:$false