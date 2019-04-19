#IMPORT IIS PS REQUIREMENTS BASED ON OS VERSION
if ([System.Version] (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion -ge [System.Version] "6.1") `
    {Import-Module WebAdministration -force} 
    else {
        Add-PSSnapin WebAdministration
    }
Remove-WebConfigurationProperty  -pspath 'MACHINE/WEBROOT/APPHOST/ProgressiveCom'  -filter "system.webServer/rewrite/allowedServerVariables" -name "."
Stop-WebAppPool -Name Privacy
Stop-WebAppPool -Name ProgressiveCOM
Stop-WebAppPool -Name ProgressiveProxy
Stop-WebAppPool -Name TestDriveEnroll
Stop-WebAppPool -Name UBITrialCustomer
Remove-WebAppPool Privacy
Remove-WebAppPool ProgressiveCOM
Remove-WebAppPool ProgressiveProxy
Remove-WebAppPool TestDriveEnroll
Remove-WebAppPool UBITrialCustomer
remove-website -name Privacy
remove-website -name ProgressiveCOM
remove-website -name ProgressiveProxy
Remove-Item -Path 'd:\inetpub\vserver\ResourceCenter' -Recurse -Force -Confirm:$false
Remove-Item -Path 'd:\inetpub\vserver\ProgressiveCom' -Recurse -Force -Confirm:$false
Remove-Item -Path 'd:\inetpub\vserver\ProgressiveProxy' -Recurse -Force -Confirm:$false
Remove-LocalGroupMember -Group "Administrators" -Member "PROGdmzq\d-z-scmpromotion-S", "PROGdmzq\Q-Z-SCMProMotion-S", "PRogdmzq\D-A-Homepage-S", "Progdmzq\q-a-homepage-s", "Progdmzq\q-a-homepage-TA-s", "Progdmzq\q-a-PAITWEB-APPDEV-S", "Progdmzq\q-L-PTST-S", "Progdmzq\S-DBA-DB2WIN-TA"
Remove-LocalGroupMember -Group "L-Z-APPLICATIONS" -Member "PROGDMZQ\ZHBLG01Q", "PROGDMZQ\zhmpg01t", "PROGDMZQ\ZSTATI1Q", "PROGDMZQ\ZUBI002Q"
Remove-LocalGroupMember -Group "L-FILE-READ" -Member "PROGDMZQ\Q-R-PAITWEB-APPDEV-S", "PROGDMZQ\S-A-SECSCAN-S", "PROGDMZQ\S-R-DSEINTG-S", "PROGDMZQ\S-R-DSEPLAT-S", "PROGDMZQ\S-R-PRODCNTRL-S"
Remove-LocalGroupMember -Group "L-File-Change" -Member "progdmzq\D-L-ASPSCONFIG-S", "progdmzq\S-L-EMON-S"