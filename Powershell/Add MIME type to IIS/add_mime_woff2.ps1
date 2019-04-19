# #############################################################################
# POWERSHELL
# NAME: add_mime_woff2.ps1
# 
# AUTHOR:  David Annett
# DATE:  3/12/2019
# 
# COMMENT:  This script will add the .woff2 mime type and font to IIS
#
# #############################################################################

# #############################################################################
#functions
     function LoadAdminModules
    {
        if ([System.Version] (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion -ge [System.Version] "6.1") `
            {Import-Module WebAdministration -force} 
            else {
                Add-PSSnapin WebAdministration
            }
    }
# #############################################################################

#begin transcript
$scriptfullname = $MyInvocation.MyCommand.Definition
$scriptnameless = $scriptfullname -replace ".{4}$"
$ScriptDir = (Split-Path $MyInvocation.MyCommand.Path) + "\"
Start-transcript -path $scriptnameless'_logfile.txt' -append

LoadAdminModules

Write-host -fore cyan "Checking for Mime type .Woff2"
if( !((Get-WebConfiguration //staticcontent).collection | ? {$_.fileextension -eq '.woff2'}) ) {
    add-webconfigurationproperty //staticContent -name collection -value @{fileExtension='.woff2'; mimeType='font/woff2'}
    if((Get-WebConfiguration //staticcontent).collection | ? {$_.fileextension -eq '.woff2'}) {
        Write-host -fore green "Mime type added and verified"
  }
    else {
        Write-host -fore cyan "Mime type not added"
    }
}
Else{
    Write-host -fore red "Mime type already there"
}  

# #############################################################################
# end of script
Stop-transcript