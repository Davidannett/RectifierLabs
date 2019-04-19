# #############################################################################
# POWERSHELL
# NAME: script.ps1
# 
# AUTHOR:  David Annett
# DATE:  3/20/19
# 
# COMMENT:  This script will....
#
# TO ADD
# 
# 
# #############################################################################

# #############################################################################
#functions
function LoadAdminModules
{
    if ([System.Version] (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion -ge [System.Version] "6.1"){
        if (Get-Module -ListAvailable -Name WebAdministration){
            Import-Module WebAdministration -force
        }
    } 
        else {
            Add-PSSnapin WebAdministration
        }
}
# #############################################################################

#relaunches session if not opened as administrator
$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}"' -f ($myinvocation.MyCommand.Definition))
    exit
    }


#begin transcript
$scriptfullname = $MyInvocation.MyCommand.Definition
$scriptnameless = $scriptfullname -replace ".{4}$"
$ScriptDir = (Split-Path $MyInvocation.MyCommand.Path) + "\"
Start-transcript -path $scriptnameless'_logfile.txt' -append

LoadAdminModules


# #############################################################################
# end of script
Stop-transcript