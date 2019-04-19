# #############################################################################
# POWERSHELL
# NAME: remote_execution_work.ps1
# 
# AUTHOR:  David Annett
# DATE:  3/12/2019
# 
# COMMENT:  this si a basic script to ping a list of servers provided in a text file. Unpingable servers are written to another file.
#
# TO ADD
# -Add a Function to ...
# -Fix the...
# #############################################################################

# #############################################################################
#functions
function LoadAdminModules
{
    if ([System.Version] (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion -ge [System.Version] "6.1"){
        if (Get-Module -ListAvailable -Name WebAdministration){
            Import-Module WebAdministration -force
            write-host "load1"
        }
    } 
        else {
            Add-PSSnapin WebAdministration
            write-host "load2"
        }
}
# #############################################################################

LoadAdminModules