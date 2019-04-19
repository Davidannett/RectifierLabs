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
        if ($(Get-Module | Where-Object { $_.Name -eq 'WebAdministration' })){
            Import-Module WebAdministration -force
        }
        Else{
            Write-host -fore red "webadministration module not installed, therefore not loaded"
        }
    } 
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

$computers = (Get-Content -Path $scriptdir'Computers.txt')

Foreach($computer in $computers){
    If (Test-Connection -ComputerName $Computer -Quiet){
        #Invoke-Command -ComputerName $Computer -FilePath $scriptdir'myScript.ps1'
        write-host -Fore cyan "$computer tested OK"
    }
    Else{
        Write-host -fore red "Error pinging server $computer"
        Add-Content -path $ScriptDir'\Unavailable-Computers.txt' $Computer
    }
}

# #############################################################################
# end of script
Stop-transcript