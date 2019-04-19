# #############################################################################
# COMPANY INC - SCRIPT - POWERSHELL
# NAME: script.ps1
# 
# AUTHOR:  David Annett
# DATE:  3/8/2019
# 
# COMMENT:  Deletes one or more web applications under a site, removes associated application pools and directories
#
# TO ADD
# -Add a Function to ...
# -Fix the...
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



#Begin transcript
    $scriptfullname = $MyInvocation.MyCommand.Definition
    $scriptnameless = $scriptfullname -replace ".{4}$"
    $ScriptDir = (Split-Path $MyInvocation.MyCommand.Path) + "\"
    Start-transcript -path $scriptnameless'_logfile.txt' -append

LoadAdminModules

$Site = 'Progressive Default Site'
$WebAppNames = "Css.Mapping.CSCService", "Css.Mapping.CSCServiceTestPages", "BogusData"

     
foreach($App in $WebAppNames){
        $WebApp = Get-WebApplication -Name $App
        $WebAppPath = $WebApp.PhysicalPath + "\"
        $webapppoolname = $WebApp.ApplicationPool
    If($WebApp){
        Write-Host -fore green "Performing IIS cleanup of $App on $env:COMPUTERNAME"
            if(get-webapppoolstate $app | where {$_.value -like "started"}){
                stop-WebAppPool -Name $webApp.applicationPool
                write-host -fore cyan "WebAppPool $app stopped"
            }
            Else{
                write-host -fore cyan "WebAppPool $app already stopped"
            }
        Remove-WebApplication -Site "$Site" -Name $App -Confirm:$false
            If(Get-WebApplication -Name $App){
                    write-host -fore red "WebApp $app seems to still be there"
                }
                Else{
                    write-host -fore cyan "WebApp $app deleted"
                }
        Remove-WebAppPool -Name $WebApp.ApplicationPool -Confirm:$false
            If(test-Path "IIS:\AppPools\$WebApppoolname"){
                write-host -fore red "WebAppPool $WebApppoolname seems to still be there"
                }
                Else{
                    write-host -fore cyan "WebAppPool $WebApppoolname deleted"
                }
        If(Test-Path $WebAppPath){
            Remove-Item -Path $WebAppPath -Recurse -Force -Confirm:$false
                If(Test-Path $WebAppPath){
               write-host -fore red "Directory $webapppath not deleted"
                }
                Else{
                Write-host -fore cyan "Directory $WebAppPath deleted"
                }
        }
    }
    Else{
        Write-host -fore cyan "nothing to do for $App"
        }
}

Stop-Transcript