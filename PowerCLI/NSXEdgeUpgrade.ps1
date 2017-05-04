<#
.SYNOPSIS 
    Upgrade all HA Edges on a particular NSX Manager 
.DESCRIPTION 
    Script will upgrade all HA Edges on a particular NSX Manager to the latest version.
.PARAMETER  NSXServerName 
    FQDN of the NSX Server
.EXAMPLE 
    PS C:\>  NSXEdgeUpgrade.ps1 us01-6-vsm1.oc.vmware.com
.EXAMPLE 
    PS C:\>  NSXEdgeUpgrade.ps1 -NSXServerName us01-6-vsm1.oc.vmware.com
.NOTES
    Author: Shane van Bentum
    Date:   April 9, 2016
#>

[CmdletBinding()]
Param( 
        [Parameter(Mandatory=$true)]
        [String]$NSXServerName 
) 



##################################################
## Set variables

$NSXServer = $NSXServerName ## NSX Manager to connect to
#$NSXServer = "us01-6-vsm3.oc.vmware.com" ## Manually Specify NSX Manager to connect to for debug
$UpgradeVersion = "6.2.2" ## Set NSX Edge upgraded version
$MaxConcurrentJobs = 8 ## Set Maximum concurrent Jobs to run

##################################################

$cred = Get-Credential -Message "Enter NSX Manager Login"
$vsmUser = $cred.UserName
$vsmPass = $cred.GetNetworkCredential().password

## Connect to NSX Manager & Invoke REST API
                
## Accept Self Signed Certificate (This can not be indented for some reason...)
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    ## Create Headers
    $authbytes = [System.Text.Encoding]::ASCII.GetBytes($vsmUser + ":" + $vsmPass)
    $base64 = [System.Convert]::ToBase64String($authbytes) 
    $basicAuthValue = "Basic " + $base64
    $Headers = @{
            Authorization = $basicAuthValue
    }

    ## Connect to NSX Manager and Get Edges
    $EdgeURI = "https://$NSXServer/api/4.0/edges"
    $Response = Invoke-WebRequest -Uri $EdgeURI -Method Get -Headers $Headers
    If ($Response.StatusDescription -eq "OK") {
	    [xml]$XML = $response.Content
	    $Global:DebugXML = $XML
        Write-Host "Connected to $EdgeURI"
    } 
    Else 
    {
	    Throw "Unable to connect to $($EdgeURI)"
	    return
    }

    ## Get HA Edges from NSX (Use this one for only org edges)
    $NSXEdges = $XML.pagedEdgeList.edgePage.edgeSummary | Where-Object {$_.appliancesSummary.numberOfDeployedVms -eq 2 -and $_.appliancesSummary.vmVersion -ne $UpgradeVersion } #| select -First 1
    ## Get All Edges from NSX
    #$NSXEdges = $XML.pagedEdgeList.edgePage.edgeSummary | Where-Object {$_.appliancesSummary.vmVersion -eq "5.5.4" } #| select -First 1

    if(!$NSXEdges){
        Write-Host -Fore Yellow "No Edges Found or no Edges require upgrading to the defined version:" $UpgradeVersion
    }
    Else
    {
        Foreach($Edge in $NSXEdges){
            Write-Host "Processing $($Edge.name)"
            ## Start background Job
            $RunningJobs += 
            Start-Job {
                Write-Host " "
                Write-Host "-------------------------------------------------------"

                ## Pass Variables to Remote Job
                $EdgeId = $using:Edge.id
                $EdgeName = $using:Edge.name
                $lNSXServer = $using:NSXServer
                $lvsmUser = $using:vsmUser
                $lvsmPass = $using:vsmPass
                
                ## Accept Self Signed Certificate (This can not be indented for some reason...)
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


                ## Create Headers
                $authbytes = [System.Text.Encoding]::ASCII.GetBytes($lvsmUser + ":" + $lvsmPass)
                $base64 = [System.Convert]::ToBase64String($authbytes) 
                $basicAuthValue = "Basic " + $base64
                $Headers = @{
                        Authorization = $basicAuthValue
                }
                
                ## Build URI
                $upgradeURI =  "https://$lNSXServer/api/4.0/edges/" + $EdgeId + "?action=upgrade"
                Write-Host "Starting upgrade job for" $EdgeName
                Clear-Variable UpgradeResponse -ErrorAction Ignore
                ## Invoke Upgrade Web Request
                $UpgradeResponse = Invoke-WebRequest -Uri $upgradeURI -Method POST -Headers $Headers -TimeoutSec 600
                ## Check if Upgrade Returned a Response if not Try Redeploy
                ## Job output will display an error here
                if(!$UpgradeResponse) 
                {
                    Write-Host -Fore Yellow "Upgrade of" $EdgeName "failed due to error above! Trying to redeploy instead"
                    ## Build URI
                    $redeployURI =  "https://$lNSXServer/api/4.0/edges/" + $EdgeId + "?action=redeploy"
                    ## Invoke Redeploy Edge Request
                    $RedeployResponse = Invoke-WebRequest -Uri $redeployURI -Method POST -Headers $Headers -TimeoutSec 600
                    ## Check if Redeploy was successful, 204 Response = No Content which is expected
                    If($RedeployResponse.StatusCode -eq "204")
                    {
                        Write-Host -Fore Green "Redeploy of" $EdgeName "completed successfully"
                        Write-Host -Fore Yellow "Retrying upgrade of" $EdgeName
                        ## Invoke Upgrade Web Request
                        $UpgradeResponse = Invoke-WebRequest -Uri $upgradeURI -Method POST -Headers $Headers -TimeoutSec 600
                        ## Check if Upgrade was successful, 204 Response = No Content which is expected
                        If($UpgradeResponse.StatusCode -eq "204"){
                            Write-Host -Fore Green "Upgrade of" $EdgeName "completed successfully"
                        }
                        Else
                        {
                            Write-Host -Fore Red "Upgrade of" $EdgeName "failed"
                        }   
                    }
                    Else
                    {
                         Write-Host -Fore Green "Redeploy of" $EdgeName "failed"
                    }
                }
                Else
                {
                    If($UpgradeResponse.StatusCode -eq "204"){
                        Write-Host -Fore Green "Upgrade of" $EdgeName "completed successfully"
                    }
                    Else
                    {
                        Write-Host -Fore Red "Upgrade of" $EdgeName "failed"
                    }
                }
                Write-Host "-------------------------------------------------------"
            }
            #Wait for Job Count to drop below max concurrent
            if ($RunningJobs.Count -ge $MaxConcurrentJobs) {
                $jobstatus = $RunningJobs | Wait-Job -Any   
            }
        }
    }

#Wait for final jobs to complete before returning prompt
$jobstatus = $RunningJobs | Wait-Job

## Disblay Output from all completed Jobs
Get-Job | Receive-Job -Verbose