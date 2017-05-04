Function Provision-ShadowCopy {

<#
.SYNOPSIS
	Provisions shadowcopy of vapp template to x datastores of a storage profile
.DESCRIPTION
	Provisions shadowcopy of vapp template to x datastores of a storage profile
.PARAMETER ciServer
	Cloud server where vapp template resides
.PARAMETER Org
	Cloud server where vapp template resides
.PARAMETER catalog
    Catalog name where vapp template resides
.PARAMETER template
    name of the vapp template
.PARAMETER storagevm
    name of the vm that is the storage appliance for the vapp
.PARAMETER shadows
    number of shadows to deploy
.PARAMETER consolidate
    Will consolidate vm's before shadow copy if set to $true
.EXAMPLE
	Provision-ShadowCopy -ciServer vcloud.vcddev.local -org org1 -catalog catalogNFSSP2 -template "psv v1.1-6" -shadows 2 -storagevm "slitaz01-3" -consolidate $true
	provision-shadowcopy -ciServer vcore3-nl01.oc.vmware.com -org nl03-3-ocqa-testing-u -catalog OCQA-CERT-CATALOG-GOOD -template "HOL-SDC-1601-v1.2" -shadows 10 -storagevm "stgb-01a" -consolidate $true
.NOTES
    version 3.2.1 Grant Voss gvoss@vmware.com
	
#>

	[CmdletBinding()]
		Param (
            [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$false)]
            [ValidateScript({($_.GetType()).Name -eq "string"})]
			$ciServer,
            [Parameter(Position=1,Mandatory=$true,ValueFromPipeline=$false)]
            [ValidateScript({($_.GetType()).Name -eq "string"})]
			$org,
            [Parameter(Position=2,Mandatory=$true,ValueFromPipeline=$false)]
            [ValidateScript({($_.GetType()).Name -eq "string"})]
			$catalog,
            [Parameter(Position=3,Mandatory=$true,ValueFromPipeline=$false)]
            [ValidateScript({($_.GetType()).Name -eq "string"})]
			$template,
            [Parameter(Position=4,Mandatory=$true,ValueFromPipeline=$false)]
            [ValidateScript({($_.GetType()).Name -eq "int32"})]
			$shadows,
            [Parameter(Position=5,Mandatory=$true,ValueFromPipeline=$false)]
            [ValidateScript({($_.GetType()).Name -eq "string"})]
			$storagevm,
            [Parameter(Position=6,Mandatory=$false,ValueFromPipeline=$false)]
            [ValidateScript({($_.GetType()).Name -eq "boolean"})]
			$consolidate
		    )

    $cicredentials = Get-Credential -Message "Please enter credentials for $ciserver"
    Connect-CIServer $ciserver -Credential $Cicredentials
    
    #Get Org and Catalog ids
    Write-host "Connecting to Org:$org"
    $orgId = (Search-Cloud -QueryType Organization | Where-Object { $_.name -eq "$org" }).id 
    if (!$orgId) {
        Write-Host -ForegroundColor Red "We had problems finding Org:`"$org`". Please check the name and try again."
        Return
    }
    Write-host -ForegroundColor Green "Connected!"
    write-host "Searching for Catalog:$catalog"
    $catalogId = (Search-Cloud -QueryType AdminCatalog -Filter "Org==$orgId" | Where-Object { $_.name -eq $catalog }).id
    if (!$catalogId) {
        Write-Host -ForegroundColor Red "We had problems finding catalog:`"$catalog`". Please check the name and try again."
        Return
    }
    Write-Host -ForegroundColor Green "Catalog found!"

    #Gathering vdc info to be used during vapp deploy
    Write-Host "Searching for template:$template"
    $vtvdcId = (Search-Cloud -QueryType AdminVAppTemplate -filter "Org==$orgId;Catalog==$catalogId" | Where-Object { $_.name -eq $template }).vdc
    if (!$vtvdcId) {
        Write-Host -ForegroundColor Red "We had problems finding template:`"$template`". Please check the name and try again."
        Return
    }
    Write-Host -ForegroundColor Green "Template found!"

    Write-host "Connecting to ovdc..."
    $vtvdc = Search-Cloud -QueryType AdminOrgVdc -Filter "Id==$vtvdcId" | Get-CIView
    Write-Host -ForegroundColor Green "Connected!"
   
    #Get VM's in the template
    $vtvms = (Search-Cloud -QueryType AdminVAppTemplate -filter "Org==$orgId;Catalog==$catalogId" | Where-Object { $_.name -eq $template } | get-ciview).Children.vm

    #Start Consolidation if selected
    if ( $consolidate -eq $true ) {
        Write-Host "Consolidating VMs..."
		Try {
			#Consolidate VMs one by one
			foreach ( $vtvm in $vtvms ){
				$VMName = $vtvm.Name
				$vtvm.Consolidate()
				Write-Host "VM $VMName has been consolidated." -ForegroundColor Green
            }
            Write-Host "vApp Template $template has been consolidated." -ForegroundColor Green
		} 
		Catch {
            #Variables for logging, $ErrorType not currently in use
            $ErrorType = $_.Exception.GetType().FullName
            $ErrorDetails = $_.Exception
			Write-Host "--" -ForegroundColor red
			Write-Host "VM $VMName could not be consolidated." -ForegroundColor Red
			Write-Host "vApp Template $template not consolidated successfully." -ForegroundColor Red
			Write-Host "--" -ForegroundColor red
            Write-Host $ErrorDetails -ForegroundColor Yellow
		}
    }

    #Checking if all vm's in the template are on the same datastore;If not relocate to the same datastore as the reference vm
    Write-host "Checking that all vms are on the same datastore..."
    foreach ( $vtvm in $vtvms ) {
        if ( $vtvm.name -eq $storagevm){
        $refvmdatastore = $vtvm.vcloudextension.any.DatastoreVimObjectRef.moref
        }
    }
    foreach ( $vtvm in $vtvms ){
        $vmdatastore = $vtvm.vcloudextension.any.DatastoreVimObjectRef.moref
        if ( $refvmdatastore -ne $vmdatastore ) {
            Write-Host "Migrating vm:$($vtvm.name) to $refvmdatastore"
            $datastore = (Search-Cloud -QueryType Datastore -Filter "Moref==$refvmdatastore" | get-ciview).href
            $vtvm.Relocate($datastore)   
            Write-Host -ForegroundColor Green "Migration of vm:$($vtvm.name) complete!"
        }
    }  
    Write-host -ForegroundColor Green "All vm's are on the same datastore. Ready to shadow copy!"
    
    #Find template and get storage profile name and vc id; Need these to search for datastores    
    $spname = (Search-Cloud -QueryType AdminVAppTemplate -filter "Org==$orgId;Catalog==$catalogId" | Where-Object { $_.name -eq $template }).StorageProfileName
    $vcId = (Search-Cloud -QueryType ProviderVdcStorageProfile -Name $spname).vc

    #get ovdc and find backing vc href
    Write-Host "Querying Datastores for space..."
    $vtdsref = ((Search-Cloud VirtualCenter -Filter "Id==$vcId" | Get-ciView).GetStorageProfiles().VMWStorageProfile | Where-Object { $_.Name -eq $spname }).DataStoreRefs.VimObjectRef
    $vtdsmoref = $vtdsref.moref
    

    #check for disabled datastores in storage profile and make list of enabled datastores
    [System.Collections.ArrayList]$vtdsmorefenabled = $vtdsmoref
    $vtdsmoref | % {
        $dsmoref = $_
        $dsstatus = (Search-Cloud -QueryType Datastore -Filter "Moref==$dsmoref").IsEnabled
        if ( $dsstatus -eq $false ) { 
        $vtdsmorefenabled.Remove("$dsmoref")
        }
    }
  
    #Check space on datastores and find least used.
    $dsspacecheck = $vtdsmorefenabled | %{
        $dsmoref = $_
        if ( $dsmoref -ne $refvmdatastore ) {
        Search-Cloud -QueryType Datastore -Filter "Moref==$dsmoref" | Select Name, Moref, @{N="FreeSpaceMB";E={@(($_.StorageMB – $_.StorageUsedMB))}} 
        }
   }
   
   if ($shadows -gt $vtdsmorefenabled.Count) {
        Write-Host "Too many datastores requested. Not enough enabled datastores to deploy -datastores value"
        Return
   }

   #Take number of datastores and make array friendly
   $datastorearray = @()
   $i = 0
   While ($i -lt $shadows){
   $datastorearray += $i
   $i++
   }

   #Pick the datastores
   $dsdeploy = ($dsspacecheck | sort -Descending FreeSpaceGB)[$datastorearray]
   Write-Host -ForegroundColor Green "Datastore query complete!"
   Write-Host "`r`nThe shadow copies will be deployed to these datastores..."

   Foreach ( $ds in $dsdeploy ) {
        write-host "--"
        write-host "Name: $($ds.name)"
        write-host "Moref: $($ds.moref)"
        write-host "FreeSpace in MB: $($ds.FreeSpaceMB)"
        write-host "--"
    }

   $deploy = read-host "Continue (y/n)?"
   
   if ($deploy -eq "y") {

       #Start deploy to selected datastores
       Write-Host "`r`nBeginning vapp deployment to create shadow copies..."
       $deployedvapps = @()
       [System.Collections.ArrayList]$deployedvapps = $deployedvapps
       $dsdeploy | %{
            $deploydsmoref = $_.moref
            $vtdsmorefenabled | % {
                $dsmoref = $_
                if ($dsmoref -ne $deploydsmoref) {
                    $datastore = Search-Cloud -QueryType Datastore -Filter "Moref==$dsmoref" | get-ciview
                    $datastore.Disable() > $null
                    $datastorename = $datastore.Name
                    Write-Host -ForegroundColor Red "Disabling $datastorename"
                }
            }
            
            #Loop to deploy and sleep 60 seconds
            $datastorename = (Search-Cloud -QueryType Datastore -Filter "Moref==$deploydsmoref").name
            $vappname = "$template-$datastorename"
            write-host "Deploying vapp $vappname"
            $paramsVAppT = New-Object VMware.VimAutomation.Cloud.Views.InstantiateVAppTemplateParams
            $paramsVAppT.AllEULAsAccepted = $true
            $paramsVAppT.LinkedClone = $template
            $paramsVAppT.Source = (Search-Cloud AdminVAppTemplate -filter "Org==$orgId;Catalog==$catalogId" | Where-Object { $_.name -eq $template } | Get-CIView).href
            $paramsVAppT.Name = $vappname
            $vapp = $vtvdc.InstantiateVAppTemplate($paramsVAppT)
            $deployedvapps.Add($vapp.id) > $null
            Start-Sleep -s 60
            
            #Reenable all datastores
            $vtdsmorefenabled | %{
                $dsmoref = $_
                $datastore = Search-Cloud -QueryType Datastore -Filter "Moref==$dsmoref" | get-ciview
                $datastore.Enable() > $null
                $datastorename = $datastore.Name
                write-host -ForegroundColor Green "Enabling $datastorename"
            }
        
        }
    }

    Else {
        Write-Host -ForegroundColor Red "Terminating deploy"
        Return
    }

    #Loop to check if deployed vapps have completed and remove if powered off
    $valuesToDelete = @()
    [System.Collections.ArrayList]$valuesToDelete = $valuesToDelete
    do {
        $deployedvapps | % {
            
            #Format vapp url from deploy results to powershell id friendly and get status
            $deployedvapp = $_
            $vappquery = (Search-Cloud -QueryType AdminVApp -Filter "Org==$orgid;Id==$deployedvapp") 
            $deployedstatus = $vappquery.status

            #If powered off vapp has finished deploy and can be removed
            if ( $deployedstatus -eq "POWERED_OFF" ) {
                $vapp = $vappquery | Get-CIView
                $vappname = $vapp.name
                Write-Host -ForegroundColor Red "Removing vapp $vappname"
                $vapp.Delete()
                $valuesToDelete.add($deployedvapp) > $null
            }
           
        }
        
        #remove any deleted vapps from the deployedvapps array
        $valuesToDelete | % {
            $deployedvapps.Remove($_)
        }
        
        #Clear valuetoDelete array and sleep 60 seconds to check status again
        $valuesToDelete.Clear()
        if (!$deployedvapps.count -eq 0 ){
        Start-Sleep -s 60
        }
        
    }
    while ( $deployedvapps.count -gt 0 )

    #Post deploy shadow copy verification
    Write-Host "`r`nChecking Post deployment shadow count ..."
    $vtvms = (Search-Cloud -QueryType AdminVAppTemplate -filter "Org==$orgId;Catalog==$catalogId" | Where-Object { $_.name -eq $template } | get-ciview).Children.vm
    foreach ( $vtvm in $vtvms ) {
        $vtvmId = $vtvm.Id
        $vtvmshadows = (Search-Cloud -QueryType AdminShadowVM -Filter "PrimaryVM==$vtvmId") 
            $i = 0
            foreach ( $vtvmshadow in $vtvmshadows ) {
                $i++
            }  
        write-host "$($vtvm.Name) has $i shadow vm's"
    }

    Write-Host -ForegroundColor Green "Shadowcopy deployment complete!"
   
}
