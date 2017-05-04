#Get all virtual machines with mounted ISOs and dismount (if wanted)
#2013 By Christian Stankowic 

##################################################################

#Get array of all Clusters
$myClusters = Get-Cluster

#Create VMs array
$VMs = @()

Write-Host "Okay - I'm going to check all VMs whether there are mounted ISO files."
Write-Host "This will take some time - get yourself some coffee.. ;-)"
Write-Host ""

#Get vms of cluster
foreach ($cluster in $myClusters) {
                #Get VMs
                #$thisVMs = Get-VM
                $thisVMs = Get-Cluster $cluster | Get-VM
                $counter=0;

                #Get VM information
                foreach ($vm in $thisVMs) {
                               #Get view
                               $vmView = $vm | Get-View

                               if( (($vm | Get-CDDrive).ISOPath) -or (($vm | Get-CDDrive).RemoteDevice) -or (($vm | Get-CDDrive).HostDevice) )
                               {
                                               #Setup output
                                               $VMInfo = "" | Select "VM","Host","ISO","RemoteDevice","HostDevice"

                                               #Write-Host "VM = $vm | Host = " ($vm | Get-VMHost).name " | ISO = " ($vm | Get-CDDrive).ISOPath " / Remote-Device = " $(vm | Get-CDDrive).RemoteDevice " / HostDevice = " $(vm | Get-CDDrive).HostDevice

                                               #Defining hostname, ESX host and ISO path
                                               $VMInfo."VM" = $vm.Name
                                               $VMInfo."Host" = ($vm | Get-VMHost).Name
                                               $VMInfo."ISO" = ($vm | Get-CDDrive).ISOPath
                                               $VMInfo."RemoteDevice" = ($vm | Get-CDDrive).RemoteDevice
                                               $VMInfo."HostDevice" = ($vm | Get-CDDrive).HostDevice

                                               #Add to array
                                               $VMs += $VMInfo
                               }

                               $counter++;
                               if( $counter % 10 -eq 0 ) {
                               Write-Host "Check $counter of " $thisVMs.length " in " $cluster " so far..."
                               }
                }
}

#sort array by Cluster
$VMs | Sort Cluster

#disconnect
$answer = Read-Host "Found " $VMs.length " mappings - force disconnect now? (y/n)"
if($answer -eq "y")
{
                foreach ($vm in $VMs)
                {
                               Write-Host "Disconnect on " $vm.VM "..."
                               Get-VM $vm.VM | Get-CDDrive | Set-CDDrive -NoMedia -Confirm:$false
                }
}
else { Write-Host "Disconnect aborted by user." }