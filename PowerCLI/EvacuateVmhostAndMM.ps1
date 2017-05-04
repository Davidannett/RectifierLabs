## --------------------------------------------------- ##
# Master 	PowerShell Reporting - SI Team OneCloud		#
# Author: 	Tom Ralph									#
# Revision: 0.1											#
# Date: 	01/10/2015									#
## --------------------------------------------------- ##

## Define Inputs
Param (
	[Parameter(Mandatory=$true)]
	[String] $VCUsername ,
	[String] $Password ,
	[String] $HostToMM ,
	[String] $TargetHost
	)
	
## Load Plugin
Add-PSSnapin *.Core
	
## Do some work

# Connect to vCenter
Write-Host "Connecting to "$VC
$Connected = Connect-VIServer -Username $VCUsername -password $Password -Server $VC -ErrorVariable $Errors

# Get the host to enter MM
$VMHost = Get-VMHost $HostToMM 

# Validate the host actually exists
If ( !$VMHost ) {
	Write-Host "Unable to find host:" $HostToMM
	Exit
}

# Get all not-Powered on VMs
$VMs = Get-VM | Where-Object { $_.PowerState -ne "PoweredOn" }

# Select target hosts
$TargetVMHost = Get-VMHost $TargetHost | Where-Object { $_.ParentId -eq $VMHost.ParentId -and $_.Name -ne $VMhost.Name }

# Validate the target actually exists
If ( !$TargetVMHost ) {
	Write-Host "Unable to find host:" $TargetHost
	Exit
}

# Start some Relocations
ForEach ( $VM in $VMs ) {
	Write-Host "Moving" $VM.Name
	$VM | Move-VM -Destination $TargetVMHost -RunAsync
}

# Eject CD's From remaining VMs on Host
ForEach ( $CDVM in ( Get-VM -Location $VMHost ) ) {
	If ( $VM.CDDrives.IsoPath -like "*/usr/lib*" ) {
		Write-Host $VM.Name "has VMWare Tools mounted"
		Dismount-Tools $VM
		Get-CDDrive $VM | Set-CDDrive -NoMedia -Confirm:$false
		Write-Host "Unmounting..."
	}
}

# Enter MM
Write-Host "Entering MM"
$Task = Set-VMHost -State Maintenance -VMHost $VMHost -Confirm:$False -Evacuate:$True -RunAsync
Get-DrsRecommendation -Cluster ( Get-Cluster -Id $VMHost.ParentId ) | Where {$_.Reason -eq "Host is entering maintenance mode"} | Apply-DrsRecommendation -RunAsync
$VMHost = Wait-Task $Task

#Done ?
Write-Host "Done"
Disconnect-VIServer * -Confirm:$False




