# File:: vmkping.ps1
# Author:: OneCloud Quality Assurane Team <oc-infra-qa@vmware.com>
# Last Modified:: April 25th 2017
# Purpose:: Automate the OCQA testing processes. Queries one or more vCenters for VXLAN interfaces and pings one host to all others
# Version:: 1.2


# Global Variables

	$adauser = Read-Host 'What is your ADA Username? (include domain\)'
	$SecurePassword = Read-Host -Prompt "Enter ADA password" -AsSecureString
	#assuming host root username
	$esx_un = "root"
	$esx_pw = Read-Host 'What is the ESX root password?'
	#next section asks for vCenter FQDN's to test against, one after another. Just enter blank to proceed
	$vc_to_test = @()
		do {
		$AskForVCs = (Read-Host "What is the FQDN of the VC you are testing? Hit Enter on a blank line to proceed")
		if ($AskForVCs -ne '') {$vc_to_test += $AskForVCs}
			}
		until ($AskForVCs -eq '')
	# decrypt password and dump it into another variable to use
	$BSTR = `
    	[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
	# then put decrypted into a variable to use later
	$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Main program

# Logon to VC
	Write-Host "`n"
	Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Logging on to VC "
		foreach ($vc in $vc_to_test)
			{Connect-VIServer -Server $vc_to_test -WarningAction SilentlyContinue -user $adauser -Password $PlainPassword | Out-Null
		}
		$first_host = (Get-VmHost)[0].Name
		$vxlan_ips = Get-VMHostNetworkadapter | where {$_.PortgroupName -match "vxw*"} | Select IP

#this needs an actual test for connectivity
	Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Connected to $vc_to_test `n"

# Start SSH on a Host
	Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Select the first Host and start the SSH Service "
		$first_host = (Get-VmHost)[0].Name
	Write-Host -ForegroundColor white "$(Get-Date -format 'u') - The host $first_host will be used"
		$vmHostService = (Get-VMHostService $first_host | Where { $_.Key -eq "TSM-SSH"})
		if ($vmHostService[0].Running -eq $False) {
			Start-VmHostService $vmHostService[0]
			Write-Host "`n"
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - SSH Service started on $first_host `n"
		} else {
			Write-Host "`n"
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - SSH Service is already running `n"
		}
		Start-Sleep -Seconds 10

# Gather VXLan IPs
	Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Gather all IPs for the VXLan from VC and add to an array "
		$vxlan_ips = Get-VMHostNetworkadapter | where {$_.PortgroupName -match "vxw*"} | Select IP
    Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Gathered the following VXLan IPs: `n"
    Write-Host -ForegroundColor white $vxlan_ips
	Write-Host "`n"
		Start-Sleep -Seconds 10


# Run VMKping test
	Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Connecting to an SSH session to the $first_host `n"
	Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Run the VMKping test from the first host to every VXLan IP found in the VC `n"
		foreach ($ip in $vxlan_ips){
			Write-Output "yes" | PLINK.EXE -ssh $first_host -P 22 -l $esx_un -pw $esx_pw vmkping ++netstack=vxlan $($ip.ip) -I vmk4 | out-file results.txt
			#this is where i intend to output to a file
		}


# Stop SSH Service on host
    Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Stopping SSH Service on host "
        Write-Host -ForegroundColor white $vmHostService
		$vmHostService = (Get-VMHostService $first_host | Where { $_.Key -eq "TSM-SSH"})
    if ($vmHostService[0].Running -eq $True) {
        Write-Host "`n"
		Stop-VmHostService $vmHostService[0]
		Write-Host "`n"
        Write-Host -ForegroundColor white "$(Get-Date -format 'u') - SSH Service stopped on $first_host `n"
    } else {
		Write-Host "`n"
		Write-Host -ForegroundColor white "$(Get-Date -format 'u') - SSH Service is already stopped `n"
       }

# Disconnect from VC
	Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Disconnecting from the VC `n"
        Disconnect-VIServer -Server $vc_to_test -Confirm:$false

# Complete Test
	Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Test completed "