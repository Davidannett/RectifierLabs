# File:: OCQA_snapshots.ps1
# Author:: OCQA <oc-infra-qa@vmware.com>
# Last Modified:: April 28 2017
# Purpose:: Automate the USQ snapshot/revert process
# Version:: 2.0
#
# EXAMPLES:
# Create snapshot #11 for vCore2:  OCQA_snapshots.ps1 -create -core 2 -snapshot 11
# Revert environment to snapshot #11 for vCore2:  OCQA_snapshots.ps1 -revert -core 2 -snapshot 11

# GLOBAL VARIABLES
	param(
		[switch]$revert = $false,
		[switch]$create = $false,
		[switch]$check = $false,
		[Parameter(Mandatory=$true)][string]$core,
		[string]$snapshot
	)

	$shutdown_order = @("vcd103", "vcd102", "vcd101", "vcd100", "vcd3", "vcd2", "vcd1",
		"nsx1", "xfer1", "vc1", "psc1", "dhcp1")
	$startup_order = @("dhcp1", "psc1", "vc1", "xfer1", "nsx1", "vcd1",
		"vcd2", "vcd3", "vcd100", "vcd101", "vcd102", "vcd103")

	$adauser = Read-Host 'What is your ADA Username? (include domain\)'
	$SecurePassword = Read-Host -Prompt "Enter ADA password" -AsSecureString
	$esx_pw = Read-Host 'What is your ESX Hosts current Password?'
	$sapwd = Read-Host 'What is the SA password?'
	$stop_bool = $false
	$revert_bool = $false
	$start_bool = $false

	# decrypt password and dump it into another variable to use
	$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
	# then put decrypted into a variable to use later
	$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# MAIN PROGRAM

# REVERT ENVIRONMENT

	if ($revert) {
		Connect-VIServer -Server usq1-0-vc1.oc.vmware.com -WarningAction SilentlyContinue  -user $adauser -Password $PlainPassword | Out-Null
		if (-not $stop_bool) {
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Verifying VMs are powered off."
			foreach ($vm_obj in $shutdown_order) {
				$vm_name = "usq1-" + $core + "-" + $vm_obj
				$powerstate = Get-VM $vm_name | foreach {$_.PowerState}

					if ($powerstate -eq "PoweredOn") {
						Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Powering down $vm_name prior to snapshot revert."
						stop-vmguest -VM $vm_name -Confirm:$false | Out-Null
						$stop_bool = $true
					}
						if ($stop_bool) {

						}
		    }
		}

		Write-Host -ForegroundColor red "$(Get-Date -format 'u') - Sleeping 2 minutes to allow VM power down completion"
		Start-Sleep -seconds 120

		# SQL SERVER RESTORE DATABASE

			$vm_name = "usq1-" + $core + "-vcdsql1"
			$vcddbserver = "usq1-" + $core + "-vcdsql1.oc.vmware.com"
			$location = "g:\"
			$dbname = "vcore" + $core + "vcddb"
			$user = "sa"

			$timestamp=((get-date).toString("yyyy_MM_dd_hh_mm"))
			$file = $location + "usq1-" + $core + "-vcdsql1-ss" + $snapshot + ".bak"

			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Starting SQL DB Restore process"

			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Rebooting SQL Server VM to close all open connections"
			Write-Host -ForegroundColor red "$(Get-Date -format 'u') - Sleeping 90 seconds to wait for reboot to complete."
			Restart-VmGuest $vm_name -Confirm:$false | Out-Null
			Start-Sleep -seconds 90

			[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
			[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
			[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null

			$connection = New-Object "Microsoft.SqlServer.Management.Common.ServerConnection"
			$connection.ServerInstance = $vcddbserver
			$connection.LoginSecure = $false
			$connection.Login = $user
			$connection.Password = $sapwd

			$server = New-Object "Microsoft.SqlServer.Management.Smo.Server" $connection
			$restore = New-Object "Microsoft.SqlServer.Management.Smo.restore"
			$restore.Database= $dbname
			$restore.Devices.AddDevice($file, "File")
			$restore.ReplaceDatabase = $true
			$restore.Action::Database

			$restore.SqlRestore($server)

			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - SQL DB Restore complete."
			Start-Sleep -seconds 10

		# SNAPSHOT REVERT MANAGEMENT VMs

			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Beginning the snapshot restore process."

			foreach ($vm_obj in $startup_order) {
				$vm_host = "usq1-" + $core + "-" + $vm_obj
				$snap_name = $vm_host + "-ss" + $snapshot
				Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Reverting to snapshot ($snap_name) on $vm_host."
				$snap_obj = Get-Snapshot -VM $vm_host -Name $snap_name
				Set-VM -VM $vm_host -snapshot $snap_obj -Confirm:$false | Out-Null
			}

			$revert_bool = $true
			Disconnect-VIServer -Server usq1-0-vc1.oc.vmware.com -Confirm:$false
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Restore process complete."
			Start-Sleep -seconds 10

		# STARTUP PRIMARY MANAGEMENT VMs

			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Beginning the startup process."
			Connect-VIServer -Server usq1-0-vc1.oc.vmware.com -WarningAction SilentlyContinue  -user $adauser -Password $PlainPassword | Out-Null
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Preparing to power up USQ1 vCore $core environment."

			# The DHCP should be the first vm powered on in the environment
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Powering on DHCP VM."
			Write-Host -ForegroundColor red "$(Get-Date -format 'u') - Sleeping 1 minute to wait for power on to complete."
			$vm_host = "usq1-" + $core + "-dhcp1"
			start-vm -VM $vm_host -Confirm:$false | Out-Null
			Start-Sleep -seconds 60

			# The PSC should be the second vm powered on in the environment
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Powering on Platform Services Controller VM."
			Write-Host -ForegroundColor red "$(Get-Date -format 'u') - Sleeping 1 minute to wait for power on to complete."
			$vm_host = "usq1-" + $core + "-psc1"
			start-vm -VM $vm_host -Confirm:$false | Out-Null
			Start-Sleep -seconds 60

		    # Need to automate rejoin of domain and reboot (/opt/likewise/bin/domainjoin-cli join domain username)

			$nsx_obj = "usq1-" + $core + "-nsx1"
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Starting NSX Manager VM ($nsx_obj)"
			Write-Host -ForegroundColor red "$(Get-Date -format 'u') - Sleeping 1 minute to wait for power on to complete."
			start-vm -vm $nsx_obj -Confirm:$false | Out-Null
			Start-Sleep -seconds 60

			# The vCenter Server should be powered on after the PSC and VSM are online
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Powering on vCenter Server VM."
			Write-Host -ForegroundColor red "$(Get-Date -format 'u') - Sleeping 3 minutes to wait for power on to complete."
			$vm_host = "usq1-" + $core + "-vc1"
			start-vm -VM $vm_host -Confirm:$false | Out-Null
			Start-Sleep -seconds 180
			Disconnect-VIServer -Server usq1-0-vc1.oc.vmware.com -Confirm:$false
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Sucessfully powered on VC.  Disconnecting the powershell connection to VC."

		# REBOOT ESX SERVERS  (NOTE:  we need to make this query for all hosts and put in an array so that we dont hard code this info)

			$esxi = @("esx1", "esx2", "esx3", "esx4")
			foreach ($esxi_obj in $esxi) {
				$esxi_host = "usq1-" + $core + "-" + $esxi_obj + ".oc.vmware.com"
				Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Connecting to $esxi_host and rebooting the host"
				Connect-VIServer -Server $esxi_host -WarningAction SilentlyContinue -User root -Password $esx_pw | Out-Null
				Restart-VMHost -vmhost $esxi_host -Confirm:$false -Force | Out-Null
				Disconnect-VIServer -Server $esxi_host -Confirm:$false
				Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Disconnecting the powershell connection to $esxi_host"
			}

			Write-Host -ForegroundColor red "$(Get-Date -format 'u') - Sleeping 15 minutes to allow ESXi servers to reboot."
			Start-Sleep -seconds 900

		# STARTUP REMAINING MANAGEMENT VMs

			Connect-VIServer -Server usq1-0-vc1.oc.vmware.com -WarningAction SilentlyContinue  -user $adauser -Password $PlainPassword | Out-Null

			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Starting vCloud Director components"
			$xfer_obj = "usq1-" + $core + "-xfer1"
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Starting Transfer server VM ($xfer_obj)."
			start-vm -vm $xfer_obj -Confirm:$false | Out-Null
			Write-Host -ForegroundColor red "$(Get-Date -format 'u') - Sleeping 1 minute to allow $xfer_obj servers to start."

			Start-Sleep -seconds 60

			$first_cell = "usq1-" + $core + "-vcd1"
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Starting the first vCloud Director Cell ($first_cell)."
			start-vm -vm $first_cell -Confirm:$false | Out-Null
			Write-Host -ForegroundColor red "$(Get-Date -format 'u') - Sleeping 1 minute to allow $first_cell servers to start."

			Start-Sleep -seconds 60

			$last_cells = @("vcd2", "vcd3", "vcd100", "vcd101", "vcd102", "vcd103")
			foreach ($last_obj in $last_cells) {
				$vm_host = "usq1-" + $core + "-" + $last_obj
				Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Starting vCloud Director Cell ($vm_host)."
				start-vm -vm $vm_host -Confirm:$false | Out-Null
			}

	# REVERT PROCESS COMPLETED

		Disconnect-VIServer -Server usq1-0-vc1.oc.vmware.com -Confirm:$false
		Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Disconnecting the powershell connection to VC."
		Write-Host -ForegroundColor green "$(Get-Date -format 'u') - CONGRATULATIONS! Environment revert process complete."

	}
	# END REVERT ENVIRONMENT


# CREATE SNAPSHOT ENVIRONMENT

	if ($create) {
		Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Starting snapshot creation process."
		if (-Not $snapshot) {
			[string]$snap_num = $(Read-Host "Input NEW number to assign to this snapshot")
			$snapshot = $snap_num
		}

		Connect-VIServer -Server usq1-0-vc1.oc.vmware.com -WarningAction SilentlyContinue  -user $adauser -Password $PlainPassword | Out-Null

		# POWER OFF MANAGEMENT VMs

			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Verifying all VMs are powered off."
			foreach ($vm_obj in $shutdown_order) {
				$vm_name = "usq1-" + $core + "-" + $vm_obj
				$powerstate = Get-VM $vm_name | foreach {$_.PowerState}
					if ($powerstate -eq "PoweredOn") {
						Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Powering down $vm_name prior to snapshot creation."
						stop-vmguest -VM $vm_name -Confirm:$false | Out-Null
						Start-Sleep -seconds 5
						$stop_bool = $true
					}
						if ($stop_bool) {

						}
		    }

		    Write-Host -ForegroundColor red "$(Get-Date -format 'u') - Sleeping 2 minutes to allow any VMs to power down."
				Start-Sleep -seconds 120

		# CREATE SNAPSHOTS OF MANAGEMENT VMs

			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Starting creation of new snapshots."

			foreach ($vm_obj in $startup_order) {
				$vm_name = "usq1-" + $core + "-" + $vm_obj
				$snap_name = $vm_name + "-ss" + $snapshot
				Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Creating new snapshot ($snap_name) for $vm_name."
				New-Snapshot -VM $vm_name -Name $snap_name -Confirm:$false -RunAsync -WarningAction silentlyContinue | Out-Null
			}
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Snapshot creatiom process complete."

	    # CREATE SQL DATABASE BACKUP

			$vm_name = "usq1-" + $core + "-vcdsql1"
		    $bak_name =  $vm_name + "-ss" + $snapshot

			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Rebooting SQL Server VM to close all open connections"
			Write-Host -ForegroundColor red "$(Get-Date -format 'u') - Sleeping 90 seconds to wait for reboot to complete."
			Restart-VmGuest $vm_name -Confirm:$false | Out-Null
			Disconnect-VIServer -Server usq1-0-vc1.oc.vmware.com -Confirm:$false
			Start-Sleep -seconds 90

			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Creating new SQL Backup ($bak_name) on SQL server $vm_name."
		    $vcddbserver = $vm_name + ".oc.vmware.com"
		    $location = "g:\"
		    $user = "sa"

		    $timestamp=((get-date).toString("yyyy_MM_dd_hh_mm"))
		    $file = $location + $bak_name + ".bak"

		    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
		    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
		    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null

		    $connection = New-Object "Microsoft.SqlServer.Management.Common.ServerConnection"
		    $connection.ServerInstance =$vcddbserver
		    $connection.LoginSecure = $false
		    $connection.Login = $user
		    $connection.Password = $sapwd

		    $server = New-Object "Microsoft.SqlServer.Management.Smo.Server" $connection
		    $backup = New-Object "Microsoft.SqlServer.Management.Smo.backup"
		    $backup.Action::Database

		    $device = New-Object ('Microsoft.SqlServer.Management.Smo.BackupDeviceItem') ($file, 'File')
		    $device.DeviceType = 'File'
		    $device.Name = $file

		    $backup.MediaDescription = "Disk"
		    $backup.Database= "vcore" + $core + "vcddb"
		    $backup.Devices.Add($device)
		    $backup.SqlBackup($server)

		    Write-Host -ForegroundColor white "$(Get-Date -format 'u') - SQL Backup process for $vm_name is complete."
			Write-Host -ForegroundColor green "$(Get-Date -format 'u') - CONGRATULATIONS! The environment backup process is now complete!"

	}

# END CREATE SNAPSHOT ENVIRONMENT

# CHECK AVAILABLE SNAPSHOTS

	if ($check) {
		Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Checking current available snapshots."
		Connect-VIServer -Server usq1-0-vc1.oc.vmware.com -WarningAction SilentlyContinue  -user $adauser -Password $PlainPassword | Out-Null

		foreach ($vm_obj in $startup_order) {
			$vm_name = "usq1-" + $core + "-" + $vm_obj
			Write-Host -ForegroundColor white "$(Get-Date -format 'u') - $vm_name has the following snapshots:"
			Write-Host -ForegroundColor white "$(Get-Snapshot -VM $vm_name)"
		}

		Disconnect-VIServer -Server usq1-0-vc1.oc.vmware.com -Confirm:$false | Out-Null
		Write-Host -ForegroundColor white "$(Get-Date -format 'u') - Checking snapshots process complete."
	}

# END CHECK AVAILABLE SNAPSHOTS

# END MAIN PROGRAM