Add-PSSnapin VMware.VimAutomation.Core
Connect-VIServer "sjc01-1-vc1.oc.vmware.com"
foreach($vmhost in Get-VMHost){
$esxcli = Get-EsxCli -VMHost $vmhost.Name
$esxcli.system.coredump.network.set($null,"vmk0",10.119.102.1,6500)
$esxcli.system.coredump.network.set(1)
$esxcli.system.coredump.network.get()
}