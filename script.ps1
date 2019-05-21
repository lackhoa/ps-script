# Install-WindowsFeature: AD-Domain-Services, DNS
# Import-Module: ADDSDeployment

# Networking
Get-NetAdapter
Get-NetIPAddress -AddressFamily IPv4
Disable-NetAdapter
Get-ADDomain
Get-ADUser -Filter *
## Forming a team
New-NetLbfoTeam -Name team -TeamMembers Ethernet0, Ethernet1
## Working with nic
$nic = Get-NetAdapter team
$nic | Get-NetIPAddress -AddressFamily IPv4 | Remove-NetIPAddress
$nic | New-NetIPAddress -AddressFamily IPv4 -IPAddress 192.168.163.10 -PrefixLength 24 -DefaultGateway 192.168.163.2
$nic | Set-DnsClientServerAddress -ServerAddresses localhost, 192.168.163.2
$nic | Get-NetIPAddress -AddressFamily IPv4

# AD
## Install an AD forest
$pass = (ConvertTo-SecureString -AsPlainText -Force -String 'P@ssw0rd')
Install-ADDSForest -DomainName xamklab.fi -DomainNetbiosName XAMKLAB -CreateDnsDelegation:$false -DatabasePath 'C:\Windows\NTDS' -SafeModeAdministratorPassword $pass
## Rename-Computer
Rename-Computer -NewName WinServer-DC

# File system
Remove-Item
Rename-Item
## Show file size
ls | Select-Object Name, @{Name="MBs";Expression={$_.Length / 1MB}}
## Mounting remote location
net use P: '\\mb3\Public' /Persistent:Yes

# vSphere
Connect-VIServer
## Networking
Get-VirtualSwitch
Get-VirtualPortGroup
## Creating a new datastore
$dsName = 'ds-khoa'
$ip = '192.168.163.101'
$vmHost = (Get-VMHost $ip)
Get-ScsiLun -VmHost $vmHost | Format-Table CanonicalName,CapacityGB
$scsiName = 'mpx.vmhba1:C0:T1:L0'
New-Datastore -VMHost $vmHost -Name $dsName -Path $scsiName -Vmfs -FileSystemVersion 5
## Uploading stuff
cd vmstore:
$ds = Get-Datastore $dsName
New-PSDrive -Location $ds -Name ds -PSProvider VimDatastore -Root '\'
Set-Location ds:\  # Can also be "cd vmstore:\ha-datacenter\ds-khoa"
mkdir Images
net use P: '\\mb3\Public' /Persistent:Yes
$src = 'P:\Matti\ISO\Puppy Linux tahr-6.0.5_PAE.iso'
$dst = 'ds:\Images'
Copy-DatastoreItem -Item $src -Destination $dst
$s0 = (Get-VirtualSwitch -Name 'vSwitch0')
## Creating a new VM and boot it to Puppy (Thanks to the hero at: https://serverfault.com/questions/891430/powercli-build-and-install-vm-from-iso)
$vm = New-VM -Name vm-khoa -Datastore ds-khoa -DiskGB 2 -MemoryGB 0.25 -Notes Puppy!
$CDDrive = (New-CDDrive -VM $vm -IsoPath '[ds-khoa] Images\Puppy.iso' -StartConnected)  # -StartConnected is a switch parameter, which doesn't need arguments
Sleep 5  # Force BIOS to wait, otw this wouldn't work
Start-VM -VM $vm
Set-CDDrive -connected 0 $CDDrive
## Now Puppy Linux is installed!
## VM Firewall, hold this guy accountable: http://vcloud-lab.com/entries/active-directory/vmware-powercli-time-configuration-ntp-network-time-protocol-on-multiple-esxi-server
Connect-VIServer 192.168.163.102
$vmHost2 = (Get-VMHost 192.168.163.102)
Add-VMHostNtpServer -NtpServer pool.ntp.org $vmHost2
Get-VMHostFirewallException -VMHost $vmHost2 | ? {$_.Name -eq "NTP client"}
Get-VMHostFirewallException -VMHost $vmHost2 | ? {$_.Name -eq 'NTP client'} | Set-VMHostFirewallException -Enabled:$true
Get-VmHostService $vmHost2 | ? {$_.key -eq 'ntpd'} | Start-VMHostService
Get-VmHostService $vmHost2 | ? {$_.key -eq 'ntpd'} | Set-VMHostService -policy 'on'
## Import: you can only import just the ovf file (included in the ova), because of a bug in the script
Import-vApp -Source 'S:\win98\Windows 98.ovf' -VMHost $vmHost $ds -DiskStorageFormat Thin
## Resource pool
$rp = (Get-ResourcePool -Name 'Resources')
New-ResourcePool -Name 'RP-High' -Location $rp -CpuSharesLevel High -MemSharesLevel High
New-ResourcePool -Name 'RP-Low'  -Location $rp -CpuSharesLevel Low -MemSharesLevel  Low
$rpHigh = Get-ResourcePool -name 'RP-High'
$rpLow = Get-ResourcePool -name 'RP-Low'
$vm = (Get-VM -name 'Windows 98')
Move-VM $vm -Destination $rpHigh
## Check the result: this is terrible
$vm.ResourcePool.Name
Get-VM -Location $rpHigh
$vmHost = (Get-VMHost 192.168.163.101)
Get-VMStartPolicy $vm
## When the server starts, the VM is powered on (backwards syntax). And of course you configure stop action in a cmdlet called 'Set-VMHostStartPolicy'!
$vmHost | Get-VMHostStartPolicy | Set-VMHostStartPolicy -Enabled $True -StartDelay 60 -StopAction Suspend
## (Inh.) means "inherited"; It is the default
Get-VMStartPolicy $vm | Set-VMStartPolicy -StartAction PowerOn -StartOrder 1
## Snapshot business
New-Snapshot -Name 'powernap' -VM $vm -Description 'Testing'
$snapshot = Get-Snapshot -Name 'powernap' -VM $vm
Start-VM $vm
set-vm -VM $vm -Snapshot $snapshot  # I like how reverting to a snapshot will also shutdown the VM :)
## Template exporting
Export-VApp -VM $vm -Destination C:\Users\Cisco