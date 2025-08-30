output "subnet_ids" {
  description = "A map of subnet names to subnet IDs"
  value       = { for k, v in azurerm_subnet.mysubnets : k => v.id }
}

output "nic_ids" {
  description = "A map of nic names to nic ids"
  value       = { for k, v in azurerm_network_interface.my_nics : k => v.id }
}

output "windows_vm_ip" {
  description = "Private IP address of the Windows Server"
  value       = { for k, v in azurerm_windows_virtual_machine.my_win_vms : k => azurerm_network_interface.my_nics[lookup(var.win_vms[k], "nic_id")].private_ip_address }
}

output "linux_vm_ip" {
  description = "Private IP address of the Linux Server"
  value       = { for k, v in azurerm_linux_virtual_machine.my_linux_vms : k => azurerm_network_interface.my_nics[lookup(var.linux_vms[k], "nic_id")].private_ip_address }
}

output "windows_public_ip" {
  description = "Public IP address of the Windows Server"
  value       = azurerm_public_ip.windows_public_ip.ip_address
}

output "linux_public_ip" {
  description = "Public IP address of the Linux Server"
  value       = azurerm_public_ip.linux_public_ip.ip_address
}

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.myrg.name
}

# Additional useful outputs for SOC management
output "windows_vm_name" {
  description = "Windows VM name"
  value       = { for k, v in azurerm_windows_virtual_machine.my_win_vms : k => v.name }
}

output "linux_vm_name" {
  description = "Linux VM name"
  value       = { for k, v in azurerm_linux_virtual_machine.my_linux_vms : k => v.name }
}
