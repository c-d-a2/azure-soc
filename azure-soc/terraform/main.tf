data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "myrg" {
    name     = "socrg"
    location = "East US"
  }

resource "azurerm_virtual_network" "myvn" {
   name = "socvn"
   location = azurerm_resource_group.myrg.location
   resource_group_name = azurerm_resource_group.myrg.name
   address_space = ["172.16.0.0/16"]
   depends_on = [azurerm_resource_group.myrg]
}

resource "azurerm_subnet" "mysubnets" {
   for_each = var.sn
   name = each.value.name
   resource_group_name = azurerm_resource_group.myrg.name
   virtual_network_name = azurerm_virtual_network.myvn.name
   address_prefixes = each.value.address_prefixes
   depends_on = [azurerm_virtual_network.myvn]
}

# Public IP for Windows Server
resource "azurerm_public_ip" "windows_public_ip" {
  name                = "windows-server-public-ip"
  location            = azurerm_resource_group.myrg.location
  resource_group_name = azurerm_resource_group.myrg.name
  allocation_method   = "Static"
  sku                 = "Standard"

  depends_on = [azurerm_resource_group.myrg]
}

# Public IP for Linux Server
resource "azurerm_public_ip" "linux_public_ip" {
  name                = "linux-server-public-ip"
  location            = azurerm_resource_group.myrg.location
  resource_group_name = azurerm_resource_group.myrg.name
  allocation_method   = "Static"
  sku                 = "Standard"

  depends_on = [azurerm_resource_group.myrg]
}

resource "azurerm_network_interface" "my_nics" {
  for_each            = var.nic_confs
  name                = each.value.name
  location            = azurerm_resource_group.myrg.location
  resource_group_name = azurerm_resource_group.myrg.name

  ip_configuration {
    name                          = each.value.ip_config_name
    subnet_id                     = azurerm_subnet.mysubnets[each.value.subnet_key].id
    private_ip_address_allocation = each.value.private_ip_address_allocation
    private_ip_address            = each.value.private_ip_address
    public_ip_address_id          = each.value.nic_type == "windows" ? azurerm_public_ip.windows_public_ip.id : azurerm_public_ip.linux_public_ip.id
  }

  depends_on = [azurerm_subnet.mysubnets, azurerm_public_ip.windows_public_ip, azurerm_public_ip.linux_public_ip]
}

resource "azurerm_storage_account" "my_storage_account" {
  name                     = "socnet1"
  resource_group_name      = azurerm_resource_group.myrg.name
  location                 = azurerm_resource_group.myrg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    environment = "staging"
  }
  depends_on = [azurerm_resource_group.myrg]
}
resource "azurerm_linux_virtual_machine" "my_linux_vms" {
  for_each              = var.linux_vms
  name                  = each.value.name
  location              = azurerm_resource_group.myrg.location
  resource_group_name   = azurerm_resource_group.myrg.name
  network_interface_ids = [azurerm_network_interface.my_nics[each.value.nic_id].id]
  size                  = "Standard_B1s"

  os_disk {
    name                 = "${each.value.name}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  computer_name  = each.value.name
  admin_username = var.username
  admin_password = var.password
  disable_password_authentication = false

  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.my_storage_account.primary_blob_endpoint
  }
  depends_on = [
    azurerm_network_interface.my_nics,
    azurerm_storage_account.my_storage_account,
    azurerm_network_interface_security_group_association.linux_nsg_assoc
  ]
}


resource "azurerm_windows_virtual_machine" "my_win_vms" {
  for_each              = var.win_vms
  name                  = each.value.name
  admin_username        = var.username
  admin_password        = var.password
  location              = azurerm_resource_group.myrg.location
  resource_group_name   = azurerm_resource_group.myrg.name
  network_interface_ids = [azurerm_network_interface.my_nics[each.value.nic_id].id]
  size                  = "Standard_B1ms"

  os_disk {
    name                 = "${each.value.name}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }


  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.my_storage_account.primary_blob_endpoint
  }
  depends_on = [
    azurerm_network_interface.my_nics,
    azurerm_storage_account.my_storage_account,
    azurerm_network_interface_security_group_association.windows_nsg_assoc
  ]
}






resource "azurerm_log_analytics_workspace" "my_log_analytics_workspace" {
  name                = "soc-wp"
  location            = azurerm_resource_group.myrg.location
  resource_group_name = azurerm_resource_group.myrg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  depends_on = [azurerm_resource_group.myrg]
}
# Add NSGs after the subnet resource
resource "azurerm_network_security_group" "windows_nsg" {
  name                = "windows-server-nsg"
  location            = azurerm_resource_group.myrg.location
  resource_group_name = azurerm_resource_group.myrg.name

  security_rule {
    name                       = "RDP"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range         = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  depends_on = [azurerm_resource_group.myrg]
}

resource "azurerm_network_security_group" "linux_nsg" {
  name                = "linux-server-nsg"
  location            = azurerm_resource_group.myrg.location
  resource_group_name = azurerm_resource_group.myrg.name

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range         = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  depends_on = [azurerm_resource_group.myrg]
}

# Add NSG associations after the network_interface resource
resource "azurerm_network_interface_security_group_association" "windows_nsg_assoc" {
  network_interface_id      = azurerm_network_interface.my_nics["windows_server"].id
  network_security_group_id = azurerm_network_security_group.windows_nsg.id
  depends_on = [
    azurerm_network_interface.my_nics,
    azurerm_network_security_group.windows_nsg
  ]
}

resource "azurerm_network_interface_security_group_association" "linux_nsg_assoc" {
  network_interface_id      = azurerm_network_interface.my_nics["ubuntu_server"].id
  network_security_group_id = azurerm_network_security_group.linux_nsg.id
  depends_on = [
    azurerm_network_interface.my_nics,
    azurerm_network_security_group.linux_nsg
  ]
}
resource "azurerm_monitor_data_collection_rule" "winevents_law" {
  name                = "winevents-law"
  resource_group_name = azurerm_resource_group.myrg.name
  location            = azurerm_resource_group.myrg.location
  kind                = "Windows"

  data_sources {
    windows_event_log {
      name            = "eventLogsDataSource"
      streams         = ["Microsoft-Event"]
      x_path_queries  = [
        "Application!*[System[(Level=1 or Level=2)]]",
        "System!*[System[(Level=1 or Level=2)]]",
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall!*",
        "Microsoft-Windows-Sysmon/Operational!*",
        "Microsoft-Windows-PowerShell/Operational!*"
      ]
    }
  }

  destinations {
    log_analytics {
      name                  = "destination-log"
      workspace_resource_id = azurerm_log_analytics_workspace.my_log_analytics_workspace.id
    }
  }

  data_flow {
    streams      = ["Microsoft-Event"]
    destinations = ["destination-log"]
  }

  depends_on = [azurerm_log_analytics_workspace.my_log_analytics_workspace]
}

# Data Collection Rule for Linux Syslog
resource "azurerm_monitor_data_collection_rule" "linuxsyslog_law" {
  name                = "linuxsyslog-law"
  resource_group_name = azurerm_resource_group.myrg.name
  location            = azurerm_resource_group.myrg.location
  kind                = "Linux"

  data_sources {
    syslog {
      facility_names = ["alert", "audit", "auth", "authpriv", "clock", "cron", "daemon", "ftp", "kern", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7", "lpr", "mail", "news", "nopri", "ntp", "syslog", "user", "uucp"]
      log_levels     = ["Debug", "Info", "Notice", "Warning", "Error", "Critical", "Alert", "Emergency"]
      name           = "sysLogsDataSource"
      streams        = ["Microsoft-Syslog"]
    }
  }

  destinations {
    log_analytics {
      name                  = "destination-log"
      workspace_resource_id = azurerm_log_analytics_workspace.my_log_analytics_workspace.id
    }
  }

  data_flow {
    streams      = ["Microsoft-Syslog"]
    destinations = ["destination-log"]
  }

  depends_on = [azurerm_log_analytics_workspace.my_log_analytics_workspace]
}

# Associate Windows VMs with System/Application Events DCR
resource "azurerm_monitor_data_collection_rule_association" "windows_events_dcr_association" {
  for_each                = var.win_vms
  name                    = "windows-events-dcr-association-${each.key}"
  target_resource_id      = azurerm_windows_virtual_machine.my_win_vms[each.key].id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.winevents_law.id

  depends_on = [
    azurerm_windows_virtual_machine.my_win_vms,
    azurerm_monitor_data_collection_rule.winevents_law,
    azurerm_virtual_machine_extension.windows_azure_monitor_agent
  ]
}

# Associate Linux VMs with Syslog DCR
resource "azurerm_monitor_data_collection_rule_association" "linux_syslog_dcr_association" {
  for_each                = var.linux_vms
  name                    = "linux-syslog-dcr-association-${each.key}"
  target_resource_id      = azurerm_linux_virtual_machine.my_linux_vms[each.key].id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.linuxsyslog_law.id

  depends_on = [
    azurerm_linux_virtual_machine.my_linux_vms,
    azurerm_monitor_data_collection_rule.linuxsyslog_law,
    azurerm_virtual_machine_extension.linux_azure_monitor_agent
  ]
}

# Azure Monitor Agent for Windows
resource "azurerm_virtual_machine_extension" "windows_azure_monitor_agent" {
  for_each                   = var.win_vms
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.my_win_vms[each.key].id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true

  settings = jsonencode({
    enableAMA = true
  })

  depends_on = [
    azurerm_windows_virtual_machine.my_win_vms,
    azurerm_log_analytics_workspace.my_log_analytics_workspace
  ]
}

# Azure Monitor Agent for Linux
resource "azurerm_virtual_machine_extension" "linux_azure_monitor_agent" {
  for_each                   = var.linux_vms
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.my_linux_vms[each.key].id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  
  settings = jsonencode({
    enableAMA = true
  })


  depends_on = [
    azurerm_linux_virtual_machine.my_linux_vms,
    azurerm_log_analytics_workspace.my_log_analytics_workspace
  ]
}


resource "azurerm_virtual_machine_extension" "log_config_script" {
  for_each             = var.win_vms
  name                 = "CustomScriptExtension"
  virtual_machine_id   = azurerm_windows_virtual_machine.my_win_vms[each.key].id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.10"

  settings = <<SETTINGS
    {

      "fileUris": ["https://raw.githubusercontent.com/c-d-a2/azure-soc-net/refs/heads/main/scripts/config.ps1"],
      "commandToExecute": "powershell -ExecutionPolicy Unrestricted -File config.ps1"
    }
  SETTINGS
  depends_on = [
    azurerm_windows_virtual_machine.my_win_vms,
    azurerm_log_analytics_workspace.my_log_analytics_workspace
  ]


}
