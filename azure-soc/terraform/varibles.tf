variable "subnet_list" {
  description = "List of subnets to create"
  type = map(object({
    name     = string
    net_cidr = string
  }))
  default = {
    sn  = { name = "srv_net",    net_cidr = "172.16.1.0/28" }
    sn2 = { name = "client_net", net_cidr = "172.16.2.0/24" }

  }
}

variable "sn" {
  description = "Subnet definitions"
  type = map(object({
    name                 = string
    resource_group_name  = string
    virtual_network_name = string
    address_prefixes     = list(string)
  }))
  default = {
    sn1 = {
      name                 = "subnet1"
      resource_group_name  = "socrg"            
      virtual_network_name = "socvn"
      address_prefixes     = ["172.16.1.0/24"]
    }
    sn2 = {
      name                 = "subnet2"
      resource_group_name  = "socrg"
      virtual_network_name = "socvn"
      address_prefixes     = ["172.16.2.0/24"]
    }
  }
}

variable "nic_confs" {
  description = "NIC configurations for each machine"
  type = map(object({
    name                          = string
    ip_config_name                = string
    subnet_key                    = string
    private_ip_address_allocation = string
    private_ip_address            = string
    nic_type                      = string
  }))
  default = {
    ubuntu_server = {
      name                          = "ubuntu-server-nic"
      ip_config_name                = "ubuntu-server-ipconfig"
      subnet_key                    = "sn1"
      private_ip_address_allocation = "Static"
      private_ip_address            = "172.16.1.10"
      nic_type                      = "linux"
    }
    windows_server = {
      name                          = "windows-server-nic"
      ip_config_name                = "windows-server-ipconfig"
      subnet_key                    = "sn2"
      private_ip_address_allocation = "Static"
      private_ip_address            = "172.16.2.10"
      nic_type                      = "windows"
    }
  }
}

variable "linux_vms" {
  description = "Linux VM configuration"
  type = map(object({
    name = string
    nic_id = string 
  }))
  default = {
    linux1 = {
      name = "ubuntu-server"
      nic_id = "ubuntu_server"
    }
  }
}

variable "win_vms" {
  description = "Windows VM configuration"
  type = map(object({
    name   = string
    nic_id = string
  }))
  default = {
    win1 = {
      name   = "windows-server"
      nic_id = "windows_server"
    }
  }
}

variable "username" {
  description = "Username for both Windows and Linux machines"
  type        = string
  default     = "azureuser"
}

variable "password" {
  description = "Password for both Windows and Linux machines"
  type        = string
  sensitive   = true
}
