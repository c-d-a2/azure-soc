locals {
  subnets = {
    subnet1_nics = {
      nic1 = {
        name            = "nic1_name"
        ip_configuration = {
          name = "nic1_ipconfig_name"
          private_ip_address_allocation = "Dynamic"
        }
      }
      nic2 = {
        name            = "nic2_name"
        ip_configuration = {
          name = "nic2_ipconfig_name"
          private_ip_address_allocation = "Dynamic"
        }
      }
    }
    subnet2_nics = {
      nic1 = {
        name            = "subnet2_nic1_name"
        ip_configuration = {
          name = "subnet2_ipconfig_name"
          private_ip_address_allocation = "Dynamic"
        }
      }
    }
  }
}

#locals {
#  nics_confs = {
#    for subnet_key, subnet in locals.subnets:
#    for nic_key, nic in subnet.subnet
#  } 
#}


