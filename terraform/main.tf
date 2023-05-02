resource "azurerm_linux_virtual_machine" "linux_virtual_machine_2_c_c_2_c" {
  tags           = merge(var.tags, {})
  location       = "East US"
  admin_username = "admin"
}

resource "azurerm_linux_virtual_machine" "linux_virtual_machine_2_c_c_1_c" {
  tags           = merge(var.tags, {})
  location       = "East US"
  admin_username = "admin"
}

resource "azurerm_linux_virtual_machine" "linux_virtual_machine_2" {
  tags           = merge(var.tags, {})
  location       = "East US"
  admin_username = "admin"
}

resource "azurerm_linux_virtual_machine" "linux_virtual_machine_2_c_c_3_c" {
  tags           = merge(var.tags, {})
  location       = "East US"
  admin_username = "admin"
}

resource "azurerm_linux_virtual_machine" "linux_virtual_machine_2_c_c" {
  tags           = merge(var.tags, {})
  location       = "East US"
  admin_username = "admin"
}

resource "azurerm_virtual_machine" "virtual_machine_3_c_c" {
  tags     = merge(var.tags, {})
  location = "East US"
}

resource "azurerm_virtual_machine" "virtual_machine_3_c_c_1_c" {
  tags     = merge(var.tags, {})
  location = "East US"
}

resource "azurerm_virtual_machine" "virtual_machine_3" {
  tags     = merge(var.tags, {})
  location = "East US"
}

