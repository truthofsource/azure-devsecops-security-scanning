# Scanner-only fixture, never deployed. A limited fix does not satisfy every rule.
resource "azurerm_storage_account" "example" {
  name = "examplefixture001"
  resource_group_name = "rg-example-fixture"
  location = "eastus2"
  account_tier = "Standard"
  account_replication_type = "LRS"
  min_tls_version = "TLS1_2"
  shared_access_key_enabled = false
  allow_nested_items_to_be_public = false
  public_network_access_enabled = true
}
