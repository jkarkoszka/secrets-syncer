terraform {
  required_version = ">= 1.5.0"
}

resource "random_pet" "example" {
  length = 2
}
