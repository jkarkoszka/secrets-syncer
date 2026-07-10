include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  root_config  = read_terragrunt_config(find_in_parent_folders("root.hcl"))
  secrets_file = local.root_config.locals.secrets_file

  secrets_doc = yamldecode(sops_decrypt_file(local.secrets_file))
  secrets_for_sm = [
    for secret in local.secrets_doc.secrets : secret
    if try(secret.create_secrets_manager, false)
  ]
  secrets_syncer_input = base64encode(yamlencode({
    version  = 1
    provider = "aws-secretsmanager"
    secrets = [
      for secret in local.secrets_for_sm : {
        key            = secret.key
        value          = secret.value
        description    = try(secret.description, null)
        encryption_key = try(secret.encryption_key, null)
        tags           = try(secret.tags, null)
      }
    ]
  }))
}

terraform {
  source = "../modules/baseline"
  before_hook "secrets_syncer_plan" {
    commands = ["plan"]
    execute = [
      "bash",
      "-c",
      "printf '%s' '${local.secrets_syncer_input}' | secrets-syncer plan --input - --input-base64"
    ]
  }

  before_hook "secrets_syncer_apply" {
    commands = ["apply"]
    execute = [
      "bash",
      "-c",
      "printf '%s' '${local.secrets_syncer_input}' | secrets-syncer apply --input - --input-base64 --auto-approve"
    ]
  }
}
