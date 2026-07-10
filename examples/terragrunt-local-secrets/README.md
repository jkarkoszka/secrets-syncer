# Terragrunt local example

This example shows how to use `secrets-syncer` from Terragrunt with local state
and SOPS encryption using `age`.

## Configuration

The `root.hcl` file defines `secrets_file`, pointing to the encrypted YAML
(`global-secrets.enc.yaml`).

`secrets-syncer` hooks use your default AWS credential chain (profile, env, or
instance role). Region comes from `AWS_REGION`, `AWS_DEFAULT_REGION`, or the
active profile; account is resolved from STS.

## Prerequisites

- `terragrunt`, `tofu` or `terraform`
- `secrets-syncer` on PATH
- `sops` and `age` (`age-keygen`)
- AWS credentials with a configured region (default profile or env)

## Setup

1. Set up local secrets (age keypair, `.sops.yaml`, sample secrets, encrypted file):

```bash
./scripts/setup-local-secrets.sh
```

2. For later edits, export the age key and re-encrypt:

```bash
export SOPS_AGE_KEY_FILE=".secrets/age.key"
sops -e global-secrets.yaml > global-secrets.enc.yaml
```

## Run

```bash
cd baseline
terragrunt plan
terragrunt apply
```

## Notes

- The private key in `.secrets/age.key` should not be committed.
- `global-secrets.yaml` and `global-secrets.enc.yaml` are gitignored; regenerate or re-encrypt locally.
- Update secrets in `global-secrets.yaml`, re-encrypt, and re-run Terragrunt.
