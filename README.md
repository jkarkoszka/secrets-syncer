# secrets-syncer

[![CI](https://github.com/jkarkoszka/secrets-syncer/actions/workflows/ci.yml/badge.svg)](https://github.com/jkarkoszka/secrets-syncer/actions/workflows/ci.yml)

GitOps-style CLI for managing secret **values** in AWS Secrets Manager without storing them in Terraform/OpenTofu state.

`secrets-syncer` compares desired secret values from Git (YAML/JSON, optionally SOPS-encrypted) with AWS Secrets Manager, shows a Terraform-like plan, and applies changes when approved.

## Highlights

- Terraform-like plan/apply for secret value changes
- YAML or JSON input, optionally SOPS-encrypted
- Safe-by-default tagging to avoid touching unmanaged secrets
- Works with AWS profiles, environment credentials, and role assumption
- No secret values in logs or plan output

## Install

### Go install (recommended)

```bash
go install github.com/jkarkoszka/secrets-syncer@latest
```

### GitHub Releases

```bash
curl -sSL https://github.com/jkarkoszka/secrets-syncer/releases/latest/download/secrets-syncer_${OS}_${ARCH}.tar.gz \
  | tar -xz secrets-syncer
sudo mv secrets-syncer /usr/local/bin/
```

Examples:

```bash
# Linux x86_64
curl -sSL https://github.com/jkarkoszka/secrets-syncer/releases/latest/download/secrets-syncer_linux_amd64.tar.gz \
  | tar -xz secrets-syncer
sudo mv secrets-syncer /usr/local/bin/

# macOS arm64
curl -sSL https://github.com/jkarkoszka/secrets-syncer/releases/latest/download/secrets-syncer_darwin_arm64.tar.gz \
  | tar -xz secrets-syncer
sudo mv secrets-syncer /usr/local/bin/
```

### From source

```bash
git clone https://github.com/jkarkoszka/secrets-syncer.git
cd secrets-syncer
task build
```

The binary is written to `./bin/secrets-syncer`.

## Commands

- `validate` — parse and validate input (no AWS calls)
- `plan` — show planned creates, updates, and optional deletes
- `apply` — show plan, confirm, and apply changes

## Examples

### Plan with profile and role

```bash
secrets-syncer plan \
  --account-id 000000000000 \
  --region eu-central-1 \
  --profile my-iam-user-profile \
  --role-arn arn:aws:iam::000000000000:role/example-deployment-role \
  --input secrets.yaml
```

### Plan with default credential chain

```bash
secrets-syncer plan \
  --account-id 000000000000 \
  --region eu-central-1 \
  --role-arn arn:aws:iam::000000000000:role/example-deployment-role \
  --input secrets.yaml
```

### Stdin input

```bash
cat secrets.yaml | secrets-syncer plan \
  --account-id 000000000000 \
  --region eu-central-1 \
  --role-arn arn:aws:iam::000000000000:role/example-deployment-role \
  --input -
```

### Pre-decrypted SOPS pipeline (recommended for Terragrunt)

```bash
sops -d secrets.enc.yaml | secrets-syncer plan \
  --account-id 000000000000 \
  --region eu-central-1 \
  --role-arn arn:aws:iam::000000000000:role/example-deployment-role \
  --input -
```

### SOPS-encrypted file

```bash
secrets-syncer plan \
  --account-id 000000000000 \
  --region eu-central-1 \
  --role-arn arn:aws:iam::000000000000:role/example-deployment-role \
  --input secrets.enc.yaml \
  --sops
```

### Apply with auto-approve

```bash
sops -d secrets.enc.yaml | secrets-syncer apply \
  --account-id 000000000000 \
  --region eu-central-1 \
  --role-arn arn:aws:iam::000000000000:role/example-deployment-role \
  --input - \
  --auto-approve
```

## Input format

YAML or JSON with `version: 1`, `provider: aws-secretsmanager`, and a `secrets` list. The provider is read from the input file; there is no CLI flag for it.

```yaml
version: 1
provider: aws-secretsmanager
secrets:
  - key: /dev1/networking/bgp_auth_key
    value: "example-secret-value"
    description: "BGP auth key"
    encryption_key: "arn:aws:kms:eu-central-1:000000000000:key/example-key"
    tags:
      environment: dev1
      owner: platform
```

Fields:

- `key` — secret name/path (required)
- `value` — secret value (required)
- `description` — optional
- `encryption_key` — optional KMS key ARN, alias, or ID
- `tags` — optional map

## Terragrunt hooks

```hcl
before_hook "secrets_syncer_plan" {
  commands = ["plan"]
  execute = [
    "bash",
    "-c",
    "sops -d secrets.enc.yaml | secrets-syncer plan --account-id ${local.account_id} --region ${local.region} --role-arn ${local.role_arn} --input -"
  ]
}

before_hook "secrets_syncer_apply" {
  commands = ["apply"]
  execute = [
    "bash",
    "-c",
    "sops -d secrets.enc.yaml | secrets-syncer apply --account-id ${local.account_id} --region ${local.region} --role-arn ${local.role_arn} --input - --auto-approve"
  ]
}
```

Terragrunt may decrypt SOPS, filter secrets per account/region, or generate JSON/YAML before piping to `secrets-syncer`.

## Management tag

Secrets managed by this tool are tagged:

```text
secrets_syncer_managed = true
```

Rules:

- Only secrets with this tag can be updated or deleted by `secrets-syncer`
- Created secrets automatically receive the tag
- Existing secrets without the tag are never modified; plan/apply reports a conflict and skips them
- Deletion requires `--prune` and only affects tagged secrets

## AWS authentication

Credential resolution order:

1. **Environment variables** (`AWS_ACCESS_KEY_ID`, etc.) — used when set, even if `--profile` is also passed (so an active `awsume` session is not discarded).
2. **`--profile`** — when `awsume` is on PATH, uses `awsume` for MFA and optional `--role-arn` (same as `go-sops-secrets` / Terragrunt workflows). Falls back to the AWS SDK shared config if `awsume` is not installed.
3. **Default AWS credential chain** when neither env creds nor `--profile` is set.

Then:

- Assume `--role-arn` when provided and not already in the target account.
- Validate `--account-id` against `sts:GetCallerIdentity`.

Example (single command, no pre-awsume):

```bash
secrets-syncer plan \
  --account-id 000000000000 \
  --region eu-central-1 \
  --profile example-source-profile \
  --role-arn arn:aws:iam::000000000000:role/example-access-role \
  --input secrets.yaml
```

**MFA and stdin:** When using `--input -`, secret input is read from stdin. The apply confirmation prompt uses `/dev/tty` so you can still type `yes` after piping or heredoc input. Use `--auto-approve` for non-interactive runs (e.g. Terragrunt hooks).

## Safety

- Secret values are never printed in plan output, errors, or logs
- Decrypted content stays in memory only
- Does not replace Terraform/Terragrunt for infrastructure, IAM, KMS policies, or secret resource definitions
- Manages only secret **values** in a GitOps-friendly way

## Development

```bash
task test
task lint
task build
```

Unit tests use mocked AWS API clients and an in-memory provider; no live AWS account is required.

## Pre-commit hooks

```bash
pre-commit install
pre-commit run --all-files
```

## Release

1. Update `internal/cli/version.go` to the next `X.Y.Z-dev`
2. Commit the change
3. Tag and push:

```bash
git tag v0.2.0
git push origin main --tags
```

GitHub Actions will build and publish a release with binaries.

## License

[MIT](LICENSE)
