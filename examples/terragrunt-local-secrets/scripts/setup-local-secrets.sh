#!/usr/bin/env bash
set -euo pipefail

if ! command -v age-keygen >/dev/null 2>&1; then
  echo "age-keygen is required. Install age and try again." >&2
  exit 1
fi

mkdir -p .secrets
key_path=".secrets/age.key"

if [[ -f "${key_path}" ]]; then
  echo "Key already exists at ${key_path}" >&2
  exit 1
fi

age-keygen -o "${key_path}"
recipient=$(grep -E '^# public key:' "${key_path}" | awk '{print $4}')

cat > .sops.yaml <<EOF
creation_rules:
  - path_regex: global-secrets(\.enc)?\.yaml$
    age: ${recipient}
EOF

api_key=$(openssl rand -hex 16)
unused_key=$(openssl rand -hex 8)

cat > global-secrets.yaml <<EOF
secrets:
  - key: /demo/app/api_key
    value: ${api_key}
    description: API key for demo app
    encryption_key: alias/aws/secretsmanager
    tags:
      env: dev
      owner: platform
    create_secrets_manager: true
  - key: /demo/app/unused
    value: ${unused_key}
    description: Not managed by Secrets Manager
    create_secrets_manager: false
EOF

export SOPS_AGE_KEY_FILE="${key_path}"
sops -e global-secrets.yaml > global-secrets.enc.yaml

cat <<EOF
Local secrets setup complete.

Private key: ${key_path}
Public key:  ${recipient}
Generated:   global-secrets.yaml
Encrypted:   global-secrets.enc.yaml

Next steps:
  export SOPS_AGE_KEY_FILE="${key_path}"
  sops -e global-secrets.yaml > global-secrets.enc.yaml  # after editing secrets
EOF
