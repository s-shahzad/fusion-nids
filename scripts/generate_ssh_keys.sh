#!/usr/bin/env sh
set -eu

KEY_NAME="${1:-universal_nids_cloud}"
KEY_COMMENT="${2:-universal-nids-cloud}"
SSH_DIR="${HOME}/.ssh"
KEY_PATH="${SSH_DIR}/${KEY_NAME}"

if ! command -v ssh-keygen >/dev/null 2>&1; then
  echo "ssh-keygen is required but was not found in PATH." >&2
  exit 1
fi

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

if [ -f "$KEY_PATH" ] || [ -f "${KEY_PATH}.pub" ]; then
  echo "SSH key already exists: $KEY_PATH"
else
  ssh-keygen -t rsa -b 4096 -C "$KEY_COMMENT" -f "$KEY_PATH" -N ""
  chmod 600 "$KEY_PATH"
  chmod 644 "${KEY_PATH}.pub"
fi

echo ""
echo "Private key: $KEY_PATH"
echo "Public key:  ${KEY_PATH}.pub"
echo ""
echo "Public key contents:"
cat "${KEY_PATH}.pub"
echo ""
echo "Upload or paste only the public key into Oracle Cloud or Google Cloud."
