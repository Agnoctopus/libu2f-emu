#/bin/sh

# Secure mode
set -e

# Target to put or data
target_dir="./keys"

if [ "$#" -ne 0 ]; then
    target_dir="$1"
fi

# Check non-existence
if [ -e "$target_dir" ]; then
    echo "Usage: ./setup.sh [DIR]"
    echo ""
    echo "DIR:  non existant directory"
    exit 1
fi


# Create dir
mkdir -p "$target_dir"

# EC Key
openssl ecparam -name prime256v1 -genkey -noout -out "$target_dir"/private-key.pem

# x509
openssl req -new -x509 -key "$target_dir"/private-key.pem -out "$target_dir"/certificate.pem -days 1460  -subj '/CN=U2F emulated'

# AES entropy bits
head -c 48 /dev/random > "$target_dir"/entropy
