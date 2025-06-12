#!/bin/bash

# Exit on first error
set -e

# Define the binary name
BINARY_NAME="yard-api-server"

# Build the project in release mode
echo "Building the project in release mode..."
cargo build --release

# Copy the binary to /usr/local/bin, overwrite if exists
echo "Copying the binary to /usr/local/bin (requires sudo)..."
sudo cp -f "target/release/$BINARY_NAME" /usr/local/bin/

echo "Done! $BINARY_NAME has been installed to /usr/local/bin."
systemctl restart yard-api-server
tail -f /var/log/yard-api-server/yard-api-server.log
