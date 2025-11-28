#!/bin/bash
#
# build.sh - Cross-compiles a Go application for multiple architectures.
#
# USAGE:
# 1. Ensure you have your Go package files in the current directory.
# 2. Make the script executable: chmod +x build.sh
# 3. Run the script: ./build.sh
# 4. The compiled binaries will appear in the 'bin' directory.

# --- Configuration ---
APP_NAME="wScanner" # Replace with the desired name of your binary
SOURCE_FILE="." # Use "." to build the entire Go package in the current directory (go build .).
OUTPUT_DIR="bin"

# Define the target platforms using GOOS (Operating System) and GOARCH (Architecture)
# Raspberry Pi 5 uses 64-bit Linux (arm64, or aarch64)
TARGETS=(
    "linux/amd64"    # x64 Linux
    "linux/arm64"    # Raspberry Pi 5 Linux (ARM)
    "darwin/amd64"   # macOS (Intel/x64 - Older Macs or non-Apple Silicon)
    "darwin/arm64"   # macOS (Apple Silicon / M1, M2, M3 chips - ARM)
)

# --- Setup and Validation ---

echo "Starting cross-compilation for '$APP_NAME'..."

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"
echo "Output directory created: $OUTPUT_DIR"

# Note: We now check for any *.go file instead of just main.go
if find . -maxdepth 1 -name "*.go" -print -quit | grep -q .; then
    echo "Go source files found."
else
    echo "ERROR: No Go source files found in the current directory."
    exit 1
fi

# --- Versioning Setup ---
# Attempt to get Git version information, otherwise use a default
VERSION="beta-v2.0.0"
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "Building version: $VERSION (Date: $BUILD_DATE)"


# --- Compilation Loop ---

for TARGET in "${TARGETS[@]}"; do
    # Split the target string into GOOS and GOARCH
    IFS='/' read -r GOOS GOARCH <<< "$TARGET"

    # Define the output file name
    # Linux and RPi binaries have no extension, macOS usually has none, but we add the target for clarity.
    OUTPUT_FILE="$OUTPUT_DIR/$APP_NAME-$GOOS-$GOARCH-$VERSION"

    echo "----------------------------------------"
    echo "Compiling for: $GOOS/$GOARCH"
    
    # Set the Linker Flags (-ldflags) to inject version and build info into the Go program (main package).
    # The Go program must define 'var Version string' and 'var BuildDate string' in the main package.
    # -s and -w flags remove debugging symbols and DWARF generation, reducing binary size.
    LDFLAGS="-s -w -X main.Version=$VERSION -X main.BuildDate=$BUILD_DATE -X main.GOOS=$GOOS -X main.GOARCH=$GOARCH"

    # Set the environment variables for cross-compilation
    # CGO_ENABLED=0 disables the C linker (libc), making the binary statically compiled and fully self-contained.
    # This is strongly recommended for cross-compilation to avoid dependency issues on the target machine.
    
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -ldflags "$LDFLAGS" -o "$OUTPUT_FILE" "$SOURCE_FILE"

    if [ $? -eq 0 ]; then
        echo "SUCCESS: Binary saved to $OUTPUT_FILE"
    else
        echo "FAILURE: Compilation failed for $GOOS/$GOARCH"
    fi

done

echo "----------------------------------------"
echo "All cross-compilation tasks finished."