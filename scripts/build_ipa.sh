#!/bin/bash
#
# Build iOS IPA from cross-compiled binary
# Usage: ./scripts/build_ipa.sh
#

set -e

APP_NAME="SandboxEscapePOC"
BUNDLE_ID="com.research.sandboxescapepoc"
OUTPUT_DIR="output"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         iOS IPA Builder - Cross-Platform                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if binary exists
if [ ! -f "${OUTPUT_DIR}/${APP_NAME}.app/${APP_NAME}" ]; then
    echo "[!] Binary not found. Running cross_compile.py first..."
    python3 scripts/cross_compile.py
fi

APP_DIR="${OUTPUT_DIR}/${APP_NAME}.app"

echo "[1/5] Copying resources..."

# Copy Info.plist
cp "SandboxEscapePOC/SandboxEscapePOC/Info.plist" "${APP_DIR}/"

# Copy LaunchScreen if exists
if [ -f "SandboxEscapePOC/SandboxEscapePOC/LaunchScreen.storyboard" ]; then
    cp "SandboxEscapePOC/SandboxEscapePOC/LaunchScreen.storyboard" "${APP_DIR}/"
fi

# Create PkgInfo
echo -n "APPL????" > "${APP_DIR}/PkgInfo"

# Copy source for reference
mkdir -p "${APP_DIR}/Source"
cp "SandboxEscapePOC/SandboxEscapePOC/main.m" "${APP_DIR}/Source/" 2>/dev/null || true

echo "[2/5] Creating code signature structure..."

# Create _CodeSignature directory
mkdir -p "${APP_DIR}/_CodeSignature"

# Create minimal CodeResources
cat > "${APP_DIR}/_CodeSignature/CodeResources" << 'CODERESOURCES'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>files</key>
    <dict>
        <key>Info.plist</key>
        <data>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</data>
    </dict>
    <key>files2</key>
    <dict>
        <key>Info.plist</key>
        <dict>
            <key>hash2</key>
            <data>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</data>
        </dict>
    </dict>
    <key>rules</key>
    <dict>
        <key>^.*</key>
        <true/>
    </dict>
    <key>rules2</key>
    <dict>
        <key>^.*</key>
        <true/>
    </dict>
</dict>
</plist>
CODERESOURCES

# Create empty embedded.mobileprovision (for sideloading tools)
touch "${APP_DIR}/embedded.mobileprovision"

echo "[3/5] App bundle contents:"
ls -la "${APP_DIR}/"
echo ""

echo "[4/5] Creating Payload structure..."
rm -rf "${OUTPUT_DIR}/Payload"
mkdir -p "${OUTPUT_DIR}/Payload"
cp -r "${APP_DIR}" "${OUTPUT_DIR}/Payload/"

echo "[5/5] Compressing to IPA..."
cd "${OUTPUT_DIR}"
rm -f "${APP_NAME}.ipa"
zip -r "${APP_NAME}.ipa" Payload -x "*.DS_Store" -x "__MACOSX/*"
rm -rf Payload
cd ..

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                    BUILD COMPLETE!                        ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║  Output: ${OUTPUT_DIR}/${APP_NAME}.ipa"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Show file info
ls -lh "${OUTPUT_DIR}/${APP_NAME}.ipa"
file "${OUTPUT_DIR}/${APP_NAME}.app/${APP_NAME}"
