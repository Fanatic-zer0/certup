#!/usr/bin/env bash
# post-build-sign.sh
# Ad-hoc sign the Tauri .app bundle and repackage the DMG.
# Run automatically via: npm run ship
set -euo pipefail

BUNDLE_DIR="src-tauri/target/release/bundle"
APP="$BUNDLE_DIR/macos/CertUp.app"
DMG_DIR="$BUNDLE_DIR/dmg"

# Locate the DMG Tauri just built
ORIGINAL_DMG=$(find "$DMG_DIR" -maxdepth 1 -name "*.dmg" ! -name "*_adhoc*" | head -1)
OUT_DMG="${ORIGINAL_DMG%.dmg}_adhoc.dmg"

echo "==> Stripping broken/empty signature from .app …"
codesign --remove-signature "$APP" 2>/dev/null || true

echo "==> Ad-hoc signing (no Developer ID required) …"
codesign --force --deep --sign - "$APP"

echo "==> Verifying signature …"
codesign --verify --deep "$APP" && echo "    ✓ Signature OK"

echo "==> Removing macOS quarantine from .app …"
xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true

echo "==> Rebuilding DMG …"
hdiutil create \
  -volname "CertUp" \
  -srcfolder "$APP" \
  -ov -format UDZO \
  "$OUT_DMG" > /dev/null

# Remove quarantine from the DMG itself (helps when shared via USB/AirDrop)
xattr -dr com.apple.quarantine "$OUT_DMG" 2>/dev/null || true

echo ""
echo "  ✓ Done: $OUT_DMG"
echo ""
echo "  Recipients: right-click → Open on first launch to bypass Gatekeeper."
echo "  Or they can run:  xattr -cr /Applications/CertUp.app"
