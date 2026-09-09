#!/bin/bash
# Сборка TGWSProxyMac.app (release)
set -e
cd "$(dirname "$0")/App"

swift build -c release 2>&1 | grep -E "error" && { echo "BUILD FAILED"; exit 1; } || true

BIN=".build/release/TGWSProxyMac"
[ -f "$BIN" ] || { echo "бинарник не найден"; exit 1; }

APP_DIR="$HOME/Desktop/tgws-proxy-mac/TGWSProxyMac.app"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

cp "$BIN" "$APP_DIR/Contents/MacOS/TGWSProxyMac"
cp "$HOME/Desktop/tgws-proxy-mac/AppIcon.icns" "$APP_DIR/Contents/Resources/AppIcon.icns"

cat > "$APP_DIR/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>TG WS Proxy</string>
    <key>CFBundleDisplayName</key><string>TG WS Proxy</string>
    <key>CFBundleIdentifier</key><string>com.flowseal.tgwsproxy.mac</string>
    <key>CFBundleVersion</key><string>1.0.0</string>
    <key>CFBundleShortVersionString</key><string>1.0.0</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleExecutable</key><string>TGWSProxyMac</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>LSUIElement</key><true/>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

# ad-hoc подпись для локального запуска
codesign --force --sign - --deep "$APP_DIR" 2>/dev/null || true

echo "GOTOVO: $APP_DIR"
# проверка
plutil -lint "$APP_DIR/Contents/Info.plist"
echo "bundle: $(du -sh "$APP_DIR" | cut -f1)"
