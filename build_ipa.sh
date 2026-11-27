#!/usr/bin/env bash
# 用 swiftc 直接把 Swift 源码编译成 .app，再打成未签名 IPA。
# 不需要 .xcodeproj，避免 pbxproj 版本问题。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

APP_NAME="NinebotKey"
BUNDLE_ID="com.ninebotkey.app"
MIN_IOS="15.0"
SRC_DIR="NinebotKey"
BUILD="build"
APP="$BUILD/Payload/$APP_NAME.app"

echo "==> Xcode"
xcodebuild -version || true
xcrun swiftc --version || true

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
echo "==> SDK: $SDK"

rm -rf "$BUILD"
mkdir -p "$APP"

echo "==> swiftc 编译（Swift 5 语言模式，锁死避免 Swift 6 严格并发报错）"
xcrun --sdk iphoneos swiftc \
  -sdk "$SDK" \
  -target "arm64-apple-ios${MIN_IOS}" \
  -module-name "$APP_NAME" \
  -swift-version 5 \
  -parse-as-library \
  -O \
  -whole-module-optimization \
  -emit-executable \
  "$SRC_DIR/AES128.swift" \
  "$SRC_DIR/Frame.swift" \
  "$SRC_DIR/V2Crypto.swift" \
  "$SRC_DIR/Models.swift" \
  "$SRC_DIR/Session.swift" \
  "$SRC_DIR/ContentView.swift" \
  "$SRC_DIR/NinebotKeyApp.swift" \
  -o "$APP/$APP_NAME"

echo "==> 组装 bundle"
cp "$SRC_DIR/Info.plist" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $BUNDLE_ID" "$APP/Info.plist" >/dev/null
/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable $APP_NAME" "$APP/Info.plist" >/dev/null
chmod +x "$APP/$APP_NAME"

if [ -f "$SRC_DIR/Assets.car" ]; then cp "$SRC_DIR/Assets.car" "$APP/"; fi

echo "==> 结构检查"
ls -la "$APP"
file "$APP/$APP_NAME" || true
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$APP/Info.plist"

# 未签名包：不 codesign，交给 TrollStore / Sideloadly / AltStore 签
if [ "${SIGN_ADHOC:-0}" = "1" ]; then
  echo "==> ad-hoc 签名"
  codesign --force --sign - --timestamp=none "$APP" || true
fi

echo "==> 打 IPA"
( cd "$BUILD" && zip -qry "${APP_NAME}-unsigned.ipa" Payload )
ls -la "$BUILD/${APP_NAME}-unsigned.ipa"

echo "==> 完成: $BUILD/${APP_NAME}-unsigned.ipa"
