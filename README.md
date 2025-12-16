# 🔓 iOS Sandbox Escape PoC

[![Build iOS IPA](https://github.com/YOUR_USERNAME/ios-sandbox-escape-poc/actions/workflows/build-ios.yml/badge.svg)](https://github.com/YOUR_USERNAME/ios-sandbox-escape-poc/actions/workflows/build-ios.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![iOS 15.0+](https://img.shields.io/badge/iOS-15.0+-blue.svg)](https://developer.apple.com/ios/)

iOS security research app for testing sandbox escape techniques on iOS 26.1.

## 📋 Overview

This project contains Proof-of-Concept implementations for various iOS sandbox escape and privilege escalation techniques, including:

| CVE | Name | Description |
|-----|------|-------------|
| CVE-2025-43448 | CloudKit Symlink | Symlink-based sandbox container escape |
| CVE-2025-43407 | Assets Bypass | mobileassetd entitlements bypass |
| CVE-2019-7286 | cfprefsd | XPC multi-message exploit patterns |
| - | Disk Amplification | Write amplification DoS testing |
| - | Timing Channel | Side-channel information leakage |

## 🏗️ Project Structure

```
ios-sandbox-escape-poc/
├── .github/
│   └── workflows/
│       └── build-ios.yml      # GitHub Actions CI/CD
├── SandboxEscapePOC/
│   ├── main.m                 # Main source code (Objective-C)
│   ├── Info.plist             # App configuration
│   ├── LaunchScreen.storyboard
│   └── SandboxEscapePOC.xcodeproj/
├── scripts/
│   ├── cross_compile.py       # Cross-platform Mach-O generator
│   └── build_ipa.sh           # IPA packaging script
├── docs/
│   └── RESEARCH.md            # Detailed vulnerability research
├── README.md
├── LICENSE
└── .gitignore
```

## 🚀 Quick Start

### Option 1: Download Pre-built IPA

1. Go to [Releases](https://github.com/YOUR_USERNAME/ios-sandbox-escape-poc/releases)
2. Download `SandboxEscapePOC.ipa`
3. Install using your preferred method (see [Installation](#-installation))

### Option 2: Build with Xcode (macOS)

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/ios-sandbox-escape-poc.git
cd ios-sandbox-escape-poc

# Open in Xcode
open SandboxEscapePOC/SandboxEscapePOC.xcodeproj

# Build: ⌘B
# Run: ⌘R
```

### Option 3: Build with GitHub Actions

Push to `main` branch or create a tag to trigger automatic builds:

```bash
git tag v1.0.0
git push origin v1.0.0
```

### Option 4: Cross-compile on Linux

```bash
# Install dependencies
sudo apt-get install python3 zip

# Generate Mach-O binary
python3 scripts/cross_compile.py

# Package IPA
./scripts/build_ipa.sh
```

## 📱 Installation

### TrollStore (Recommended for iOS 15-17)
1. Open TrollStore
2. Select the IPA file
3. Tap "Install"

### Sideloadly
```bash
sideloadly SandboxEscapePOC.ipa
```

### AltStore
1. Open AltStore on device
2. Go to "My Apps" → "+"
3. Select the IPA file

### Jailbroken Device
```bash
# Copy to device
scp SandboxEscapePOC.ipa root@<device_ip>:/var/mobile/

# SSH and install
ssh root@<device_ip>
cd /var/mobile
unzip SandboxEscapePOC.ipa
cp -r Payload/SandboxEscapePOC.app /Applications/
uicache -p /Applications/SandboxEscapePOC.app
```

## 🔧 Building from Source

### Requirements

- **Xcode Build**: macOS 12+ with Xcode 14+
- **Cross-compile**: Python 3.8+, any OS

### Xcode Build

```bash
cd SandboxEscapePOC

# Build for device
xcodebuild \
    -project SandboxEscapePOC.xcodeproj \
    -scheme SandboxEscapePOC \
    -sdk iphoneos \
    -configuration Release \
    CODE_SIGN_IDENTITY="-" \
    CODE_SIGNING_REQUIRED=NO

# Create IPA
mkdir -p Payload
cp -r build/Release-iphoneos/SandboxEscapePOC.app Payload/
zip -r SandboxEscapePOC.ipa Payload
```

### Manual Compilation (clang)

```bash
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
clang -isysroot $SDK \
      -arch arm64 \
      -mios-version-min=15.0 \
      -fobjc-arc \
      -framework UIKit \
      -framework Foundation \
      -framework CoreSpotlight \
      -o SandboxEscapePOC \
      SandboxEscapePOC/main.m
```

## 📊 Features

The app provides an interactive UI to test:

| Feature | Description |
|---------|-------------|
| **System Info** | Display device information and sandbox container paths |
| **CloudKit Symlink** | Attempt symlink-based sandbox escape |
| **Assets Bypass** | Test mobileassetd entitlement bypass |
| **cfprefsd XPC** | Test XPC multi-message patterns |
| **Disk Amplification** | Measure write amplification potential |
| **Timing Channel** | Analyze timing side-channel leakage |
| **Run All** | Execute all tests sequentially |

## 🔬 Research Notes

### CVE-2025-43448: CloudKit Symlink Escape

The vulnerability exists in CloudKit's handling of symbolic links within app containers. By creating a symlink pointing outside the sandbox, an attacker can potentially read/write files in privileged locations.

```objc
NSString *target = @"/var/mobile/Library/Preferences";
NSString *link = [container stringByAppendingPathComponent:@"escape_link"];
[[NSFileManager defaultManager] createSymbolicLinkAtPath:link 
                                     withDestinationPath:target 
                                                   error:nil];
```

### CVE-2025-43407: mobileassetd Bypass

The mobileassetd service doesn't properly validate entitlements for certain operations, allowing unprivileged apps to query system update information.

### cfprefsd Multi-Message Pattern

Based on CVE-2019-7286, the cfprefsd service can be abused through crafted multi-message XPC requests to cause resource exhaustion or information disclosure.

## ⚠️ Disclaimer

**FOR SECURITY RESEARCH PURPOSES ONLY**

This tool is intended for:
- Security researchers testing their own devices
- Educational purposes to understand iOS security
- Responsible vulnerability disclosure

**DO NOT** use this tool:
- On devices you don't own
- For malicious purposes
- To violate any laws or regulations

The authors are not responsible for any misuse of this software.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📚 References

- [Apple Security Updates](https://support.apple.com/en-us/HT201222)
- [iOS Security Guide](https://support.apple.com/guide/security)
- [Project Zero Blog](https://googleprojectzero.blogspot.com/)
- [xtool - Cross-platform Xcode replacement](https://github.com/xtool-org/xtool)

## 📞 Contact

- Create an [Issue](https://github.com/YOUR_USERNAME/ios-sandbox-escape-poc/issues)
- Submit a [Pull Request](https://github.com/YOUR_USERNAME/ios-sandbox-escape-poc/pulls)

---

**Made with ☕ for iOS Security Research**
