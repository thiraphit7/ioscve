#!/usr/bin/env python3
"""
Cross-compile iOS arm64 Mach-O binary without Xcode
Creates a minimal but valid iOS executable

Usage: python3 cross_compile.py
Output: output/SandboxEscapePOC.app/SandboxEscapePOC
"""

import struct
import os
import sys

# Mach-O Constants
MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 0x2
MH_NOUNDEFS = 0x1
MH_DYLDLINK = 0x4
MH_PIE = 0x200000
MH_TWOLEVEL = 0x80

CPU_TYPE_ARM64 = 0x100000C
CPU_SUBTYPE_ARM64_ALL = 0

# Load Commands
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLINKER = 0xE
LC_UUID = 0x1B
LC_BUILD_VERSION = 0x32
LC_SOURCE_VERSION = 0x2A
LC_MAIN = 0x80000028
LC_LOAD_DYLIB = 0xC

PLATFORM_IOS = 2
PAGE_SIZE = 0x4000  # 16KB for iOS


def align(value, alignment):
    """Align value to boundary"""
    return (value + alignment - 1) & ~(alignment - 1)


def pad_string(s, size):
    """Pad string to fixed size with null bytes"""
    b = s.encode('utf-8') if isinstance(s, str) else s
    return b + b'\x00' * (size - len(b))


def create_ios_binary():
    """Create a complete iOS arm64 Mach-O executable"""
    
    print("[*] Creating iOS arm64 Mach-O binary...")
    
    # Frameworks to link
    dylibs = [
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        "/System/Library/Frameworks/UIKit.framework/UIKit",
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
        "/System/Library/Frameworks/CoreSpotlight.framework/CoreSpotlight",
        "/usr/lib/libobjc.A.dylib",
        "/usr/lib/libSystem.B.dylib",
    ]
    
    # ARM64 assembly - minimal main() that returns 0
    # In full build, this would call UIApplicationMain
    code = bytearray([
        # _main:
        0xFD, 0x7B, 0xBF, 0xA9,  # stp x29, x30, [sp, #-16]!
        0xFD, 0x03, 0x00, 0x91,  # mov x29, sp
        0x00, 0x00, 0x80, 0x52,  # mov w0, #0
        0xFD, 0x7B, 0xC1, 0xA8,  # ldp x29, x30, [sp], #16
        0xC0, 0x03, 0x5F, 0xD6,  # ret
    ])
    
    # Build load commands
    lc_data = bytearray()
    ncmds = 0
    
    # 1. LC_SEGMENT_64 __PAGEZERO
    lc = struct.pack('<II', LC_SEGMENT_64, 72)
    lc += pad_string("__PAGEZERO", 16)
    lc += struct.pack('<QQQQ', 0, 0x100000000, 0, 0)
    lc += struct.pack('<iiII', 0, 0, 0, 0)
    lc_data += lc
    ncmds += 1
    
    # 2. LC_SEGMENT_64 __TEXT with __text section
    text_size = PAGE_SIZE
    lc = struct.pack('<II', LC_SEGMENT_64, 72 + 80)
    lc += pad_string("__TEXT", 16)
    lc += struct.pack('<QQQQ', 0x100000000, text_size, 0, text_size)
    lc += struct.pack('<iiII', 7, 5, 1, 0)  # rwx, rx, 1 section
    
    # __text section header
    code_offset = PAGE_SIZE - len(code)
    lc += pad_string("__text", 16)
    lc += pad_string("__TEXT", 16)
    lc += struct.pack('<QQ', 0x100000000 + code_offset, len(code))
    lc += struct.pack('<II', code_offset, 2)
    lc += struct.pack('<IIII', 0, 0, 0x80000400, 0)
    lc += struct.pack('<II', 0, 0)
    lc_data += lc
    ncmds += 1
    
    # 3. LC_SEGMENT_64 __LINKEDIT
    linkedit_off = text_size
    linkedit_size = PAGE_SIZE
    lc = struct.pack('<II', LC_SEGMENT_64, 72)
    lc += pad_string("__LINKEDIT", 16)
    lc += struct.pack('<QQQQ', 0x100000000 + linkedit_off, linkedit_size, linkedit_off, linkedit_size)
    lc += struct.pack('<iiII', 1, 1, 0, 0)
    lc_data += lc
    ncmds += 1
    
    # 4. LC_BUILD_VERSION (iOS 15.0)
    lc = struct.pack('<II', LC_BUILD_VERSION, 24)
    lc += struct.pack('<IIII', PLATFORM_IOS, 0x000F0000, 0x000F0000, 0)
    lc_data += lc
    ncmds += 1
    
    # 5. LC_SOURCE_VERSION
    lc = struct.pack('<II', LC_SOURCE_VERSION, 16)
    lc += struct.pack('<Q', 0x0001000000000000)
    lc_data += lc
    ncmds += 1
    
    # 6. LC_MAIN
    lc = struct.pack('<II', LC_MAIN, 24)
    lc += struct.pack('<QQ', code_offset, 0)
    lc_data += lc
    ncmds += 1
    
    # 7. LC_LOAD_DYLINKER
    dylinker = "/usr/lib/dyld"
    dylinker_size = align(12 + len(dylinker) + 1, 8)
    lc = struct.pack('<II', LC_LOAD_DYLINKER, dylinker_size)
    lc += struct.pack('<I', 12)
    lc += pad_string(dylinker, dylinker_size - 12)
    lc_data += lc
    ncmds += 1
    
    # 8. LC_UUID
    lc = struct.pack('<II', LC_UUID, 24)
    import hashlib
    uuid_bytes = hashlib.md5(b"SandboxEscapePOC").digest()
    lc += uuid_bytes
    lc_data += lc
    ncmds += 1
    
    # 9. LC_LOAD_DYLIB for each framework
    for dylib in dylibs:
        dylib_cmdsize = align(24 + len(dylib) + 1, 8)
        lc = struct.pack('<II', LC_LOAD_DYLIB, dylib_cmdsize)
        lc += struct.pack('<IIII', 24, 2, 0x00010000, 0x00010000)
        lc += pad_string(dylib, dylib_cmdsize - 24)
        lc_data += lc
        ncmds += 1
    
    # 10. LC_SYMTAB
    lc = struct.pack('<II', LC_SYMTAB, 24)
    lc += struct.pack('<IIII', linkedit_off, 0, linkedit_off, 0)
    lc_data += lc
    ncmds += 1
    
    # 11. LC_DYSYMTAB
    lc = struct.pack('<II', LC_DYSYMTAB, 80)
    lc += b'\x00' * 64  # All zeros for minimal binary
    lc_data += lc
    ncmds += 1
    
    sizeofcmds = len(lc_data)
    
    # Build Mach-O header
    flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE
    header = struct.pack('<IiiIIIII',
                        MH_MAGIC_64,
                        CPU_TYPE_ARM64,
                        CPU_SUBTYPE_ARM64_ALL,
                        MH_EXECUTE,
                        ncmds,
                        sizeofcmds,
                        flags,
                        0)
    
    # Assemble final binary
    binary = bytearray()
    binary += header
    binary += lc_data
    
    # Pad to code location
    current_size = len(binary)
    text_padding = text_size - len(code) - current_size
    binary += b'\x00' * text_padding
    binary += code
    
    # Add __LINKEDIT segment
    binary += b'\x00' * linkedit_size
    
    print(f"[+] Binary size: {len(binary):,} bytes")
    print(f"[+] Load commands: {ncmds}")
    print(f"[+] Linked frameworks: {len(dylibs)}")
    
    return bytes(binary)


def main():
    # Create output directory
    output_dir = "output/SandboxEscapePOC.app"
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate binary
    binary = create_ios_binary()
    
    # Write binary
    binary_path = os.path.join(output_dir, "SandboxEscapePOC")
    with open(binary_path, "wb") as f:
        f.write(binary)
    
    # Make executable
    os.chmod(binary_path, 0o755)
    
    print(f"[+] Saved to: {binary_path}")
    
    # Verify with file command if available
    try:
        import subprocess
        result = subprocess.run(["file", binary_path], capture_output=True, text=True)
        print(f"[+] {result.stdout.strip()}")
    except:
        pass
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
