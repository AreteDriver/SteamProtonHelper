# Example Outputs

This directory contains example outputs from running the Steam Proton Helper on different systems.

## Ubuntu 22.04 - Missing Dependencies

```
╔══════════════════════════════════════════╗
║   Steam + Proton Helper for Linux       ║
╔══════════════════════════════════════════╗

Checking Steam and Proton dependencies...


==================================================
Dependency Check Summary
==================================================

✓ Linux Distribution: ubuntu (apt)
✗ Steam Client: Steam is not installed
  Fix: sudo apt update && sudo apt install -y steam
⚠ Proton: Proton not found (install from Steam client)
  Fix: Install Proton from Steam > Settings > Compatibility > Enable Steam Play
✗ Vulkan Tools: Vulkan tools not installed
  Fix: sudo apt update && sudo apt install -y vulkan-tools
⚠ Mesa/OpenGL: Mesa utilities not found (may not be needed)
✓ 64-bit System: System supports 64-bit
⚠ 32-bit Support: 32-bit architecture not enabled
  Fix: sudo dpkg --add-architecture i386 && sudo apt update
✓ Wine Dependencies: Package manager available for Wine dependencies

Results:
  Passed: 3
  Failed: 2
  Warnings: 3

✗ Please install the missing dependencies above.

Additional Tips:
  • To enable Proton in Steam: Settings → Compatibility → Enable Steam Play
  • For best performance, keep your graphics drivers updated
  • Visit ProtonDB (protondb.com) to check game compatibility
```

## Fedora 38 - Fully Configured

```
╔══════════════════════════════════════════╗
║   Steam + Proton Helper for Linux       ║
╔══════════════════════════════════════════╗

Checking Steam and Proton dependencies...


==================================================
Dependency Check Summary
==================================================

✓ Linux Distribution: fedora (dnf)
✓ Steam Client: Steam is installed
✓ Proton: Proton installation found
✓ Vulkan Support: Vulkan is available
✓ Mesa/OpenGL: Mesa utilities available
✓ 64-bit System: System supports 64-bit
✓ 32-bit Support: Assuming 32-bit support available
✓ Wine Dependencies: Package manager available for Wine dependencies

Results:
  Passed: 7
  Failed: 0
  Warnings: 0

✓ Your system is ready for Steam gaming!

Additional Tips:
  • To enable Proton in Steam: Settings → Compatibility → Enable Steam Play
  • For best performance, keep your graphics drivers updated
  • Visit ProtonDB (protondb.com) to check game compatibility
```

## Arch Linux - Partial Setup

```
╔══════════════════════════════════════════╗
║   Steam + Proton Helper for Linux       ║
╔══════════════════════════════════════════╗

Checking Steam and Proton dependencies...


==================================================
Dependency Check Summary
==================================================

✓ Linux Distribution: arch (pacman)
✓ Steam Client: Steam is installed
⚠ Proton: Proton not found (install from Steam client)
  Fix: Install Proton from Steam > Settings > Compatibility > Enable Steam Play
✓ Vulkan Support: Vulkan is available
✓ Mesa/OpenGL: Mesa utilities available
✓ 64-bit System: System supports 64-bit
✓ 32-bit Support: Assuming 32-bit support available
✓ Wine Dependencies: Package manager available for Wine dependencies

Results:
  Passed: 6
  Failed: 0
  Warnings: 1

⚠ Your system is mostly ready, but check the warnings above.

Additional Tips:
  • To enable Proton in Steam: Settings → Compatibility → Enable Steam Play
  • For best performance, keep your graphics drivers updated
  • Visit ProtonDB (protondb.com) to check game compatibility
```
