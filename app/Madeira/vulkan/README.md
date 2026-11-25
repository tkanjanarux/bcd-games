# Wine Vulkan bundle libraries

The independent v0.1.712 build generates `winevulkan.dll` and `vulkan-1.dll`
from the pinned Wine submodule with `tools/build-vulkan-dlls.sh`.

- `arm64ec-windows/` holds the ARM64EC pair for 64-bit Windows programs.
- `i386-windows/` holds the i386 pair for 32-bit Windows programs.

These opt-in libraries are staged in the Vulkan bundle directory rather than
in the default Wine DLL farms. `tools/check-vulkan-shipped.py` checks the DLL
pairs; the i386 pair is required when the package includes the i386 farm.
This directory does not supply prebuilts for the independent build.
