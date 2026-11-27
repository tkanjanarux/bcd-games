# Playport KosmicKrisp patch notes

These notes describe the patches in the public BCD v0.1.712 source tree. The patch files are the source of truth. The build applies them in numeric order with `../build-playport-kosmickrisp.sh`.

Patches 0001–0031 are the bundled Playport series. Later BCD patches include:

| Patch | Behavior |
| --- | --- |
| `0032-kk-in-process-opaque-fd-memory-and-semaphores.patch` | `MADEIRA_KK_OPAQUE_FD=1` enables process-local sharing of Metal memory and semaphore objects through opaque file descriptors. |
| `0033-kk-snorm-color-attachments-report-blending.patch` | `MADEIRA_KK_SNORM_BLEND=1` reports the color-attachment blend feature for signed normalized formats. The default reports the original capabilities. |
| `0034-kk-log-the-msl-source-metal-refused.patch` | When Metal rejects a library, `[kk-msl-fail]` logs numbered MSL for the first three failures, at most 800 lines per source. |
| `0035-kk-drop-stores-to-multisampled-storage-images.patch` | `MADEIRA_KK_MS_STORE_DROP=1` binds multisampled storage images read-only and omits stores and their fences. The default leaves shader translation unchanged. |
| `0036-wsi-metal-apple-frame-interpolation-MADEIRA_VT_INTERP.patch` | Adds opt-in VideoToolbox interpolation and Lossless Scaling frame generation to the Metal Vulkan presentation path. |
