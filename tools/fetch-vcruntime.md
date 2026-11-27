# Microsoft Visual C++ runtime for the iOS build

The x64 Windows guest needs the Microsoft Visual C++ runtime. Microsoft
distributes these proprietary DLLs as part of its own redistributable. The
independent iOS build extracts them directly from that distribution. It does
not take them from a released BCD IPA.

## CI inputs and checks

In [build-ipa.yml](../.github/workflows/build-ipa.yml), **Fetch the VC++ runtime
DLLs from Microsoft** downloads the x64 installer from Microsoft and compares
its SHA-256 with the pin in the workflow before extraction. The package is
a WiX Burn bundle. `cabextract` scans the embedded cabinets, and
`msiextract` (from `msitools`) handles MSI layers when needed. The PE
machine check accepts AMD64 (`0x8664`) and rejects ARM64 payloads even when
they have the right DLL name. The strict host checker also requires PE32+
and a structurally valid certificate table. That structural check is not
a substitute for cryptographic Authenticode verification.

Fourteen files belong in the x64 set (twelve runtime DLLs and two MFC DLLs):

- `concrt140.dll`
- `msvcp140.dll`
- `msvcp140_1.dll`
- `msvcp140_2.dll`
- `msvcp140_atomic_wait.dll`
- `msvcp140_codecvt_ids.dll`
- `vcamp140.dll`
- `vccorlib140.dll`
- `vcomp140.dll`
- `vcruntime140.dll`
- `vcruntime140_1.dll`
- `vcruntime140_threads.dll`
- `mfc140.dll`
- `mfc140u.dll`

The separate x86 Microsoft installer is hash-pinned for the 32-bit MFC host
test. CI does not bundle that installer into the IPA.

## Local extraction and testing

For a local reproduction, independently check the x64 installer's SHA-256
against the workflow pin first, then pass that same file to the helper.
Install `cabextract`, `msitools` and Python 3 before running the commands.

```sh
VCRUNTIME_INSTALLER=/absolute/path/to/VC_redist.x64.exe ./tools/fetch-vcruntime.sh
python3 tests/host/check-vcruntime.py --strict
```

The helper defaults to writing into `app/Madeira/x86_64-vcruntime/`.
`VCRUNTIME_DEST` can override the output path. If no installer is supplied,
the helper can download Microsoft's current installer over HTTPS and prints
its digest when `shasum` is available. That convenience path is not a
reproduction of the pinned CI input.

At runtime, `WineProcessBridge.m` can also read the app's
`Documents/vcruntime` folder. Only known runtime DLL names are considered.
The MFC entries are enabled by default. Set `MADEIRA_MFC=0` for a game to
omit those MFC links and remove stale links from an earlier session.
