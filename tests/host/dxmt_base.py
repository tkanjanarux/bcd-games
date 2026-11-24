"""The dxmt revision the fork's winemetal / dxmt / airconv patch checks start from.

madeira-bcd: since the 2026-10-15 upstream merge the dxmt pin (128b297) carries
the fork's patches that went upstream (willfaust/dxmt #9 and #21-#33), so a
check that applies a patch to the pin as committed would find it already there.
Those checks start from OVERLAY_BASE, the pin the patches were written against,
instead: rev() names it (fetched by SHA from the original public repository when
a shallow clone lacks it) when the pin carries the wave, else HEAD as before.
The BCD submodule's remote does not advertise this historical commit. CI builds
from the new pin plus the same patches, which leaves the same files (the pin's
own additions are those patches' output; checked when the merge was made).
"""
from pathlib import Path
import subprocess

OVERLAY_BASE = 'db546ee466ad50ec6463edb5fa183de11db43761'
OVERLAY_REPOSITORY = 'https://github.com/willfaust/dxmt.git'
PIN_MARKER = 'madeira_rp_lean_on'   # willfaust/dxmt#26, in the wave's pin and later


def rev(dxmt):
    dxmt = Path(dxmt)
    wm = dxmt / 'src/winemetal/unix/winemetal_unix.c'
    if not wm.is_file() or PIN_MARKER not in wm.read_text(errors='ignore'):
        return 'HEAD'
    have = subprocess.run(['git', '-C', str(dxmt), 'cat-file', '-e', OVERLAY_BASE + '^{commit}'], capture_output=True)
    if have.returncode:
        subprocess.run(['git', '-C', str(dxmt), 'fetch', '-q', '--depth=1', OVERLAY_REPOSITORY, OVERLAY_BASE], check=True)
    return OVERLAY_BASE
