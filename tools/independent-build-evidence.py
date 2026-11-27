#!/usr/bin/env python3
"""Fail-closed preflight and evidence packager for an independent BCD build."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/build-ipa.yml"
INPUT_LOCK = ROOT / "security/independent-build-inputs.json"
AUDIT = ROOT / "docs/independent-build-security-audit.md"
BASELINE = "f811dd05a9183cda20ffd3956cb1958cafe654f7"
APP_ENTITLEMENTS = ROOT / "app/Madeira/Madeira.entitlements"
SIDELOAD_ENTITLEMENTS = ROOT / "app/Madeira/Sideload.entitlements"


def fail(message: str) -> None:
    raise SystemExit(f"independent-build preflight: {message}")


def run(*args: str, cwd: Path = ROOT, check: bool = True) -> str:
    proc = subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)
    if check and proc.returncode:
        fail(f"command failed: {shlex.join(args)}\n{proc.stderr[-4000:]}")
    return proc.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def verify_entitlements() -> dict[str, dict[str, object]]:
    expected = {
        APP_ENTITLEMENTS: [
            "com.apple.developer.kernel.extended-virtual-addressing",
            "com.apple.developer.kernel.increased-memory-limit",
            "com.apple.security.cs.allow-jit",
        ],
        SIDELOAD_ENTITLEMENTS: [
            "com.apple.developer.kernel.extended-virtual-addressing",
            "com.apple.developer.kernel.increased-memory-limit",
            "com.apple.security.cs.allow-jit",
        ],
    }
    result: dict[str, dict[str, object]] = {}
    for path, keys in expected.items():
        try:
            values = plistlib.loads(path.read_bytes())
        except Exception as exc:
            fail(f"cannot parse entitlement plist {relative(path)}: {exc}")
        for key in keys:
            if values.get(key) is not True:
                fail(f"required entitlement is missing or false: {relative(path)}:{key}")
        result[relative(path)] = {key: values[key] for key in keys}
    return result


def action_refs(workflow: str) -> list[dict[str, str]]:
    refs = []
    for use in re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, re.M):
        if use.startswith("./"):
            continue
        action, sep, ref = use.rpartition("@")
        if not sep or not re.fullmatch(r"[0-9a-f]{40}", ref):
            fail(f"third-party action is not pinned to a full commit SHA: {use}")
        refs.append({"action": action, "commit": ref})
    return refs


def inventory_tracked_binaries() -> list[dict[str, object]]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    records = []
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        path = ROOT / os.fsdecode(entry)
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as handle:
                magic = handle.read(8)
            suffix = path.suffix.lower()
            recognized = (suffix in {".dll", ".exe", ".a", ".dylib", ".so"}
                          or magic.startswith(b"MZ") or magic.startswith(b"\x7fELF")
                          or magic.startswith(b"!<arch>\n")
                          or magic[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                                           b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
                                           b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                                           b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"})
            if not recognized:
                continue
            records.append({"path": path.relative_to(ROOT).as_posix(),
                            "sha256": sha256(path), "size_bytes": path.stat().st_size,
                            "file_type": "compiled binary"})
    return sorted(records, key=lambda item: str(item["path"]))


def verify_required_checks(workflow: str) -> None:
    required = [
        "tests/host/check-log-upload.py",
        "tests/host/check-feedback.py",
        "tests/host/check-feedback-attach.py",
        "tests/host/check-bcd-perftrace.py",
        "tests/host/check-bcd-help.py",
        "tests/host/check-bcd-screenshot.py",
        "tests/host/check-steam-signin-native.py",
        "tests/host/check-guest-log-secrets.py",
        "tests/host/check-vcruntime-download.py",
    ]
    for check in required:
        if check not in workflow:
            fail(f"required security/privacy check is missing from the workflow: {check}")
        start = workflow.rfind("      - name:", 0, workflow.index(check))
        end = workflow.find("      - name:", workflow.index(check))
        block = workflow[start:end if end >= 0 else len(workflow)]
        if "continue-on-error: true" in block or re.search(r"^\s*if:\s*(?:false|0)\s*$", block, re.M):
            fail(f"required security/privacy check is allowed to fail or disabled: {check}")


def verify_pinned_input_references(lock: dict[str, object]) -> None:
    locations = {
        "FreeType": [WORKFLOW],
        "LLVM": [WORKFLOW],
        "LuaJIT": [ROOT / "build/luajit-x64/build.sh"],
        "MoltenVK": [ROOT / "build/moltenvk-ios/build.sh", ROOT / "build/moltenvk-ios/build-patched.sh"],
        "SPIRV-Cross": [ROOT / "build/moltenvk-ios/build-patched.sh"],
        "DirectXShaderCompiler": [ROOT / "tools/build-dxcompiler.sh"],
        "DXC clang-format host tool": [ROOT / "tools/build-dxcompiler.sh"],
        "d3d8to9": [ROOT / "third-party/d3d8to9/BCD-SOURCE.txt"],
        "cnc-ddraw": [ROOT / "third-party/cnc-ddraw/BCD-SOURCE.txt"],
        "DXMT overlay test base": [ROOT / "tests/host/dxmt_base.py"],
        "FEX overlay test base": [ROOT / "tests/host/fexpatch_eval.py"],
        "BCD historical XtaJIT reference": [ROOT / "tools/build-xtajit64.sh"],
        "Metal Shader Converter mirror anchor": [ROOT / "tools/fetch-msc-pinned.sh"],
    }
    for entry in lock["git_sources"]:
        if entry["path"] in {"FEX", "dxmt", "madeira-dock", "wine"}:
            continue
        candidates = locations.get(entry["name"])
        if not candidates:
            fail(f"no source verifier is configured for pinned dependency {entry['name']}")
        if not any(path.is_file() and entry["commit"] in path.read_text(errors="replace") for path in candidates):
            fail(f"pinned dependency commit is not enforced by its build source: {entry['name']} {entry['commit']}")
    for archive in lock["archives"]:
        paths = archive.get("enforced_by", [])
        if not paths:
            fail(f"archive has no configured integrity verifier: {archive['name']}")
        verifier_text = []
        for relative_path in paths:
            candidate = ROOT / relative_path
            if not candidate.is_file():
                fail(f"archive verifier is missing for {archive['name']}: {relative_path}")
            verifier_text.append(candidate.read_text(errors="replace"))
        if archive["sha256"] not in "\n".join(verifier_text):
            fail(f"archive hash is recorded but not enforced by the build: {archive['name']}")
    requirements_lock = ROOT / "build/mesa-ios/requirements.lock"
    requirements_text = requirements_lock.read_text()
    for package in lock.get("python_wheels", []):
        expected_line = f"{package['name']}=={package['version']}"
        if expected_line not in requirements_text or package["sha256"] not in requirements_text:
            fail(f"Python wheel pin is missing from requirements.lock: {expected_line}")
def preflight(out: Path) -> None:
    lock = json.loads(INPUT_LOCK.read_text())
    workflow = WORKFLOW.read_text()
    head = run("git", "rev-parse", "HEAD")
    if lock["baseline"]["commit"] != BASELINE:
        fail("the recorded v0.1.712 baseline pin changed")
    if run("git", "rev-parse", f"{BASELINE}^{{commit}}") != BASELINE:
        fail("v0.1.712 baseline commit is unavailable")
    if subprocess.run(["git", "merge-base", "--is-ancestor", BASELINE, "HEAD"], cwd=ROOT).returncode:
        fail("HEAD does not descend from the requested v0.1.712 baseline")
    if os.environ.get("GITHUB_REPOSITORY", "").lower() == "thebcd69/bcd-games":
        fail("refusing to run this independent build on the upstream repository")
    if re.search(r"\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*", workflow):
        fail("the IPA workflow references repository secrets; CI must have no Apple ID or store credentials")
    if "CODE_SIGNING_ALLOWED=NO" not in workflow:
        fail("Xcode archive is not explicitly configured without certificate signing")
    if not re.search(r"^\s*runs-on:\s*xcode-27\s*$", workflow, re.M):
        fail("the job must use the xcode-27 macOS runner image")
    if "${{ github.run_id }}" not in workflow or "${{ github.run_attempt }}" not in workflow:
        fail("build caches are not isolated to this workflow run")
    lines = workflow.splitlines()
    for index, line in enumerate(lines):
        if re.search(r"uses:\s*actions/cache/(?:restore|save)@", line):
            end = next((i for i in range(index + 1, len(lines)) if re.match(r"\s{6}- name:", lines[i])), len(lines))
            block = "\n".join(lines[index:end])
            if "key:" not in block or "${{ github.run_id }}" not in block or "${{ github.run_attempt }}" not in block:
                fail(f"compiled-output cache can be restored across workflow runs: {line.strip()}")
            if "restore-keys:" in block:
                fail("cache fallback keys are forbidden in an independent source build")
    actions = action_refs(workflow)
    verify_required_checks(workflow)
    audit = AUDIT.read_text()
    worker = ROOT / "bcd-logs/worker/worker.js"
    if not worker.exists() and ("UNVERIFIED" not in audit or "server-side privacy or security claim" not in audit):
        fail("the missing external diagnostic Worker must be disclosed as unverified in the security audit")
    if not worker.exists():
        tests = [ROOT / f"tests/host/{name}" for name in ("check-log-upload.py", "check-feedback.py", "check-feedback-attach.py", "check-bcd-help.py", "check-bcd-screenshot.py")]
        if not all(path.is_file() and "UNVERIFIED: bcd-logs Worker source is absent" in path.read_text() for path in tests):
            fail("client privacy checks must report the missing Worker source explicitly")
    pull_tool = ROOT / "tools/pull-logs.py"
    if not pull_tool.exists():
        if "operator-side `tools/pull-logs.py` helper" not in audit or "reported as `UNVERIFIED`" not in audit:
            fail("the absent log-pull operator utility must be disclosed as unverified")
        tests = [ROOT / f"tests/host/{name}" for name in ("check-log-upload.py", "check-feedback.py", "check-bcd-help.py", "check-bcd-screenshot.py")]
        if not all(path.is_file() and "UNVERIFIED" in path.read_text() for path in tests):
            fail("host checks must print UNVERIFIED for the absent log-pull operator utility")
    log_facts = ROOT / "tools/log-facts.py"
    if not log_facts.exists():
        perftrace_test = ROOT / "tests/host/check-bcd-perftrace.py"
        if "trace-summary helper is absent" not in audit or not perftrace_test.is_file() or "UNVERIFIED: tools/log-facts.py is absent" not in perftrace_test.read_text():
            fail("the absent trace-summary helper must remain explicitly unverified")
        session_test = ROOT / "tests/host/check-bcd-session-record.py"
        cluster_test = ROOT / "tests/host/check-cluster-logs.py"
        if not session_test.is_file() or "UNVERIFIED: tools/log-facts.py is absent" not in session_test.read_text():
            fail("session recording checks must retain app behavior and disclose the absent operator parser")
        if not cluster_test.is_file() or "UNVERIFIED: tools/log-facts.py is absent" not in cluster_test.read_text():
            fail("log triage checks must disclose the absent operator parser")
    cluster_tool = ROOT / "tools/cluster-logs.py"
    if not cluster_tool.exists():
        cluster_test = ROOT / "tests/host/check-cluster-logs.py"
        if "operator-side `tools/cluster-logs.py` triage program" not in audit or not cluster_test.is_file() or "UNVERIFIED: tools/cluster-logs.py is absent" not in cluster_test.read_text():
            fail("the absent log-triage operator utility must remain explicitly unverified")
    documentation_tests = {
        "docs/ITCH.md": ("check-itch.py",),
        "docs/EA.md": ("check-ea.py",),
        "docs/VULKAN.md": ("check-moltenvk-patched.py", "check-vulkan-wow64.py", "check-kk-lsfg.py", "check-kk-vt-interp.py"),
        "docs/STEAM_DESKTOP.md": ("check-steam-desktop.py",),
        "docs/STEAM_LIBRARY.md": ("check-steam-cm-transport.py",),
        "docs/BINARIES-WOW64.md": ("check-system32-x86-tools.py",),
        "docs/LIBRARY.md": ("check-onboarding.py",),
        "docs/KEYBOARD_MOUSE.md": ("check-hardware-input.py",),
    }
    declared = {item.get("path") for item in lock.get("unavailable_documentation", [])}
    for rel, test_names in documentation_tests.items():
        if (ROOT / rel).exists():
            continue
        if rel not in declared or f"`{rel}`" not in audit:
            fail(f"the absent documentation {rel} must be inventoried in the security audit")
        for name in test_names:
            test = ROOT / "tests/host" / name
            if not test.is_file() or f"UNVERIFIED: {rel} is absent" not in test.read_text():
                fail(f"the {name} documentation-only assertion must be disclosed without suppressing source checks")
    verify_pinned_input_references(lock)

    submodule_status = subprocess.check_output(
        ["git", "submodule", "status", "--recursive"], cwd=ROOT, text=True
    )
    recursive_submodules = []
    for line in submodule_status.splitlines():
        if not line:
            continue
        state, remainder = line[0], line[1:]
        if state != " ":
            fail(f"recursive submodule is uninitialized or not at its gitlink pin: {line}")
        commit, _, path = remainder.strip().partition(" ")
        path = re.sub(r"\s+\([^()]*\)$", "", path)
        if not re.fullmatch(r"[0-9a-f]{40}", commit) or not path:
            fail(f"cannot parse recursive submodule provenance: {line}")
        recursive_submodules.append({"path": path, "commit": commit})
    raw_submodule_sources = run(
        "git", "submodule", "foreach", "--recursive", "--quiet",
        r'''printf '%s\t%s\t%s\n' "$displaypath" "$(git rev-parse HEAD)" "$(git config --get remote.origin.url || true)"'''
    )
    for line in raw_submodule_sources.splitlines():
        path, commit, url = line.split("\t", 2)
        for item in recursive_submodules:
            if item["path"] == path:
                item["url"] = url
                if item["commit"] != commit:
                    fail(f"recursive submodule HEAD differs from its pinned gitlink: {path}")
                break

    for entry in lock["git_sources"]:
        path = entry["path"]
        if path in {"build-out/evidence/msc-origin.json"}:
            continue
        if path in {"FEX", "dxmt", "madeira-dock", "wine"}:
            gitlink = run("git", "ls-tree", "HEAD", path)
            if entry["commit"] not in gitlink:
                fail(f"source lock disagrees with the superproject gitlink: {path}")
            actual = run("git", "-C", path, "rev-parse", "HEAD")
            if actual != entry["commit"]:
                fail(f"submodule is not at its pinned commit: {path} ({actual})")

    tracked_ipas = run("git", "ls-files", "--", "*.ipa")
    if tracked_ipas:
        fail("the source tree contains a tracked IPA; independent builds must start from source only")
    for candidate in ROOT.rglob("*.ipa"):
        if ".git" not in candidate.parts and "build-out" not in candidate.parts:
            fail(f"unexpected IPA already exists before the build: {relative(candidate)}")

    entitlements = verify_entitlements()
    out.mkdir(parents=True, exist_ok=True)
    input_manifest = {
        "baseline": lock["baseline"],
        "source_commit": head,
        "repository": os.environ.get("GITHUB_REPOSITORY", "local-checkout"),
        "submodules": recursive_submodules,
        "tracked_prebuilt_binary_inputs": inventory_tracked_binaries(),
        "entitlements": entitlements,
        "pinned_actions": actions,
        "pinned_external_inputs": lock,
    }
    (out / "prebuild-inputs.json").write_text(json.dumps(input_manifest, indent=2) + "\n")
    print(f"preflight passed: baseline={BASELINE}, actions={len(actions)}, recursive source pins={len(recursive_submodules)}, tracked binaries={len(input_manifest['tracked_prebuilt_binary_inputs'])}")


def checked_environment() -> dict[str, object]:
    try:
        xcode = run("xcodebuild", "-version")
        sdk = run("xcrun", "--sdk", "iphoneos", "--show-sdk-version")
    except (SystemExit, FileNotFoundError) as exc:
        fail(f"final evidence requires the macOS/Xcode runner: {exc}")
    if not sdk.startswith("27."):
        fail(f"expected an iOS 27 SDK, got {sdk}")
    try:
        swift = run("xcrun", "swift", "--version").splitlines()[0]
        clang = run("xcrun", "clang", "--version").splitlines()[0]
        brew = run("brew", "list", "--formula", "--versions")
    except (SystemExit, FileNotFoundError) as exc:
        fail(f"could not record compiler or Homebrew input versions: {exc}")
    formulae = []
    for line in brew.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            formulae.append({"name": parts[0], "versions": parts[1:]})
    return {"xcode": xcode, "iphoneos_sdk": sdk, "swift": swift, "clang": clang,
            "homebrew_formulae": formulae,
            "runner_os": os.environ.get("ImageOS", "macOS"),
            "runner_image_version": os.environ.get("ImageVersion", "recorded by GitHub runner")}


def check_ipa(path: Path, app_name: str) -> None:
    expected_app = f"Payload/{app_name}.app/Info.plist"
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if expected_app not in names:
            fail(f"unexpected or incomplete IPA payload: {path.name}")
        if any(name.endswith("/embedded.mobileprovision") for name in names):
            fail(f"unsigned IPA unexpectedly contains a provisioning profile: {path.name}")
        for name in names:
            if name.startswith("/") or "../" in name or name.startswith("Payload/") is False:
                fail(f"unexpected IPA member path: {name!r}")
        info = plistlib.loads(archive.read(expected_app))
        if not isinstance(info, dict):
            fail(f"invalid app Info.plist inside {path.name}")
        with tempfile.TemporaryDirectory(prefix="bcd-ipa-verify-") as temp_dir:
            archive.extractall(temp_dir)
            app = Path(temp_dir) / "Payload" / f"{app_name}.app"
            verify = subprocess.run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if verify.returncode:
                fail(f"ad-hoc code signature verification failed for {path.name}: {verify.stderr[-2000:]}")
            details = subprocess.run(["codesign", "-d", "--verbose=4", str(app)], text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            signature_details = details.stdout + details.stderr
            if details.returncode or "Signature=adhoc" not in signature_details:
                fail(f"{path.name} does not carry the expected ad-hoc signature")
            if "Authority=" in signature_details or (
                    "TeamIdentifier=" in signature_details and "TeamIdentifier=not set" not in signature_details):
                fail(f"{path.name} unexpectedly names a signing authority or team")
            embedded = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(app)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if embedded.returncode:
                fail(f"could not read signed entitlements from {path.name}: {embedded.stderr.decode(errors='replace')[-2000:]}")
            try:
                values = plistlib.loads(embedded.stdout)
            except Exception as exc:
                fail(f"signed entitlements are invalid in {path.name}: {exc}")
            for key in ("com.apple.developer.kernel.increased-memory-limit",
                        "com.apple.developer.kernel.extended-virtual-addressing",
                        "com.apple.security.cs.allow-jit"):
                if values.get(key) is not True:
                    fail(f"{path.name} signature is missing required entitlement {key}")


def collect_logs(out: Path) -> None:
    log_paths = sorted(p for p in ROOT.glob("*.log") if p.is_file())
    with (out / "build.log").open("w", encoding="utf-8") as combined:
        for path in log_paths:
            combined.write(f"\n===== {path.name} =====\n")
            combined.write(path.read_text(errors="replace"))
            if path.stat().st_size and not path.read_bytes().endswith(b"\n"):
                combined.write("\n")
    (out / "log-manifest.json").write_text(json.dumps([
        {"path": p.name, "sha256": sha256(p), "size_bytes": p.stat().st_size} for p in log_paths
    ], indent=2) + "\n")


def sbom_components(out: Path, input_manifest: dict[str, object], ipa_paths: list[Path],
                    environment: dict[str, object]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    lock = json.loads(INPUT_LOCK.read_text())
    components: list[dict[str, object]] = []
    deps: list[dict[str, object]] = []
    root_ref = f"pkg:github/{os.environ.get('GITHUB_REPOSITORY', 'local/bcd-games')}@{input_manifest['source_commit']}"
    components.append({"type": "application", "name": "BCD (source build)",
                       "version": str(input_manifest["source_commit"]), "bom-ref": root_ref,
                       "purl": root_ref, "externalReferences": [{"type": "vcs", "url": "https://github.com/thebcd69/bcd-games"}]})
    dependency_refs = []
    for entry in lock["git_sources"]:
        if entry["path"] == "build-out/evidence/msc-origin.json":
            continue
        purl = "pkg:github/" + entry["url"].removeprefix("https://github.com/").removesuffix(".git") + "@" + entry["commit"]
        ref = purl + "#" + re.sub(r"[^A-Za-z0-9_.-]", "_", entry["path"])
        components.append({"type": "library", "name": entry["name"], "version": entry["commit"],
                           "bom-ref": ref, "purl": purl,
                           "externalReferences": [{"type": "vcs", "url": entry["url"]}],
                           "properties": [{"name": "source.path", "value": entry["path"]}]})
        dependency_refs.append(ref)
    for submodule in input_manifest["submodules"]:
        source_url = str(submodule.get("url", ""))
        if source_url.startswith("git@github.com:"):
            source_url = "https://github.com/" + source_url.split(":", 1)[1]
        if not source_url.startswith("https://github.com/"):
            fail(f"cannot make a provenance URL for recursive submodule {submodule['path']}: {source_url}")
        repo_name = source_url.removeprefix("https://github.com/").removesuffix(".git")
        purl = f"pkg:github/{repo_name}@{submodule['commit']}"
        ref = purl + "#" + re.sub(r"[^A-Za-z0-9_.-]", "_", str(submodule["path"]))
        components.append({"type": "library", "name": repo_name.split("/")[-1],
                           "version": submodule["commit"], "bom-ref": ref, "purl": purl,
                           "externalReferences": [{"type": "vcs", "url": source_url}],
                           "properties": [{"name": "source.path", "value": submodule["path"]}]})
        dependency_refs.append(ref)
    for archive in lock["archives"]:
        ref = "urn:sha256:" + archive["sha256"]
        components.append({"type": "library", "name": archive["name"], "version": archive["sha256"],
                           "bom-ref": ref, "hashes": [{"alg": "SHA-256", "content": archive["sha256"]}],
                           "externalReferences": [{"type": "distribution", "url": archive["url"]}],
                           "properties": [{"name": "integrity.enforced_by", "value": ", ".join(archive["enforced_by"])}]})
        dependency_refs.append(ref)
    for package in lock.get("python_wheels", []):
        ref = f"pkg:pypi/{package['name']}@{package['version']}"
        components.append({"type": "library", "name": package["name"], "version": package["version"],
                           "bom-ref": ref, "purl": ref,
                           "hashes": [{"alg": "SHA-256", "content": package["sha256"]}],
                           "externalReferences": [{"type": "distribution", "url": "https://pypi.org/project/" + package["name"] + "/" + package["version"] + "/"}]})
        dependency_refs.append(ref)
    for action in input_manifest["pinned_actions"]:
        ref = f"pkg:github/{action['action']}@{action['commit']}"
        components.append({"type": "library", "name": action["action"], "version": action["commit"],
                           "bom-ref": ref, "purl": ref,
                           "externalReferences": [{"type": "vcs", "url": "https://github.com/" + action["action"]}]})
        dependency_refs.append(ref)
    for formula in environment["homebrew_formulae"]:
        for version in formula["versions"]:
            ref = f"pkg:brew/{formula['name']}@{version}"
            components.append({"type": "library", "name": formula["name"], "version": version,
                               "bom-ref": ref, "purl": ref,
                               "externalReferences": [{"type": "distribution",
                                                       "url": f"https://formulae.brew.sh/formula/{formula['name']}"}],
                               "properties": [{"name": "provenance", "value": "version installed on the recorded GitHub macOS runner"}]})
            dependency_refs.append(ref)
    for binary in input_manifest["tracked_prebuilt_binary_inputs"]:
        ref = "urn:sha256:" + str(binary["sha256"])
        components.append({"type": "file", "name": str(binary["path"]), "version": str(input_manifest["source_commit"]),
                           "bom-ref": ref + ":" + str(binary["path"]),
                           "hashes": [{"alg": "SHA-256", "content": str(binary["sha256"])}],
                           "properties": [{"name": "provenance", "value": "tracked binary input at the pinned source commit"}]})
    for ipa in ipa_paths:
        digest = sha256(ipa)
        ref = "urn:sha256:" + digest
        components.append({"type": "file", "name": ipa.name, "version": "0.1.712", "bom-ref": ref,
                           "hashes": [{"alg": "SHA-256", "content": digest}],
                           "properties": [{"name": "build.output", "value": "unsigned IPA"}]})

    # Complete the source inventory for Cargo and MoltenVK's pinned dependency revisions.
    cargo = ROOT / "build/rppairing-ios/Cargo.lock"
    if cargo.is_file():
        try:
            import tomllib
            packages = tomllib.loads(cargo.read_text()).get("package", [])
        except Exception as exc:
            fail(f"cannot parse Cargo.lock for SBOM: {exc}")
        for package in packages:
            checksum = package.get("checksum")
            ref = f"pkg:cargo/{package['name']}@{package['version']}"
            comp: dict[str, object] = {"type": "library", "name": package["name"], "version": package["version"],
                                       "bom-ref": ref, "purl": ref}
            if checksum:
                comp["hashes"] = [{"alg": "SHA-256", "content": checksum}]
            components.append(comp)
            dependency_refs.append(ref)
    for rev_file in sorted(ROOT.glob("toolchains/MoltenVK*/ExternalRevisions/*_repo_revision")):
        commit = rev_file.read_text().strip()
        if re.fullmatch(r"[0-9a-f]{40}", commit):
            ref = f"urn:git-commit:{commit}:{rev_file.relative_to(ROOT).as_posix()}"
            components.append({"type": "library", "name": rev_file.name.removesuffix("_repo_revision"),
                               "version": commit, "bom-ref": ref,
                               "properties": [{"name": "revision-file", "value": rev_file.relative_to(ROOT).as_posix()}]})
            dependency_refs.append(ref)

    deps.append({"ref": root_ref, "dependsOn": dependency_refs})
    return components, deps


def finalize(out: Path, ipa_dir: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    preflight_file = ROOT / "build-evidence/prebuild-inputs.json"
    if not preflight_file.is_file():
        fail("preflight inventory is missing")
    input_manifest = json.loads(preflight_file.read_text())
    sdk = checked_environment()
    build = 712
    ipa_paths = sorted(ipa_dir.glob(f"*-0.1.{build}-unsigned.ipa"))
    expected = {f"Madeira-0.1.{build}-unsigned.ipa", f"Madeira2-0.1.{build}-unsigned.ipa"}
    if {p.name for p in ipa_paths} != expected:
        fail(f"expected both unsigned IPA variants, found {[p.name for p in ipa_paths]}")
    for path in ipa_paths:
        check_ipa(path, "Madeira2" if path.name.startswith("Madeira2-") else "Madeira")

    (ipa_dir / "SHA256SUMS").write_text("".join(f"{sha256(path)}  {path.name}\n" for path in ipa_paths))
    for name in ("Madeira.entitlements", "Sideload.entitlements"):
        (out / name).write_bytes((ROOT / "app/Madeira" / name).read_bytes())
    (out / "JITHelper.entitlements").write_bytes((ROOT / "app/MadeiraJITHelper/JITHelper.entitlements").read_bytes())
    (out / "SECURITY-AUDIT.md").write_text(AUDIT.read_text())
    (out / "prebuild-inputs.json").write_text(preflight_file.read_text())
    (out / "build-environment.json").write_text(json.dumps(sdk, indent=2) + "\n")
    msc = ROOT / "build-out/evidence/msc-origin.json"
    if not msc.is_file():
        fail("verified Metal Shader Converter mirror provenance is missing")
    msc_origin = json.loads(msc.read_text())
    if any(msc_origin.get(key) is not True for key in (
            "mirror_commit_signature_verified_by_github", "apple_code_signature_verified", "baseline_headers_match")):
        fail("Metal Shader Converter provenance is missing required verification results")
    if (out / "msc-origin.json").resolve() != msc.resolve():
        (out / "msc-origin.json").write_bytes(msc.read_bytes())

    current = {r["path"]: r["sha256"] for r in inventory_tracked_binaries()}
    before = {r["path"]: r["sha256"] for r in input_manifest["tracked_prebuilt_binary_inputs"]}
    delta = {"changed": sorted(p for p, digest in before.items() if p in current and current[p] != digest),
             "unchanged": sorted(p for p, digest in before.items() if current.get(p) == digest),
             "removed": sorted(p for p in before if p not in current)}
    (out / "tracked-binary-rebuild-delta.json").write_text(json.dumps(delta, indent=2) + "\n")

    collect_logs(out)
    components, dependencies = sbom_components(out, input_manifest, ipa_paths, sdk)
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "serialNumber": uuid.uuid5(uuid.NAMESPACE_URL, str(input_manifest["source_commit"]) + ":" + str(os.environ.get("GITHUB_RUN_ID", "local"))).urn,
           "metadata": {"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                        "component": {"type": "application", "name": "BCD independent iOS build", "version": "0.1.712"}},
           "components": components, "dependencies": dependencies}
    (out / "SBOM.cdx.json").write_text(json.dumps(bom, indent=2) + "\n")
    provenance = {
        "baseline": input_manifest["baseline"],
        "source_commit": run("git", "rev-parse", "HEAD"),
        "repository": os.environ.get("GITHUB_REPOSITORY", "local-checkout"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "workflow": ".github/workflows/build-ipa.yml",
        "build_environment": sdk,
        "metal_shader_converter": msc_origin,
        "submodules": input_manifest["submodules"],
        "signing": {"certificate": "none", "provisioning_profile": "none", "ipa_seal": "ad-hoc signature only; no Apple ID or team identity"},
        "outputs": [{"name": p.name, "sha256": sha256(p), "size_bytes": p.stat().st_size} for p in ipa_paths],
        "note": "No device execution is performed by this workflow. Tracked PE/native binary inputs are separately inventoried; the rebuild delta shows which were regenerated."
    }
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"evidence finalized: {len(ipa_paths)} IPAs, {len(components)} SBOM components, SDK {sdk['iphoneos_sdk']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("preflight")
    p.add_argument("--out", type=Path, required=True)
    f = sub.add_parser("finalize")
    f.add_argument("--out", type=Path, required=True)
    f.add_argument("--ipa-dir", type=Path, required=True)
    args = parser.parse_args()
    out = args.out if args.out.is_absolute() else ROOT / args.out
    if args.command == "preflight":
        preflight(out)
    else:
        ipa_dir = args.ipa_dir if args.ipa_dir.is_absolute() else ROOT / args.ipa_dir
        finalize(out, ipa_dir)


if __name__ == "__main__":
    main()
