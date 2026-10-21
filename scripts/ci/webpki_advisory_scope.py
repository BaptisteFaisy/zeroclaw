#!/usr/bin/env python3
"""Constrain RUSTSEC-2026-0382 to rumqttc's legacy error-type dependency.

The reviewed crates.io rumqttc 0.25.1 archive has exactly one webpki reference
under src/: tls.rs:42 uses webpki::Error. Its connector uses tokio-rustls/rustls,
not the legacy certificate verifier. Error conversion/formatting may be reachable.
The gate binds Cargo's selected package inputs to checksum-verified canonical
archives; lock identities and source-provided checksum maps alone cannot do so.

All identities intentionally fail closed on updates, including future patched
versions: re-review this exception rather than silently broadening its scope.
Remove the exception and this gate once the affected legacy copy is repaired or removed.
Tracking: https://github.com/zeroclaw-labs/zeroclaw/issues/5869
Upstream: https://github.com/bytebeamio/rumqtt/pull/1037
"""

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tomllib


REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
REVIEWED = {
    "rustls-webpki": {
        "0.102.8": "64ca1bc8749bd4cf37b5ce386cc146580777b4e8572c7b97baf22c83f444bee9",
        "0.103.16": "4443b1b6d39d7c663139942cc4558262562d2c84123bb6282ef177009ca8b281",
    },
    "rumqttc": {
        "0.25.1": "0feff8d882bff0b2fddaf99355a10336d43dd3ed44204f85ece28cf9626ab519",
    },
    "tokio-rustls": {
        "0.26.5": "b0c85f2c3ef0b1cd58b36682f4b17aaa995f0e5db534d85692b4903abce21f67",
    },
    "rustls": {
        "0.23.46": "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf",
    },
}


def dependencies(package: dict, name: str, by_name: dict) -> list[dict]:
    """Resolve Cargo.lock's bare, versioned, and source-qualified references."""
    result = []
    for reference in package.get("dependencies", []):
        if reference.split()[0] != name:
            continue
        matches = [
            target for target in by_name.get(name, [])
            if reference in {
                name,
                f"{name} {target['version']}",
                f"{name} {target['version']} ({target.get('source')})",
            }
        ]
        if len(matches) != 1:
            raise ValueError(f"ambiguous or unresolved dependency: {reference}")
        result.append(matches[0])
    return result


def require_edge(parent: dict, target: dict, by_name: dict) -> None:
    if dependencies(parent, target["name"], by_name) != [target]:
        raise ValueError(
            f"reviewed TLS edge changed: {parent['name']} {parent['version']} "
            f"must use {target['name']} {target['version']}"
        )


def validate_scope(packages: list[dict]) -> None:
    """Validate only the lock graph; main also binds the selected source bytes."""
    by_name: dict[str, list[dict]] = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)

    for name, versions in REVIEWED.items():
        actual = sorted(
            (package["version"], package.get("source", ""), package.get("checksum", ""))
            for package in by_name.get(name, [])
        )
        expected = sorted((version, REGISTRY, checksum) for version, checksum in versions.items())
        if actual != expected:
            raise ValueError(
                f"unreviewed {name} package identities; re-review the scoped exception "
                "or remove it if the legacy dependency is gone"
            )

    legacy = next(package for package in by_name["rustls-webpki"] if package["version"] == "0.102.8")
    patched = next(package for package in by_name["rustls-webpki"] if package["version"] == "0.103.16")
    parents = sorted(
        (package["name"], package["version"])
        for package in packages
        if legacy in dependencies(package, "rustls-webpki", by_name)
    )
    if parents != [("rumqttc", "0.25.1")]:
        raise ValueError(f"legacy webpki is not confined to reviewed rumqttc: {parents}")

    mqtt = by_name["rumqttc"][0]
    transport = by_name["tokio-rustls"][0]
    rustls = by_name["rustls"][0]
    require_edge(mqtt, transport, by_name)
    require_edge(transport, rustls, by_name)
    require_edge(rustls, patched, by_name)


def canonical_files(name: str, version: str, cargo_home: Path) -> dict[str, bytes]:
    label = f"{name}-{version}"
    candidates = sorted((cargo_home / "registry/cache").glob(f"*/{label}.crate"))
    if not candidates:
        raise ValueError(
            f"missing canonical archive {label}.crate in {cargo_home}; "
            "run cargo fetch --locked with canonical crates.io sources to populate the cache"
        )
    for archive in candidates:
        data = archive.read_bytes()
        if hashlib.sha256(data).hexdigest() == REVIEWED[name][version]:
            break
    else:
        raise ValueError(f"canonical archive checksum mismatch: {label}.crate")
    # These are the five explicitly reviewed, digest-bound archives, not an
    # arbitrary tar extraction facility. Read their inventory without extracting.
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as bundle:
        return {
            str(PurePosixPath(member.name).relative_to(label)): bundle.extractfile(member).read()
            for member in bundle if member.isfile()
        }


def validate_selected_sources(metadata: dict, cargo_home: Path) -> tuple[int, int]:
    selected = [package for package in metadata["packages"] if package["name"] in REVIEWED]
    identities = sorted((package["name"], package["version"], package["source"]) for package in selected)
    expected = sorted((name, version, REGISTRY) for name, versions in REVIEWED.items() for version in versions)
    if identities != expected:
        raise ValueError("selected package identities do not match the reviewed TLS chain")
    resolved = {node["id"] for node in (metadata.get("resolve") or {}).get("nodes", [])}
    if any(package["id"] not in resolved for package in selected):
        raise ValueError("selected resolution is missing a reviewed TLS package; enable channel-mqtt")

    file_count = 0
    for package in selected:
        label = f"{package['name']}-{package['version']}"
        canonical = canonical_files(package["name"], package["version"], cargo_home)
        directory = Path(package["manifest_path"]).parent
        actual = {}
        for path in directory.rglob("*"):
            relative = path.relative_to(directory).as_posix()
            if path.is_symlink():
                raise ValueError(f"selected source mismatch: {label}: symlink {relative}")
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError(f"selected source mismatch: {label}: non-file input {relative}")
            # Cargo's extraction marker and vendor checksum map are metadata,
            # not canonical package inputs. Neither is used as proof of content.
            if relative not in {".cargo-ok", ".cargo-checksum.json"}:
                actual[relative] = path
        if actual.keys() != canonical.keys():
            raise ValueError(
                f"selected source mismatch: {label}: file inventory differs "
                f"(added={sorted(actual.keys() - canonical.keys())}, "
                f"missing={sorted(canonical.keys() - actual.keys())})"
            )
        for relative, content in canonical.items():
            if actual[relative].read_bytes() != content:
                raise ValueError(f"selected source mismatch: {label}: {relative} differs from canonical archive")
        file_count += len(canonical)
    return len(selected), file_count


def check_repository(root: Path) -> tuple[int, int]:
    with (root / "Cargo.lock").open("rb") as lock_file:
        packages = tomllib.load(lock_file)["package"]
    validate_scope(packages)
    # Fresh metadata honors the invocation's effective Cargo config/CARGO_HOME.
    # --locked forbids re-resolution and --offline avoids implicit downloads;
    # CI fetches locked dependencies before this gate. This does not build Rust.
    command = ["cargo", "metadata", "--locked", "--offline", "--format-version", "1", "--features", "channel-mqtt"]
    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    if result.returncode:
        raise ValueError(
            "locked MQTT metadata resolution failed; run cargo fetch --locked, "
            "then cargo metadata --locked --offline --format-version 1 --features channel-mqtt"
        )
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).expanduser()
    if not cargo_home.is_absolute():
        cargo_home = root / cargo_home
    return validate_selected_sources(json.loads(result.stdout), cargo_home)


def main() -> None:
    try:
        package_count, file_count = check_repository(Path(__file__).resolve().parents[2])
    except (ValueError, OSError, tarfile.TarError) as error:
        raise SystemExit(f"webpki advisory scope: {error}") from error
    print(
        "webpki advisory scope: legacy error type confined to rumqttc; active rustls verifier is patched; "
        f"{package_count} selected packages / {file_count} files match canonical archives"
    )


if __name__ == "__main__":
    main()
