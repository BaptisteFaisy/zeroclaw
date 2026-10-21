#!/usr/bin/env python3
"""Constrain RUSTSEC-2026-0382 to rumqttc's unused legacy error dependency.

The reviewed crates.io rumqttc 0.25.1 archive has exactly one webpki reference
under src/: tls.rs:42 uses webpki::Error. Its connector uses tokio-rustls/rustls,
not the legacy certificate verifier. Pinning the archive checksum preserves
that source review; Cargo verifies registry downloads against Cargo.lock.

All identities intentionally fail closed on updates, including future patched
versions: re-review this exception rather than silently broadening its scope.
Remove the exception and this gate once upstream drops the legacy dependency.
Tracking: https://github.com/zeroclaw-labs/zeroclaw/issues/5869
Upstream: https://github.com/bytebeamio/rumqtt/pull/1037
"""

from pathlib import Path
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


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    with (root / "Cargo.lock").open("rb") as lock_file:
        packages = tomllib.load(lock_file)["package"]
    try:
        validate_scope(packages)
    except ValueError as error:
        raise SystemExit(f"webpki advisory scope: {error}") from error
    print("webpki advisory scope: legacy error type confined to rumqttc; active rustls verifier is patched")


if __name__ == "__main__":
    main()
