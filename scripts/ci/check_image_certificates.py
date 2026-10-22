#!/usr/bin/env python3
"""Check the CA files shipped in an image without executing its binaries.

Requires Docker and OpenSSL 3. Release callers pass the build's immutable digest
and all of its platforms; PR callers pass the locally loaded image. Certificates
come from the final filesystem, including individual roots that could otherwise
restore trust after a bundle-only fix. No archive paths are extracted to disk.
"""

import argparse
import base64
import hashlib
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

FIXTURES = (
    Path(__file__).resolve().parents[2] / "crates/zeroclaw-tls/tests/fixtures/emudhra"
)
BUNDLE = "etc/ssl/certs/ca-certificates.crt"
CA_DIRECTORIES = (
    "etc/ssl/",
    "usr/share/ca-certificates/",
    "usr/local/share/ca-certificates/",
)
PEM = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----"
)
# Inside the shared neutral leaf's validity interval, as in emudhra_distrust.rs.
VERIFY_TIME = "1792584000"
ISSUERS = {"emsign": "emsign-ecc-g3-root.pem", "aaa": "aaa-root.pem"}


def run(*command):
    return subprocess.run(
        command, check=True, capture_output=True, text=True, timeout=300
    )


def certificates(data):
    if b"-----BEGIN TRUSTED CERTIFICATE-----" in data:
        raise ValueError("unsupported trusted-certificate PEM in image trust store")
    matches = list(PEM.finditer(data))
    if len(matches) != data.count(b"-----BEGIN CERTIFICATE-----"):
        raise ValueError("malformed PEM certificate")
    result = {}
    for match in matches:
        der = base64.b64decode(re.sub(rb"\s", b"", match[1]), validate=True)
        result[hashlib.sha256(der).digest()] = match[0] + b"\n"
    return result


def read_trust_files(stream):
    """Read only regular certificate files; never follow image symlinks on host."""
    bundle = None
    roots = {}
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for member in archive:
            name = member.name.removeprefix("./")
            if not name.startswith(CA_DIRECTORIES) or not member.isfile():
                continue
            if member.size > 16 * 1024 * 1024:
                raise ValueError(f"oversized trust-store file: {name}")
            data = archive.extractfile(member).read()
            found = certificates(data)
            roots.update(found)
            if name == BUNDLE:
                bundle = data
    # Every supported release image ships this regular bundle. A layout change
    # must update this check explicitly instead of silently testing no roots.
    if bundle is None or not certificates(bundle):
        raise ValueError(f"missing or empty image CA bundle: /{BUNDLE}")
    return bundle, b"".join(roots.values())


def verify(openssl, trusted, leaf, issuer=None):
    command = [
        openssl,
        "verify",
        "-no-CAfile",
        "-no-CApath",
        "-no-CAstore",
        "-trusted",
        str(trusted),
        "-attime",
        VERIFY_TIME,
    ]
    if issuer:
        command += [
            "-purpose",
            "sslserver",
            "-verify_hostname",
            "host.invalid",
            "-untrusted",
            str(FIXTURES / f"{issuer}-issuer-chain.pem"),
        ]
    command.append(str(leaf))
    return subprocess.run(
        command, check=False, capture_output=True, text=True, timeout=30
    )


def check_trust(bundle, roots, directory, openssl):
    leaf = FIXTURES / "host-invalid-leaf.pem"
    # Positive controls prove that both incident chains are otherwise valid at
    # the frozen time. Expiry, hostname/signature errors, or a broken OpenSSL
    # invocation must never turn a rejection into a passing security test.
    for issuer, root in ISSUERS.items():
        result = verify(openssl, FIXTURES / root, leaf, issuer)
        if result.returncode:
            raise ValueError(
                f"{issuer} fixture control failed: {result.stdout}{result.stderr}"
            )

    shipped = directory / "bundle.pem"
    shipped.write_bytes(bundle)
    # Require a usable, unaffected anchor from the actual image. An empty or
    # indiscriminately broken trust store is not a successful remediation.
    control = directory / "control.pem"
    for pem in certificates(bundle).values():
        control.write_bytes(pem)
        if verify(openssl, shipped, control).returncode == 0:
            break
    else:
        raise ValueError("no shipped trust anchor verifies at the fixture time")

    for label, data in (("bundle", bundle), ("all packaged CA files", roots)):
        trusted = directory / "trusted.pem"
        trusted.write_bytes(data)
        for issuer in ISSUERS:
            result = verify(openssl, trusted, leaf, issuer)
            errors = re.findall(r"error (\d+) at \d+ depth lookup", result.stderr)
            # OpenSSL reports untrusted self-signed chain / missing issuer.
            # Accept only trust-path failures, never expiry or parse failures.
            if (
                result.returncode != 2
                or not errors
                or not set(errors) <= {"19", "20", "21"}
            ):
                raise ValueError(
                    f"{label}: {issuer} must fail for missing trust "
                    f"(exit {result.returncode}): {result.stdout}{result.stderr}"
                )
            print(f"PASS {label}: rejected {issuer} chain (OpenSSL {','.join(errors)})")
    print("PASS unaffected shipped trust anchor")


def check_image(image, platform, pull, openssl):
    if pull:
        run("docker", "pull", "--platform", platform, image)
    container = run(
        "docker",
        "create",
        "--platform",
        platform,
        "--pull=never",
        "--network=none",
        "--entrypoint",
        "/__certificate_check__",
        image,
    ).stdout.strip()
    try:
        image_id = run(
            "docker", "inspect", "--format={{.Image}}", container
        ).stdout.strip()
        actual_platform = run(
            "docker",
            "image",
            "inspect",
            "--format={{.Os}}/{{.Architecture}}{{if .Variant}}/{{.Variant}}{{end}}",
            image_id,
        ).stdout.strip()
        if actual_platform.split("/")[: len(platform.split("/"))] != platform.split(
            "/"
        ):
            raise ValueError(f"requested {platform}, but image is {actual_platform}")
        print(f"Checking {image} ({platform}, {image_id})", flush=True)
        with tempfile.TemporaryDirectory(prefix="image-certificates-") as temporary:
            directory = Path(temporary)
            # Stream the merged filesystem, including roots outside /etc/ssl.
            # No container starts and no QEMU or in-image shell is required.
            with (
                tempfile.TemporaryFile() as errors,
                subprocess.Popen(
                    ["docker", "export", container],
                    stdout=subprocess.PIPE,
                    stderr=errors,
                ) as export,
            ):
                try:
                    bundle, roots = read_trust_files(export.stdout)
                    # tarfile stops at the end marker before consuming archive
                    # padding. Drain it so a valid export cannot hit SIGPIPE.
                    while export.stdout.read(1024 * 1024):
                        pass
                finally:
                    export.stdout.close()
                if export.wait(timeout=300):
                    errors.seek(0)
                    raise ValueError(f"docker export failed: {errors.read().decode()}")
            check_trust(bundle, roots, directory, openssl)
    finally:
        run("docker", "rm", container)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument(
        "--platforms", required=True, help="comma-separated build platforms"
    )
    parser.add_argument(
        "--pull", action="store_true", help="pull an immutable registry digest"
    )
    args = parser.parse_args()
    if args.pull and not re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", args.image):
        parser.error("--pull requires an immutable image@sha256:digest")
    platforms = args.platforms.split(",")
    if any(not re.fullmatch(r"linux/[a-z0-9_]+(?:/[a-z0-9]+)?", p) for p in platforms):
        parser.error("expected nonempty comma-separated Linux platforms")
    openssl = os.environ.get("OPENSSL", "openssl")
    if not run(openssl, "version").stdout.startswith("OpenSSL 3."):
        parser.error("OpenSSL 3 is required (set OPENSSL to its executable path)")
    for platform in platforms:
        check_image(args.image, platform, args.pull, openssl)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(
            f"image certificate check failed: {error}\n{error.stdout}{error.stderr}"
        )
    except (ValueError, OSError, tarfile.TarError, subprocess.TimeoutExpired) as error:
        sys.exit(f"image certificate check failed: {error}")
