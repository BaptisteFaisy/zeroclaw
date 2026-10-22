#!/usr/bin/env python3
"""Offline regressions for the release-image certificate gate (OpenSSL 3)."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import check_image_certificates as gate

OPENSSL = os.environ.get("OPENSSL", "openssl")
# Synthetic self-signed CA, valid 2020-2040. Only its public certificate is kept;
# the generated key was discarded. It is never added to production trust stores.
CLEAN = (gate.FIXTURES / "unaffected-root.pem").read_bytes()


def image_tar(files, links=()):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        for name, target in links:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            archive.addfile(info)
    stream.seek(0)
    return stream


class CertificateGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        version = gate.run(OPENSSL, "version").stdout
        if not version.startswith("OpenSSL 3."):
            raise RuntimeError(
                "Tests require OpenSSL 3; set OPENSSL to its executable path"
            )

    def check_files(self, files, links=()):
        bundle, roots = gate.read_trust_files(image_tar(files, links))
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            gate.check_trust(bundle, roots, Path(directory), OPENSSL)

    def test_clean_image_and_alias_pass(self):
        self.check_files(
            {gate.BUNDLE: CLEAN}, [("etc/ssl/cert.pem", "certs/ca-certificates.crt")]
        )

    def test_each_compromised_issuer_is_rejected_as_an_image_regression(self):
        for root in ("aaa-root.pem", "emsign-ecc-g3-root.pem"):
            with (
                self.subTest(root=root),
                self.assertRaisesRegex(
                    ValueError, "must fail for missing trust.*exit 0"
                ),
            ):
                self.check_files(
                    {gate.BUNDLE: CLEAN + (gate.FIXTURES / root).read_bytes()}
                )

    def test_individual_root_cannot_restore_trust_behind_a_clean_bundle(self):
        for directory in gate.CA_DIRECTORIES:
            with (
                self.subTest(directory=directory),
                self.assertRaisesRegex(ValueError, "all packaged CA files: aaa"),
            ):
                self.check_files(
                    {
                        gate.BUNDLE: CLEAN,
                        directory + "restored.crt": (
                            gate.FIXTURES / "aaa-root.pem"
                        ).read_bytes(),
                    }
                )

    def test_missing_empty_and_malformed_bundles_fail(self):
        for files in (
            {},
            {gate.BUNDLE: b""},
            {gate.BUNDLE: b"-----BEGIN CERTIFICATE-----\ninvalid"},
        ):
            with self.subTest(files=files), self.assertRaises(ValueError):
                self.check_files(files)

    def test_invalid_der_and_unsupported_trusted_pem_fail(self):
        for data in (
            b"-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n",
            CLEAN.replace(b"CERTIFICATE", b"TRUSTED CERTIFICATE"),
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.check_files({gate.BUNDLE: data})

    def test_missing_bundle_cannot_follow_a_host_symlink(self):
        with self.assertRaisesRegex(ValueError, "missing or empty"):
            self.check_files({}, [(gate.BUNDLE, "/etc/ssl/cert.pem")])

    def test_unrelated_application_certificates_are_not_trust_anchors(self):
        self.check_files(
            {
                gate.BUNDLE: CLEAN,
                "opt/app/example.pem": (gate.FIXTURES / "aaa-root.pem").read_bytes(),
            }
        )

    def test_expired_fixture_does_not_count_as_distrust(self):
        with (
            patch.object(gate, "VERIFY_TIME", "1"),
            self.assertRaisesRegex(ValueError, "fixture control failed"),
        ):
            self.check_files({gate.BUNDLE: CLEAN})

    def test_host_ca_settings_cannot_change_the_result(self):
        with patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": str(gate.FIXTURES / "aaa-root.pem"),
                "SSL_CERT_DIR": str(gate.FIXTURES),
            },
        ):
            self.check_files({gate.BUNDLE: CLEAN})

    def test_verifier_tool_failure_is_not_a_certificate_rejection(self):
        real_verify = gate.verify

        def failing_verifier(openssl, trusted, leaf, issuer=None):
            if trusted.name == "trusted.pem":
                return subprocess.CompletedProcess([], 1, "", "tool failed")
            return real_verify(openssl, trusted, leaf, issuer)

        with (
            patch.object(gate, "verify", side_effect=failing_verifier),
            self.assertRaisesRegex(ValueError, "exit 1"),
        ):
            self.check_files({gate.BUNDLE: CLEAN})

    def test_every_requested_platform_is_checked(self):
        with (
            patch.object(
                sys,
                "argv",
                ["gate", "local:image", "--platforms", "linux/amd64,linux/arm64"],
            ),
            patch.object(gate, "check_image") as check,
        ):
            gate.main()
        self.assertEqual(
            [call.args[1] for call in check.call_args_list],
            ["linux/amd64", "linux/arm64"],
        )

    def test_pull_requires_digest_and_platforms_cannot_be_empty(self):
        for arguments in (
            ["image:latest", "--pull", "--platforms", "linux/amd64"],
            ["local:image", "--platforms", ""],
            ["local:image", "--platforms", "linux/amd64,"],
        ):
            with (
                self.subTest(arguments=arguments),
                contextlib.redirect_stderr(io.StringIO()),
                patch.object(sys, "argv", ["gate"] + arguments),
                self.assertRaises(SystemExit) as error,
            ):
                gate.main()
            self.assertNotEqual(error.exception.code, 0)


class DockerBoundaryTests(unittest.TestCase):
    """Exercise the real CLI and OpenSSL; fake only the Docker service boundary."""

    def run_cli(self, bundle, *, wrong_platform=False, export_failure=False):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "image.tar").write_bytes(
                image_tar({gate.BUNDLE: bundle}).getvalue()
            )
            docker = directory / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                + """
import json
import os
from pathlib import Path
import sys
root = Path(os.environ["FAKE_DOCKER"])
args = sys.argv[1:]
with (root / "calls.jsonl").open("a") as calls:
    calls.write(json.dumps(args) + "\\n")
if args[0] == "pull":
    pass
elif args[0] == "create":
    (root / "platform").write_text(args[args.index("--platform") + 1])
    print("test-container")
elif args[0] == "inspect":
    print("sha256:" + "1" * 64)
elif args[:2] == ["image", "inspect"]:
    print("linux/wrong" if os.environ["WRONG_PLATFORM"] == "1" else (root / "platform").read_text())
elif args[0] == "export":
    sys.stdout.buffer.write((root / "image.tar").read_bytes())
    sys.exit(int(os.environ["EXPORT_FAILURE"]))
elif args[0] != "rm":
    sys.exit("unexpected Docker command")
"""
            )
            docker.chmod(0o700)
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(gate.__file__)),
                    "registry.invalid/image@sha256:" + "2" * 64,
                    "--pull",
                    "--platforms",
                    "linux/amd64,linux/arm64",
                ],
                check=False,
                env={
                    **os.environ,
                    "PATH": str(directory) + os.pathsep + os.environ["PATH"],
                    "OPENSSL": OPENSSL,
                    "FAKE_DOCKER": str(directory),
                    "WRONG_PLATFORM": str(int(wrong_platform)),
                    "EXPORT_FAILURE": str(int(export_failure)),
                },
                capture_output=True,
                text=True,
                timeout=30,
            )
            calls = [
                json.loads(line)
                for line in (directory / "calls.jsonl").read_text().splitlines()
            ]
            return result, calls

    def test_cli_checks_both_platforms_without_starting_containers(self):
        result, calls = self.run_cli(CLEAN)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("PASS unaffected shipped trust anchor"), 2)
        self.assertEqual(sum(call[0] == "rm" for call in calls), 2)
        for create in (call for call in calls if call[0] == "create"):
            self.assertIn("--pull=never", create)
            self.assertIn("--network=none", create)
        self.assertFalse(any(call[0] in ("run", "start", "exec") for call in calls))

    def test_cli_fails_and_removes_its_container_on_bad_trust(self):
        result, calls = self.run_cli(
            CLEAN + (gate.FIXTURES / "aaa-root.pem").read_bytes()
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must fail for missing trust", result.stderr)
        self.assertEqual(calls[-1], ["rm", "test-container"])

    def test_wrong_platform_and_export_errors_fail_and_clean_up(self):
        for option in ("wrong_platform", "export_failure"):
            with self.subTest(option=option):
                result, calls = self.run_cli(CLEAN, **{option: True})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls[-1], ["rm", "test-container"])


if __name__ == "__main__":
    unittest.main()
