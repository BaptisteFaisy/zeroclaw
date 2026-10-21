#!/usr/bin/env python3
"""Offline dependency-graph cases for the MQTT-only webpki exception."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock

import webpki_advisory_scope as scope
from webpki_advisory_scope import validate_scope


# These are independent fixture identities, not imports from the policy: changing
# a reviewed checksum or version in the policy must require updating the tests.
LOCK = '''
version = 4
[[package]]
name = "rumqttc"
version = "0.25.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0feff8d882bff0b2fddaf99355a10336d43dd3ed44204f85ece28cf9626ab519"
dependencies = ["rustls-webpki 0.102.8", "tokio-rustls"]
[[package]]
name = "tokio-rustls"
version = "0.26.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b0c85f2c3ef0b1cd58b36682f4b17aaa995f0e5db534d85692b4903abce21f67"
dependencies = ["rustls"]
[[package]]
name = "rustls"
version = "0.23.46"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf"
dependencies = ["rustls-webpki 0.103.16"]
[[package]]
name = "rustls-webpki"
version = "0.102.8"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "64ca1bc8749bd4cf37b5ce386cc146580777b4e8572c7b97baf22c83f444bee9"
[[package]]
name = "rustls-webpki"
version = "0.103.16"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "4443b1b6d39d7c663139942cc4558262562d2c84123bb6282ef177009ca8b281"
'''


class WebpkiScopeTests(unittest.TestCase):
    def setUp(self):
        self.packages = tomllib.loads(LOCK)["package"]

    def package(self, name, version=None):
        return next(
            package for package in self.packages
            if package["name"] == name
            and (version is None or package["version"] == version)
        )

    def test_reviewed_mqtt_graph_is_allowed(self):
        validate_scope(self.packages)

    def test_unrelated_packages_and_patched_verifier_users_are_allowed(self):
        self.packages.append({
            "name": "another-client", "version": "1.0.0",
            "dependencies": ["unrelated 2.0.0", "rustls-webpki 0.103.16"],
        })
        validate_scope(self.packages)

    def test_fully_qualified_dependency_references_are_allowed(self):
        for package in self.packages:
            for index, reference in enumerate(package.get("dependencies", [])):
                target = reference.split()[0]
                version = reference.split()[1] if " " in reference else self.package(target)["version"]
                package["dependencies"][index] = (
                    f"{target} {version} (registry+https://github.com/rust-lang/crates.io-index)"
                )
        validate_scope(self.packages)

    def test_another_legacy_verifier_parent_is_rejected(self):
        self.packages.append({
            "name": "another-client", "version": "1.0.0",
            "dependencies": ["rustls-webpki 0.102.8"],
        })
        with self.assertRaises(ValueError):
            validate_scope(self.packages)

    def test_another_source_qualified_legacy_parent_is_rejected(self):
        self.packages.append({
            "name": "another-client", "version": "1.0.0",
            "dependencies": [
                "rustls-webpki 0.102.8 (registry+https://github.com/rust-lang/crates.io-index)"
            ],
        })
        with self.assertRaises(ValueError):
            validate_scope(self.packages)

    def test_all_reviewed_package_sources_and_checksums_are_enforced(self):
        for index in range(len(self.packages)):
            for field, replacement in (
                ("source", "git+https://example.invalid/unreviewed"),
                ("checksum", "0" * 64),
                ("source", None),
                ("checksum", None),
            ):
                with self.subTest(package=index, field=field, replacement=replacement):
                    packages = copy.deepcopy(self.packages)
                    if replacement is None:
                        del packages[index][field]
                    else:
                        packages[index][field] = replacement
                    with self.assertRaises(ValueError):
                        validate_scope(packages)

    def test_unreviewed_legacy_version_is_rejected(self):
        packages = tomllib.loads(LOCK.replace("0.102.8", "0.102.7"))["package"]
        with self.assertRaises(ValueError):
            validate_scope(packages)

    def test_vulnerable_active_verifier_is_rejected(self):
        packages = tomllib.loads(LOCK.replace("0.103.16", "0.103.15"))["package"]
        with self.assertRaises(ValueError):
            validate_scope(packages)

    def test_unreviewed_future_verifier_requires_policy_review(self):
        packages = tomllib.loads(LOCK.replace("0.103.16", "0.103.17"))["package"]
        with self.assertRaises(ValueError):
            validate_scope(packages)

    def test_removing_legacy_dependency_requires_removing_exception(self):
        self.packages.remove(self.package("rustls-webpki", "0.102.8"))
        self.package("rumqttc")["dependencies"] = ["tokio-rustls"]
        with self.assertRaises(ValueError):
            validate_scope(self.packages)

    def test_duplicate_package_identity_is_rejected(self):
        self.packages.append(copy.deepcopy(self.package("rustls-webpki", "0.102.8")))
        with self.assertRaises(ValueError):
            validate_scope(self.packages)

    def test_mqtt_must_retain_its_rustls_transport(self):
        self.package("rumqttc")["dependencies"].remove("tokio-rustls")
        with self.assertRaises(ValueError):
            validate_scope(self.packages)

    def test_transport_must_retain_rustls(self):
        self.package("tokio-rustls")["dependencies"] = []
        with self.assertRaises(ValueError):
            validate_scope(self.packages)

    def test_rustls_must_retain_the_patched_verifier(self):
        self.package("rustls")["dependencies"] = []
        with self.assertRaises(ValueError):
            validate_scope(self.packages)

    def test_rustls_cannot_select_legacy_verifier(self):
        self.package("rustls")["dependencies"] = ["rustls-webpki 0.102.8"]
        with self.assertRaises(ValueError):
            validate_scope(self.packages)

    def test_ambiguous_unversioned_verifier_is_rejected(self):
        self.package("rumqttc")["dependencies"][0] = "rustls-webpki"
        with self.assertRaises(ValueError):
            validate_scope(self.packages)

    def test_unresolved_verifier_reference_is_rejected(self):
        self.package("rumqttc")["dependencies"][0] = "rustls-webpki 0.100.0"
        with self.assertRaises(ValueError):
            validate_scope(self.packages)

    def test_wrong_source_in_dependency_reference_is_rejected(self):
        self.package("rumqttc")["dependencies"][0] = (
            "rustls-webpki 0.102.8 (git+https://example.invalid/unreviewed)"
        )
        with self.assertRaises(ValueError):
            validate_scope(self.packages)


class SelectedSourceTests(unittest.TestCase):
    """Use genuine checksum-verified archives, never vendor checksum claims."""

    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.fixture.cleanup)
        cls.root = Path(cls.fixture.name)
        cls.home = cls.root / "cargo-home"
        cls.cache = cls.home / "registry/cache/canonical"
        cls.cache.mkdir(parents=True)
        cls.metadata = {"packages": [], "resolve": {"nodes": []}}
        cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
        for package in tomllib.loads(LOCK)["package"]:
            label = f"{package['name']}-{package['version']}"
            archives = list((cargo_home / "registry/cache").glob(f"*/{label}.crate"))
            archive = next((path for path in archives if hashlib.sha256(path.read_bytes()).hexdigest() == package["checksum"]), None)
            if archive is None:
                raise RuntimeError(f"missing verified {label}.crate; run cargo fetch --locked before these tests")
            shutil.copyfile(archive, cls.cache / archive.name)
            selected = cls.root / "selected" / label
            with tarfile.open(archive) as bundle:
                for member in bundle:
                    if member.isfile():
                        destination = selected / Path(member.name).relative_to(label)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(bundle.extractfile(member).read())
            identity = f"{package['name']} {package['version']}"
            cls.metadata["packages"].append({
                "name": package["name"], "version": package["version"],
                "source": package["source"], "id": identity,
                "manifest_path": str(selected / "Cargo.toml"),
            })
            cls.metadata["resolve"]["nodes"].append({"id": identity})

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name)
        self.selected = copy.deepcopy(self.metadata)

    def replace_package_directory(self, name="rumqttc"):
        package = next(package for package in self.selected["packages"] if package["name"] == name)
        original = Path(package["manifest_path"]).parent
        replacement = self.directory / original.name
        shutil.copytree(original, replacement)
        package["manifest_path"] = str(replacement / "Cargo.toml")
        return replacement

    def test_genuine_selected_archives_pass(self):
        self.assertEqual(scope.validate_selected_sources(self.selected, self.home), (5, 581))

    def test_identical_directory_replacement_passes_without_trusting_checksum_map(self):
        replacement = self.replace_package_directory()
        (replacement / ".cargo-checksum.json").write_text('{"package":"untrusted","files":{}}')
        (replacement / ".cargo-ok").write_text("cache marker")
        scope.validate_selected_sources(self.selected, self.home)

    def test_altered_selected_source_fails(self):
        replacement = self.replace_package_directory()
        with (replacement / "src/tls.rs").open("a") as source:
            source.write("\n// different selected verifier source\n")
        with self.assertRaisesRegex(ValueError, "selected source mismatch.*src/tls.rs"):
            scope.validate_selected_sources(self.selected, self.home)

    def test_altered_manifest_fails(self):
        replacement = self.replace_package_directory()
        with (replacement / "Cargo.toml").open("a") as manifest:
            manifest.write("\n# different manifest\n")
        with self.assertRaisesRegex(ValueError, "selected source mismatch.*Cargo.toml"):
            scope.validate_selected_sources(self.selected, self.home)

    def test_altered_existing_build_input_fails(self):
        replacement = self.replace_package_directory("rustls")
        with (replacement / "build.rs").open("a") as source:
            source.write("\n// different build input\n")
        with self.assertRaisesRegex(ValueError, "selected source mismatch.*build.rs"):
            scope.validate_selected_sources(self.selected, self.home)

    def test_added_source_or_build_file_fails(self):
        replacement = self.replace_package_directory()
        for filename in ("src/new_verifier.rs", "build.rs"):
            with self.subTest(filename=filename):
                extra = replacement / filename
                extra.write_text("// added package input; never compiled\n")
                with self.assertRaisesRegex(ValueError, "selected source mismatch.*inventory"):
                    scope.validate_selected_sources(self.selected, self.home)
                extra.unlink()

    def test_missing_canonical_source_fails(self):
        replacement = self.replace_package_directory()
        (replacement / "src/tls.rs").unlink()
        with self.assertRaisesRegex(ValueError, "selected source mismatch.*inventory"):
            scope.validate_selected_sources(self.selected, self.home)

    def test_self_reported_checksums_cannot_authorize_changed_bytes(self):
        replacement = self.replace_package_directory()
        source = replacement / "src/tls.rs"
        source.write_text("// changed source; never compiled\n")
        (replacement / ".cargo-checksum.json").write_text(json.dumps({
            "package": "0feff8d882bff0b2fddaf99355a10336d43dd3ed44204f85ece28cf9626ab519",
            "files": {"src/tls.rs": hashlib.sha256(source.read_bytes()).hexdigest()},
        }))
        with self.assertRaisesRegex(ValueError, "selected source mismatch.*src/tls.rs"):
            scope.validate_selected_sources(self.selected, self.home)

    def test_tampered_canonical_archive_fails_before_source_comparison(self):
        home = self.directory / "cargo-home"
        shutil.copytree(self.home, home)
        archive = home / "registry/cache/canonical/rumqttc-0.25.1.crate"
        data = bytearray(archive.read_bytes())
        data[4] ^= 1  # Alter gzip's timestamp; the archive remains parseable.
        archive.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "canonical archive checksum mismatch.*rumqttc"):
            scope.validate_selected_sources(self.selected, home)

    def test_missing_archive_fails_with_fetch_instruction(self):
        with self.assertRaisesRegex(ValueError, "missing canonical archive.*cargo fetch --locked"):
            scope.validate_selected_sources(self.selected, self.directory / "empty-home")

    def test_selected_symlink_is_not_a_canonical_file(self):
        replacement = self.replace_package_directory()
        source = replacement / "src/tls.rs"
        original = self.root / "selected/rumqttc-0.25.1/src/tls.rs"
        source.unlink()
        source.symlink_to(original)
        with self.assertRaisesRegex(ValueError, "selected source mismatch.*symlink"):
            scope.validate_selected_sources(self.selected, self.home)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO fixture requires Unix")
    def test_nonregular_selected_input_is_rejected_without_reading_it(self):
        replacement = self.replace_package_directory()
        source = replacement / "src/tls.rs"
        source.unlink()
        os.mkfifo(source)
        metadata = self.directory / "metadata.json"
        metadata.write_text(json.dumps(self.selected))
        code = (
            "import sys,json; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
            "import webpki_advisory_scope as scope; "
            "scope.validate_selected_sources(json.loads(Path(sys.argv[2]).read_text()),Path(sys.argv[3]))"
        )
        result = subprocess.run(
            [sys.executable, "-c", code, str(Path(scope.__file__).parent), str(metadata), str(self.home)],
            capture_output=True, text=True, timeout=3,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("selected source mismatch", result.stderr)
        self.assertIn("non-file input", result.stderr)

    def test_metadata_must_resolve_all_reviewed_packages(self):
        self.selected["resolve"]["nodes"].pop()
        with self.assertRaisesRegex(ValueError, "selected resolution"):
            scope.validate_selected_sources(self.selected, self.home)

    def test_metadata_identity_must_match_reviewed_lock(self):
        self.selected["packages"][0]["version"] = "0.25.2"
        with self.assertRaisesRegex(ValueError, "selected package identities"):
            scope.validate_selected_sources(self.selected, self.home)

    def test_metadata_source_must_match_reviewed_lock(self):
        self.selected["packages"][0]["source"] = "git+https://example.invalid/alternate"
        with self.assertRaisesRegex(ValueError, "selected package identities"):
            scope.validate_selected_sources(self.selected, self.home)

    def test_failed_metadata_command_is_not_accepted_even_with_valid_output(self):
        (self.directory / "Cargo.lock").write_text(LOCK)
        result = subprocess.CompletedProcess([], 1, json.dumps(self.selected), "fixture failure")
        with mock.patch.object(scope.subprocess, "run", return_value=result), mock.patch.dict(os.environ, CARGO_HOME=str(self.home)):
            with self.assertRaisesRegex(ValueError, "locked MQTT metadata resolution failed"):
                scope.check_repository(self.directory)

    def test_repository_entrypoint_honors_relative_cargo_home(self):
        (self.directory / "Cargo.lock").write_text(LOCK)
        shutil.copytree(self.home, self.directory / "local-cargo")
        result = subprocess.CompletedProcess([], 0, json.dumps(self.selected), "")
        with mock.patch.object(scope.subprocess, "run", return_value=result) as metadata, mock.patch.dict(os.environ, CARGO_HOME="local-cargo"):
            self.assertEqual(scope.check_repository(self.directory), (5, 581))
        metadata.assert_called_once_with(
            ["cargo", "metadata", "--locked", "--offline", "--format-version", "1", "--features", "channel-mqtt"],
            cwd=self.directory, capture_output=True, text=True,
        )

    def test_full_cli_rejects_locked_cargo_directory_replacement(self):
        # Six metadata-only packages reproduce the original source-replacement
        # gap. Cargo creates the initial lock; every subsequent resolution is
        # locked. No fixture Rust code is compiled or executed.
        root = self.directory / "project"
        (root / "src").mkdir(parents=True)
        (root / ".cargo").mkdir()
        (root / "src/lib.rs").write_text("// metadata-only fixture\n")
        (root / "Cargo.toml").write_text(
            '[package]\nname="source-binding-fixture"\nversion="0.1.0"\nedition="2021"\n'
            '[dependencies]\nrumqttc={version="=0.25.1",optional=true}\n'
            '[features]\nchannel-mqtt=["dep:rumqttc"]\n'
        )
        (root / ".cargo/config.toml").write_text(
            '[source.crates-io]\nreplace-with="fixture"\n'
            '[source.fixture]\ndirectory="vendor"\n'
        )
        packages = tomllib.loads(LOCK)["package"]
        for package in packages:
            folder = root / "vendor" / f"{package['name']}-{package['version']}"
            (folder / "src").mkdir(parents=True)
            manifest = (
                f'[package]\nname="{package["name"]}"\nversion="{package["version"]}"\n'
                'edition="2021"\n[dependencies]\n'
            )
            for reference in package.get("dependencies", []):
                parts = reference.split()
                version = parts[1] if len(parts) > 1 else next(p["version"] for p in packages if p["name"] == parts[0])
                manifest += f'{parts[0]}="={version}"\n'
            (folder / "Cargo.toml").write_text(manifest)
            (folder / "src/lib.rs").write_text("// replacement fixture bytes; never compiled\n")
            (folder / ".cargo-checksum.json").write_text(json.dumps({
                "package": package["checksum"],
                "files": {path.relative_to(folder).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in folder.rglob("*") if path.is_file()},
            }))
        script = root / "scripts/ci/webpki_advisory_scope.py"
        script.parent.mkdir(parents=True)
        shutil.copyfile(scope.__file__, script)
        env = dict(os.environ, CARGO_HOME=str(self.home))
        initial = subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, env=env, capture_output=True, text=True)
        self.assertEqual(initial.returncode, 0, initial.stderr)
        lock = (root / "Cargo.lock").read_bytes()
        validate_scope(tomllib.loads(lock.decode())["package"])
        metadata = subprocess.run([
            "cargo", "metadata", "--locked", "--offline", "--format-version", "1", "--features", "channel-mqtt",
        ], cwd=root, env=env, capture_output=True, text=True)
        self.assertEqual(metadata.returncode, 0, metadata.stderr)
        selected = next(p for p in json.loads(metadata.stdout)["packages"] if p["name"] == "rumqttc")
        self.assertEqual(selected["source"], "registry+https://github.com/rust-lang/crates.io-index")
        self.assertIn("vendor/rumqttc-0.25.1", Path(selected["manifest_path"]).as_posix())
        result = subprocess.run([sys.executable, str(script)], cwd=root, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("selected source mismatch", result.stderr)
        self.assertEqual((root / "Cargo.lock").read_bytes(), lock)


if __name__ == "__main__":
    unittest.main()
