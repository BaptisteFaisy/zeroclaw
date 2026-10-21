#!/usr/bin/env python3
"""Offline dependency-graph cases for the MQTT-only webpki exception."""

import copy
import tomllib
import unittest

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


if __name__ == "__main__":
    unittest.main()
