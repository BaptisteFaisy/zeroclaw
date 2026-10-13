#!/usr/bin/env bash
# Finite, source-bound causal controls in the warmed Linux plugin test job.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(git -C "$script_dir/../.." rev-parse --show-toplevel)
cd -- "$repo_root"
source_path=crates/zeroclaw-plugins/src/host/recovery.rs
host_path=crates/zeroclaw-plugins/src/host.rs
tests_path=crates/zeroclaw-plugins/src/host/recovery_tests.rs
fixed_sha=0fabf7bbbe9dc278ab1e10bfa59ffea7ec947768ee132a0a458e52bb1328d762
host_sha=ebe72c13ace5a5d3fd3f882ac043471e20d5489dff9841202cb7f8981ed28a76
tests_sha=bcb025477bd03307e70032af3d6a20fae2ae6a866ee580d4a5604907a271b0f9

verify_hash() {
    local path=$1 expected=$2 actual
    actual=$(sha256sum -- "$path") || return 1
    actual=${actual%% *}
    if [[ "$actual" != "$expected" ]]; then
        printf 'FATAL: hash mismatch for %s: expected=%s actual=%s\n' "$path" "$expected" "$actual" >&2
        return 1
    fi
}

verify_hash "$source_path" "$fixed_sha"
verify_hash "$host_path" "$host_sha"
verify_hash "$tests_path" "$tests_sha"
git diff --exit-code HEAD -- "$source_path" "$host_path" "$tests_path"
: "${RUNNER_TEMP:?hosted runner scratch is required}"
scratch=$(mktemp -d "$RUNNER_TEMP/plugin-rename-qualification.XXXXXX")
backup="$scratch/fixed-recovery.rs"
cp -- "$source_path" "$backup"
verify_hash "$backup" "$fixed_sha"
chmod 400 -- "$backup"

restore_source() {
    verify_hash "$backup" "$fixed_sha" || return 1
    cp -- "$backup" "$source_path" || return 1
    verify_hash "$source_path" "$fixed_sha" || return 1
    git diff --exit-code HEAD -- "$source_path" || return 1
    printf 'RESTORE:PASS source=%s sha256=%s\n' "$source_path" "$fixed_sha"
}

finish() {
    local status=$?
    trap - EXIT HUP INT TERM
    if ! restore_source; then
        printf 'FATAL: fixed source restoration could not be verified\n' >&2
        status=1
    fi
    printf 'QUALIFICATION:EXIT status=%s scratch=%s\n' "$status" "$scratch"
    exit "$status"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

tests=(
    host::recovery_tests::unsupported_claim_preserves_source_substitution_and_destination_file
    host::recovery_tests::atomic_claim_preserves_source_substitution_and_destination_file
    host::recovery::rename_tests::unsupported_moves_preserve_source_and_each_destination
    host::recovery::rename_tests::ordinary_atomic_move_errors_keep_errno_and_bytes
    host::recovery::rename_tests::unsupported_claim_and_restore_retain_exact_directory_generations
    host::recovery::rename_tests::atomic_claim_refuses_conflicts_then_restores_exact_generation
    host::tests::install_and_recovery_refuse_without_a_no_replace_rename
)
cargo_args=(
    test --locked -p zeroclaw-plugins --no-default-features
    --features plugins-wasm-cranelift --lib --
    --exact --test-threads=1 --color never --format pretty "${tests[@]}"
)

check_results() {
    python3 - "$1" "$2" "$3" "$source_path" "$host_path" "$tests_path" "${tests[@]}" <<'PY'
import collections
import json
from pathlib import Path
import re
import sys

stage, status, logfile, recovery, host, processes, *names = sys.argv[1:]
status = int(status)
raw = Path(logfile).read_text()
fail_indices = {
    "baseline": (0, 2, 4, 6), "fixed": (),
    "unavailable": (0, 2, 4, 6), "atomic": (1, 5), "restored-fixed": (),
}[stage]
expected_failures = {names[i] for i in fail_indices}
expected_status = 101 if expected_failures else 0
sgr = re.compile(r"\x1b\[[0-9;]*m")
expected_footer = "error: test failed, to rerun pass `-p zeroclaw-plugins --lib`"

def require(condition, reason):
    if not condition:
        raise SystemExit(f"FATAL: {stage}: {reason}")

def assertion_line(path, name, needle):
    lines = Path(path).read_text().splitlines()
    declaration = re.compile(rf"^\s*fn {re.escape(name.rsplit('::', 1)[1])}\(")
    starts = [i for i, line in enumerate(lines) if declaration.match(line)]
    require(len(starts) == 1, f"cannot bind source declaration for {name}")
    matches = [i + 1 for i in range(starts[0] + 1, len(lines)) if needle in lines[i]]
    require(bool(matches), f"cannot bind expected assertion for {name}")
    return matches[0]

def validate(text, cargo_status):
    require(len(names) == len(set(names)) == 7, "selection is not seven unique exact names")
    require(cargo_status == expected_status, f"Cargo exit {cargo_status}, expected {expected_status}")
    rows = re.findall(r"(?m)^test (\S+) \.\.\. (ok|FAILED|ignored)\s*$", text)
    counts = collections.Counter(name for name, _ in rows)
    require(set(counts) == set(names) and all(counts[n] == 1 for n in names),
            f"missing, extra or duplicate actual named rows: {dict(counts)}")
    results = dict(rows)
    for name in names:
        expected = "FAILED" if name in expected_failures else "ok"
        require(results[name] == expected, f"{name}: {results[name]}, expected {expected}")
    summaries = re.findall(
        r"(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
        r"(\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [^\n]+$", text)
    require(len(summaries) == 1, "missing or multiple terminal test summaries")
    conclusion, passed, failed, ignored, measured, _ = summaries[0]
    require((conclusion, int(passed), int(failed), int(ignored), int(measured)) ==
            ("FAILED" if expected_failures else "ok", 7 - len(expected_failures),
             len(expected_failures), 0, 0), f"unexpected summary: {summaries[0]}")
    headers = list(re.finditer(r"(?m)^---- (\S+) stdout ----\s*$", text))
    blocks = {}
    for index, header in enumerate(headers):
        stop = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        name = header.group(1)
        require(name not in blocks, f"duplicate failure section for {name}")
        blocks[name] = text[header.end():stop]
    require(set(blocks) == expected_failures, "unexpected or absent named failure sections")
    for name in expected_failures:
        block = blocks[name]
        index = names.index(name)
        if index in (0, 1):
            path = processes
            line = assertion_line(path, name, 'assert_eq!(std::fs::read(&destination).unwrap(),')
            require('assertion `left == right` failed' in block, f"{name}: not a data assertion")
            for label, data in (("left", b"substituted source"), ("right", b"destination sentinel")):
                vector = re.escape(str(list(data)))
                require(re.search(rf"(?m)^\s*{label}:\s*{vector}\s*$", block),
                        f"{name}: missing actual {label} bytes")
        elif index == 2:
            path = recovery
            line = assertion_line(path, name, 'let error = rename_new(dir, "source", dir, destination).unwrap_err();')
            require('called `Result::unwrap_err()` on an `Ok` value: ()' in block,
                    f"{name}: not an unexpectedly successful real move")
        elif index == 4:
            path = recovery
            line = assertion_line(path, name, 'let claim_result = tx.claim(&root, "source");') + 1
            require('claim result: Ok(())' in block, f"{name}: actual successful claim not observed")
        elif index == 5:
            path = recovery
            line = assertion_line(path, name, 'assert!(tx.publish(&root, "source").is_err());')
            require('assertion failed: tx.publish(&root, "source").is_err()' in block,
                    f"{name}: not the destination-conflict assertion")
        elif index == 6:
            path = host
            line = assertion_line(path, name, 'panic!("an unsupported publication must retain the stage:')
            require('an unsupported publication must retain the stage: Ok("plain")' in block,
                    f"{name}: not the observed successful publication")
        else:
            raise SystemExit(f"FATAL: {stage}: no permitted failure signature for {name}")
        require(re.search(rf"{re.escape(path)}:{line}:\d+:", block),
                f"{name}: failure not at intended source assertion {path}:{line}")
    # Cargo owns these lines; libtest output remains unmodified and --color never.
    classified = sgr.sub("", text)
    errors = re.findall(r"(?m)^error(?:\[[A-Z]\d+\])?:[^\n]*$", classified)
    require(errors == ([expected_footer] if expected_failures else []),
            f"unexpected compiler/build/Cargo error lines: {errors}")
    return results

results = validate(raw, status)

def reject(label, altered, altered_status=status):
    try:
        validate(altered, altered_status)
    except SystemExit:
        print(f"ORACLE:REJECT:{stage}:{label}")
    else:
        raise SystemExit(f"FATAL: {stage}: negative oracle accepted {label}")

# These alter accepted text only and do not supply runtime safety-control credit.
first = re.search(r"(?m)^test " + re.escape(names[0]) + r" \.\.\. (?:ok|FAILED)\s*$", raw)
require(first is not None, "missing first row for negative text oracle")
reject("missing-named-row", raw[:first.start()] + raw[first.end():])
reject("duplicate-named-row", raw + "\n" + first.group(0) + "\n")
reject("missing-summary", re.sub(r"(?m)^test result:[^\n]*$", "", raw))
reject("compiler-error", raw + "\nerror[E0308]: mismatched types\n")
reject("colored-compiler-error", raw + "\n\x1b[31merror[E0308]: mismatched types\x1b[0m\n")
reject("setup-exit", raw, 1)
if expected_failures:
    plain = sgr.sub("", raw)
    validate(plain, status)
    colored = plain.replace(expected_footer, "\x1b[31m" + expected_footer + "\x1b[0m")
    validate(colored, status)
    print(f"ORACLE:ACCEPT:{stage}:plain-and-colored-expected-footer")
    reject("wrong-footer", plain.replace(expected_footer, "error: could not compile plugin tests"))
    reject("missing-footer", plain.replace(expected_footer, ""))
    if names[4] in expected_failures:
        require('claim result: Ok(())' in raw, "missing observed claim result for negative oracle")
        reject("unrelated-claim-error", raw.replace('claim result: Ok(())',
               'claim result: Err(Io(PermissionDenied))'))

for name in names:
    print(f"CONTROL:{stage}:{'FAIL' if results[name] == 'FAILED' else 'PASS'}:{name}")
print("STAGE:ACCEPTED " + json.dumps({"stage": stage, "cargo_status": status,
      "passed": 7 - len(expected_failures), "expected_counterfactual_failures": len(expected_failures)}))
PY
}

run_stage() {
    local stage=$1 source_sha=$2 fixture=${3:-} fixture_sha=${4:-} status
    restore_source
    verify_hash "$host_path" "$host_sha"
    verify_hash "$tests_path" "$tests_sha"
    if [[ -n "$fixture" ]]; then
        verify_hash "$fixture" "$fixture_sha"
        git apply --check --include="$source_path" -- "$fixture"
        git apply --include="$source_path" -- "$fixture"
    fi
    verify_hash "$source_path" "$source_sha"
    printf 'STAGE:%s head=%s tree=%s source_sha256=%s\n' "$stage" \
        "$(git rev-parse HEAD)" "$(git rev-parse 'HEAD^{tree}')" "$source_sha"
    printf 'COMMAND:'
    printf ' %q' cargo "${cargo_args[@]}"
    printf '\n'
    set +e
    cargo "${cargo_args[@]}" > "$scratch/$stage.log" 2>&1
    status=$?
    set -e
    cat -- "$scratch/$stage.log"
    printf 'CARGO:STATUS stage=%s status=%s\n' "$stage" "$status"
    check_results "$stage" "$status" "$scratch/$stage.log"
    restore_source
}

run_stage baseline 740377e5335f82f47b3cafc09f7c939da9c2974b5d029dced87a6cce3f38781f \
    scripts/ci/fixtures/plugin-rename-baseline.patch f9fe07237e5fe8515d27e53282f030878aa1a26c1f2a03aa254b1cf20d13244d
run_stage fixed "$fixed_sha"
run_stage unavailable 04436aec924f872011339dcd00de1df03fc869e871da326a89d40f47427dbace \
    scripts/ci/fixtures/plugin-rename-unavailable.patch 51380e55f337a84976398a4c55a6b2deacbb98148afd72be2912bd5a0eb14cd2
run_stage atomic 285ba74bd6ea11d4e44f36189b5c2bf0e6f3ca76a91366921e0d39367ac66403 \
    scripts/ci/fixtures/plugin-rename-atomic.patch d2cb141b2b402d33e143a2d156959d0bf51bdb5cc373baf71cd0d7898b943abc
run_stage restored-fixed "$fixed_sha"
printf 'QUALIFICATION:PASS stages=5 actual_named_observations=35 counterfactual_failures=10\n'
