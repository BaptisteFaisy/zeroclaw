#!/usr/bin/env bash
set -euo pipefail

# Before extracting a production packager, exercise the actual current Stable
# run bodies. The pinned Git blob is the baseline, not a second packager here.
archive_test_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
archive_workflow_path=".github/workflows/release-stable-manual.yml"
archive_baseline_blob="6ca82a0ffe0d3973dac3f8b4061403a5cb63e4cc"

fail() {
  echo "archive baseline: $*" >&2
  exit 1
}

actual_blob="$(git -C "$archive_test_root" rev-parse "HEAD:$archive_workflow_path")"
[[ "$actual_blob" == "$archive_baseline_blob" ]] ||
  fail "Stable packaging source differs from the reviewed baseline"
stable_source="$(git -C "$archive_test_root" show "HEAD:$archive_workflow_path")"

case "${RUNNER_OS:-$(uname -s)}" in
  Windows|MINGW*|MSYS*|CYGWIN*)
    package_step="Package (Windows)"
    package_ext="zip"
    main_name="zeroclaw.exe"
    code_name="zerocode.exe"
    relay_name="zerorelay.exe"
    archive_tool="7z"
    ;;
  Linux|Darwin|macOS)
    package_step="Package (Unix)"
    package_ext="tar.gz"
    main_name="zeroclaw"
    code_name="zerocode"
    relay_name="zerorelay"
    archive_tool="tar"
    ;;
  *) fail "unsupported baseline runner" ;;
esac
command -v "$archive_tool" >/dev/null || fail "$archive_tool is required"

baseline_body="$(
  printf '%s\n' "$stable_source" |
    awk -v step="$package_step" '
      $0 == "      - name: " step { found = 1; next }
      found && $0 == "        run: |" { capture = 1; next }
      capture && /^          / { sub(/^          /, ""); print; next }
      capture { exit }
    '
)"
[[ -n "$baseline_body" ]] || fail "pinned packaging run body was not found"

# Only GitHub's three fixed matrix placeholders become fixture constants.
# Shell commands, member selection, copy order and archiver flags stay intact.
fixture_commands="$(
  printf '%s\n' "$baseline_body" |
    sed -e 's/[$][{][{] matrix.target [}][}]/fixture-target/g' \
      -e "s/[$][{][{] matrix.artifact [}][}]/$main_name/g" \
      -e "s/[$][{][{] matrix.ext [}][}]/$package_ext/g"
)"
[[ "$fixture_commands" != *'${{'* ]] || fail "unresolved matrix placeholder"

archive_test_tmp="$(mktemp -d "${TMPDIR:-/tmp}/zeroclaw-archive-baseline.XXXXXX")"
# This directory was created exclusively by this invocation; no repository or
# inherited staging directory is adopted or removed.
trap 'rm -rf -- "$archive_test_tmp"' EXIT
commands_file="$archive_test_tmp/package.sh"
printf '%s\n' "$fixture_commands" > "$commands_file"
case_count=0

seed_fixture() {
  local fixture="$1" companions="$2" omitted="${3:-none}"
  mkdir -p "$fixture/target/fixture-target/release"
  if [[ "$omitted" != main ]]; then
    printf 'dummy main payload\nnot executed\n' > "$fixture/target/fixture-target/release/$main_name"
    chmod 751 "$fixture/target/fixture-target/release/$main_name"
  fi
  if [[ "$companions" == both || "$companions" == code ]]; then
    printf 'dummy code companion\n' > "$fixture/target/fixture-target/release/$code_name"
  fi
  if [[ "$companions" == both || "$companions" == relay ]]; then
    printf 'dummy relay companion\n' > "$fixture/target/fixture-target/release/$relay_name"
  fi
  # A nonmember in the build directory must never enter the product archive.
  printf 'not a release member\n' > "$fixture/target/fixture-target/release/unrelated.txt"
  if [[ "$omitted" != web ]]; then
    mkdir -p "$fixture/web/dist/assets"
    printf '<html>dummy frontend</html>\n' > "$fixture/web/dist/index.html"
    printf 'dummy frontend asset\n' > "$fixture/web/dist/assets/app.js"
    printf 'space-containing asset\n' > "$fixture/web/dist/assets/with space.txt"
    printf 'hidden frontend payload\n' > "$fixture/web/dist/.metadata"
  fi
}

run_baseline() {
  local fixture="$1"
  # GitHub's packaging shell exits on a command failure. Run the unmodified
  # body in a child shell so negative-case conditionals cannot disable that.
  (cd "$fixture" && bash --noprofile --norc -e -o pipefail "$commands_file")
}

positive_case() {
  local companions="$1"
  local fixture="$archive_test_tmp/positive $companions"
  local archive="$fixture/zeroclaw-fixture-target.$package_ext"
  local extracted="$fixture/extracted"
  seed_fixture "$fixture" "$companions"
  if ! run_baseline "$fixture" > "$fixture/package.log" 2>&1; then
    cat "$fixture/package.log" >&2
    fail "packaging failed for optional companions: $companions"
  fi
  [[ -f "$archive" ]] || fail "canonical archive filename was not produced"
  mkdir "$extracted"
  if [[ "$package_ext" == zip ]]; then
    7z x "-o$extracted" "$archive" > "$fixture/extract.log"
  else
    tar -xzf "$archive" -C "$extracted"
  fi

  # Exact expected members are independent assertions over controlled fixture
  # inputs. No filesystem staging or product packaging is implemented here.
  {
    printf '%s\n' "$main_name"
    if [[ "$companions" == both || "$companions" == code ]]; then
      printf '%s\n' "$code_name"
    fi
    if [[ "$companions" == both || "$companions" == relay ]]; then
      printf '%s\n' "$relay_name"
    fi
    printf '%s\n' 'web/dist/index.html' 'web/dist/assets/app.js' \
      'web/dist/assets/with space.txt' 'web/dist/.metadata'
  } | LC_ALL=C sort > "$fixture/expected-members.txt"
  (cd "$extracted" && find . -type f | sed 's#^\./##' | LC_ALL=C sort) > "$fixture/actual-members.txt"
  cmp "$fixture/expected-members.txt" "$fixture/actual-members.txt" ||
    fail "archive member layout differs for companions: $companions"
  cmp "$fixture/target/fixture-target/release/$main_name" "$extracted/$main_name" ||
    fail "main payload changed during packaging/extraction"
  for member in "$code_name" "$relay_name"; do
    if [[ -f "$fixture/target/fixture-target/release/$member" ]]; then
      cmp "$fixture/target/fixture-target/release/$member" "$extracted/$member" ||
        fail "companion payload changed: $member"
    else
      [[ ! -e "$extracted/$member" ]] || fail "absent optional companion was added: $member"
    fi
  done
  for member in index.html assets/app.js 'assets/with space.txt' .metadata; do
    cmp "$fixture/web/dist/$member" "$extracted/web/dist/$member" ||
      fail "frontend payload changed: $member"
  done
  if [[ "$package_ext" == tar.gz ]]; then
    [[ -x "$extracted/$main_name" ]] || fail "Unix main executable mode was lost"
  fi
  case_count=$((case_count + 1))
  echo "PASS archive baseline: $package_step / optional companions $companions"
}

missing_input_case() {
  local omitted="$1"
  local fixture="$archive_test_tmp/missing $omitted"
  seed_fixture "$fixture" both "$omitted"
  if run_baseline "$fixture" > "$fixture/package.log" 2>&1; then
    fail "missing $omitted unexpectedly packaged successfully"
  fi
  [[ ! -e "$fixture/zeroclaw-fixture-target.$package_ext" ]] ||
    fail "missing $omitted produced an archive"
  case_count=$((case_count + 1))
  echo "PASS archive baseline: $package_step / missing $omitted refuses"
}

archiver_failure_case() {
  local fixture="$archive_test_tmp/archiver failure"
  local status
  seed_fixture "$fixture" both
  mkdir "$fixture/failing-bin"
  printf '#!/usr/bin/env bash\nexit 83\n' > "$fixture/failing-bin/$archive_tool"
  chmod +x "$fixture/failing-bin/$archive_tool"
  if PATH="$fixture/failing-bin:$PATH" run_baseline "$fixture" > "$fixture/package.log" 2>&1; then
    fail "an archiver failure unexpectedly succeeded"
  else
    status=$?
  fi
  [[ "$status" -eq 83 ]] || fail "archiver status was not propagated: $status"
  [[ ! -e "$fixture/zeroclaw-fixture-target.$package_ext" ]] ||
    fail "a failing archiver produced an archive"
  case_count=$((case_count + 1))
  echo "PASS archive baseline: $package_step / archiver error propagates"
}

for companions in both none code relay; do
  positive_case "$companions"
done
missing_input_case main
missing_input_case web
archiver_failure_case
[[ "$case_count" -eq 7 ]] || fail "not all seven baseline cases ran"
printf 'PASS archive baseline: %s / %s / 7 cases / source blob %s\n' \
  "$package_step" "$package_ext" "$actual_blob"
