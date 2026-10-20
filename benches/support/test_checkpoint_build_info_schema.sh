#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  printf 'usage: %s VALIDATOR RUNNER_KIND BENCHMARK\n' "$0" >&2
  exit 2
fi
validator="$1"
runner_kind="$2"
benchmark="$3"
case "$runner_kind" in
  local) expected_format=laminate-local-payload-build-info-v1 ;;
  base) expected_format=laminate-base-checkpoint-build-info-v1 ;;
  packed) expected_format=laminate-packed-checkpoint-build-info-v1 ;;
  noIntegrity) expected_format=laminate-no-integrity-build-info-v1 ;;
  *) printf 'unknown runner kind: %s\n' "$runner_kind" >&2; exit 2 ;;
esac
source "$validator"

# Exercise the production validator with the executable's complete schema.
# A development host can have a dirty checkout, a Debug build, or different
# acceleration. Substitute only existing host/build values for this schema
# test. Preserve all keys, key counts, and protocol/profile values. The
# separate build-info tests check the actual source revision and build flags.
emitted="$("$benchmark" build_info)"
qualified=''
expected_commit=''
while IFS= read -r line; do
  if [[ "$line" != *=* ]]; then
    printf '%s emitted malformed build metadata: %s\n' "$runner_kind" "$line" >&2
    exit 1
  fi
  key="${line%%=*}"
  value="${line#*=}"
  case "$key" in
    environment.git_commit) expected_commit="$value" ;;
    environment.git_dirty) value=false ;;
    environment.build_type) value=Release ;;
    environment.seal_acceleration) value=intel-hexl-runtime-dispatch ;;
    environment.sha256_acceleration) value=openssl ;;
    environment.architecture) value=x86-64 ;;
    environment.cpu_target) value=native ;;
    environment.vectorization) value=enabled ;;
  esac
  qualified+="${key}=${value}"$'\n'
done <<< "$emitted"
qualified="${qualified%$'\n'}"

if ! validate_checkpoint_build_info_metadata \
     "$runner_kind" "$expected_format" "$expected_commit" "$qualified"; then
  printf '%s executable schema is incompatible with the runner validator: %s\n' \
    "$runner_kind" "$checkpoint_build_validation_error" >&2
  printf 'Actual executable metadata:\n%s\n' "$emitted" >&2
  exit 1
fi

expect_rejected() {
  local description="$1"
  local candidate="$2"
  local source_commit="${3:-$expected_commit}"
  if validate_checkpoint_build_info_metadata \
       "$runner_kind" "$expected_format" "$source_commit" "$candidate"; then
    printf '%s validator accepted %s\n' "$runner_kind" "$description" >&2
    exit 1
  fi
}

# Every emitted field belongs to the exact schema. Check completeness and
# uniqueness using the executable output, so newly added fields join these
# checks without a second hand-written fixture.
while IFS= read -r field; do
  without_field=''
  while IFS= read -r candidate; do
    if [[ "$candidate" != "$field" ]]; then
      without_field+="$candidate"$'\n'
    fi
  done <<< "$qualified"
  expect_rejected "missing ${field%%=*}" "${without_field%$'\n'}"
  expect_rejected "duplicate ${field%%=*}" "$qualified"$'\n'"$field"
done <<< "$qualified"
expect_rejected 'an unknown field' "$qualified"$'\n''unexpected.schema.field=true'
expect_rejected 'a dirty build' \
  "${qualified/environment.git_dirty=false/environment.git_dirty=true}"
expect_rejected 'a Debug build' \
  "${qualified/environment.build_type=Release/environment.build_type=Debug}"
wrong_commit="0${expected_commit:1}"
if [[ "$wrong_commit" == "$expected_commit" ]]; then
  wrong_commit="1${expected_commit:1}"
fi
expect_rejected 'a source revision mismatch' "$qualified" "$wrong_commit"

if [[ "$runner_kind" == local ]]; then
  expect_rejected 'materialized rotation execution' \
    "${qualified/payload.execution=indexed-cross-slot-prefix-then-coordinate-major/payload.execution=cross-slot-prefix-then-coordinate-major}"
  expect_rejected 'an unknown execution model' \
    "${qualified/payload.execution=indexed-cross-slot-prefix-then-coordinate-major/payload.execution=unknown}"
  expect_rejected 'a non-reference architecture' \
    "${qualified/environment.architecture=x86-64/environment.architecture=non-x86-64}"
  expect_rejected 'a generic CPU target' \
    "${qualified/environment.cpu_target=native/environment.cpu_target=compiler-default}"
else
  expect_rejected 'an unqualified SEAL backend' \
    "${qualified/environment.seal_acceleration=intel-hexl-runtime-dispatch/environment.seal_acceleration=none}"
  expect_rejected 'an unqualified SHA-256 backend' \
    "${qualified/environment.sha256_acceleration=openssl/environment.sha256_acceleration=portable}"
fi
printf '%s executable build-info schema matches the production validator.\n' "$runner_kind"
