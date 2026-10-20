#!/usr/bin/env bash

# Strict parser for benchmark build_info output. The caller passes
# the expected runner kind, format, and clean source revision. Parsed common
# fields and a concise failure reason are returned in checkpoint_build_*.
# A reviewer-created commit of an extracted source archive is a valid expected
# revision. This validates local source/build consistency, not authorship or
# equality with the source revision recorded in a supplied benchmark result.

validate_checkpoint_build_info_metadata() {
  local runner_kind="$1"
  local expected_format="$2"
  local expected_commit="$3"
  local build_info="$4"

  checkpoint_build_commit=''
  checkpoint_build_dirty=''
  checkpoint_build_type=''
  checkpoint_build_acceleration=''
  checkpoint_build_sha256_acceleration=''
  checkpoint_build_compiler=''
  checkpoint_build_validation_error='invalid or duplicate build metadata'

  local info_format=''
  local format_count=0
  local commit_count=0
  local dirty_count=0
  local build_type_count=0
  local acceleration_count=0
  local sha256_acceleration_count=0
  local compiler_count=0
  local architecture_count=0
  local field_backend_count=0
  local vectorization_count=0
  local cpu_target_count=0
  local hexl_count=0
  local fhe_backend_count=0
  local threading_count=0
  local variants_count=0
  local exchange_count=0
  local gkr_claim_transition_count=0
  local gkr_multiplication_count=0
  local fiat_shamir_count=0
  local schedule_policy_count=0
  local quick_repetitions_count=0
  local balanced_repetitions_count=0
  local mulheavy_repetitions_count=0
  local quick_queries_count=0
  local balanced_queries_count=0
  local mulheavy_queries_count=0
  local basefold_log_rate_count=0
  local gate_mle_count=0
  local quick_ciphertext_hash_count=0
  local balanced_ciphertext_hash_count=0
  local mulheavy_ciphertext_hash_count=0
  local balanced_admitted_count=0
  local mulheavy_admitted_count=0
  local campaign_balanced_count=0
  local campaign_mulheavy_count=0
  local campaign_lanes_count=0
  local campaign_balanced=''
  local campaign_mulheavy=''
  local campaign_lanes=''
  local benchmark_variant_count=0
  local benchmark_roles_count=0
  local integrity_count=0
  local switch_policy_count=0
  local target_data_limbs_count=0
  local computation_integrity_count=0
  local computation_delegation_count=0
  local computation_server_count=0
  local payload_execution_count=0
  local payload_worker_threads_count=0
  local packed_variants=''
  local packed_exchange=''
  local gkr_claim_transition=''
  local gkr_multiplication=''
  local fiat_shamir=''
  local packed_schedule_policy=''
  local packed_quick_repetitions=''
  local packed_balanced_repetitions=''
  local packed_mulheavy_repetitions=''
  local packed_quick_queries=''
  local packed_balanced_queries=''
  local packed_mulheavy_queries=''
  local packed_basefold_log_rate=''
  local gate_mle=''
  local packed_quick_ciphertext_hash=''
  local packed_balanced_ciphertext_hash=''
  local packed_mulheavy_ciphertext_hash=''
  local packed_balanced_admitted=''
  local packed_mulheavy_admitted=''
  local benchmark_variant=''
  local integrity=''
  local switch_policy=''
  local target_data_limbs=''
  local field_backend=''
  local architecture=''
  local vectorization=''
  local cpu_target=''
  local hexl=''
  local fhe_backend=''
  local threading=''
  local benchmark_roles=''
  local computation_integrity=''
  local computation_delegation=''
  local computation_server=''
  local payload_execution=''
  local payload_worker_threads=''
  local unknown_line_count=0
  local unknown_keys=''
  local key value
  while IFS='=' read -r key value; do
    case "$key" in
      format)
        format_count="$((format_count + 1))"
        info_format="$value"
        ;;
      environment.git_commit)
        commit_count="$((commit_count + 1))"
        checkpoint_build_commit="$value"
        ;;
      environment.git_dirty)
        dirty_count="$((dirty_count + 1))"
        checkpoint_build_dirty="$value"
        ;;
      environment.build_type)
        build_type_count="$((build_type_count + 1))"
        checkpoint_build_type="$value"
        ;;
      environment.seal_acceleration)
        acceleration_count="$((acceleration_count + 1))"
        checkpoint_build_acceleration="$value"
        ;;
      environment.sha256_acceleration)
        sha256_acceleration_count="$((sha256_acceleration_count + 1))"
        checkpoint_build_sha256_acceleration="$value"
        ;;
      environment.compiler)
        compiler_count="$((compiler_count + 1))"
        checkpoint_build_compiler="$value"
        ;;
      environment.architecture)
        architecture_count="$((architecture_count + 1))"
        architecture="$value"
        ;;
      environment.field_backend)
        field_backend_count="$((field_backend_count + 1))"
        field_backend="$value"
        ;;
      environment.vectorization)
        vectorization_count="$((vectorization_count + 1))"
        vectorization="$value"
        ;;
      environment.cpu_target)
        cpu_target_count="$((cpu_target_count + 1))"
        cpu_target="$value"
        ;;
      environment.hexl)
        hexl_count="$((hexl_count + 1))"
        hexl="$value"
        ;;
      environment.fhe_backend)
        fhe_backend_count="$((fhe_backend_count + 1))"
        fhe_backend="$value"
        ;;
      environment.threading)
        threading_count="$((threading_count + 1))"
        threading="$value"
        ;;
      protocol.variants)
        variants_count="$((variants_count + 1))"
        packed_variants="$value"
        ;;
      protocol.exchange)
        exchange_count="$((exchange_count + 1))"
        packed_exchange="$value"
        ;;
      protocol.gkr_claim_transition)
        gkr_claim_transition_count="$((gkr_claim_transition_count + 1))"
        gkr_claim_transition="$value"
        ;;
      protocol.gkr_multiplication)
        gkr_multiplication_count="$((gkr_multiplication_count + 1))"
        gkr_multiplication="$value"
        ;;
      protocol.fiat_shamir)
        fiat_shamir_count="$((fiat_shamir_count + 1))"
        fiat_shamir="$value"
        ;;
      benchmark.variant)
        benchmark_variant_count="$((benchmark_variant_count + 1))"
        benchmark_variant="$value"
        ;;
      benchmark.roles)
        benchmark_roles_count="$((benchmark_roles_count + 1))"
        benchmark_roles="$value"
        ;;
      protocol.integrity)
        integrity_count="$((integrity_count + 1))"
        integrity="$value"
        ;;
      fhe.switch_policy)
        switch_policy_count="$((switch_policy_count + 1))"
        switch_policy="$value"
        ;;
      fhe.target_data_limbs)
        target_data_limbs_count="$((target_data_limbs_count + 1))"
        target_data_limbs="$value"
        ;;
      computation.integrity)
        computation_integrity_count="$((computation_integrity_count + 1))"
        computation_integrity="$value"
        ;;
      computation.delegation)
        computation_delegation_count="$((computation_delegation_count + 1))"
        computation_delegation="$value"
        ;;
      computation.server)
        computation_server_count="$((computation_server_count + 1))"
        computation_server="$value"
        ;;
      payload.execution)
        payload_execution_count="$((payload_execution_count + 1))"
        payload_execution="$value"
        ;;
      payload.worker_threads)
        payload_worker_threads_count="$((payload_worker_threads_count + 1))"
        payload_worker_threads="$value"
        ;;
      schedule.policy)
        schedule_policy_count="$((schedule_policy_count + 1))"
        packed_schedule_policy="$value"
        ;;
      profile.quick.packing_repetitions)
        quick_repetitions_count="$((quick_repetitions_count + 1))"
        packed_quick_repetitions="$value"
        ;;
      profile.target-balancedLaned.packing_repetitions)
        balanced_repetitions_count="$((balanced_repetitions_count + 1))"
        packed_balanced_repetitions="$value"
        ;;
      profile.target-mulHeavyPyramid.packing_repetitions)
        mulheavy_repetitions_count="$((mulheavy_repetitions_count + 1))"
        packed_mulheavy_repetitions="$value"
        ;;
      profile.quick.basefold_queries)
        quick_queries_count="$((quick_queries_count + 1))"
        packed_quick_queries="$value"
        ;;
      profile.target-balancedLaned.basefold_queries)
        balanced_queries_count="$((balanced_queries_count + 1))"
        packed_balanced_queries="$value"
        ;;
      profile.target-mulHeavyPyramid.basefold_queries)
        mulheavy_queries_count="$((mulheavy_queries_count + 1))"
        packed_mulheavy_queries="$value"
        ;;
      profile.basefold_log_rate)
        basefold_log_rate_count="$((basefold_log_rate_count + 1))"
        packed_basefold_log_rate="$value"
        ;;
      profile.gate_mle)
        gate_mle_count="$((gate_mle_count + 1))"
        gate_mle="$value"
        ;;
      profile.quick.ciphertext_hash)
        quick_ciphertext_hash_count="$((quick_ciphertext_hash_count + 1))"
        packed_quick_ciphertext_hash="$value"
        ;;
      profile.target-balancedLaned.ciphertext_hash)
        balanced_ciphertext_hash_count="$((balanced_ciphertext_hash_count + 1))"
        packed_balanced_ciphertext_hash="$value"
        ;;
      profile.target-mulHeavyPyramid.ciphertext_hash)
        mulheavy_ciphertext_hash_count="$((mulheavy_ciphertext_hash_count + 1))"
        packed_mulheavy_ciphertext_hash="$value"
        ;;
      profile.target-balancedLaned.admitted)
        balanced_admitted_count="$((balanced_admitted_count + 1))"
        packed_balanced_admitted="$value"
        ;;
      profile.target-mulHeavyPyramid.admitted)
        mulheavy_admitted_count="$((mulheavy_admitted_count + 1))"
        packed_mulheavy_admitted="$value"
        ;;
      campaign.target-balancedLaned.variants)
        campaign_balanced_count="$((campaign_balanced_count + 1))"
        campaign_balanced="$value"
        ;;
      campaign.target-mulHeavyPyramid.variants)
        campaign_mulheavy_count="$((campaign_mulheavy_count + 1))"
        campaign_mulheavy="$value"
        ;;
      campaign.laned.lanes)
        campaign_lanes_count="$((campaign_lanes_count + 1))"
        campaign_lanes="$value"
        ;;
      *)
        unknown_line_count="$((unknown_line_count + 1))"
        unknown_keys="${unknown_keys}${unknown_keys:+, }${key:-<empty>}"
        ;;
    esac
  done <<< "$build_info"

  if [[ "$unknown_line_count" -ne 0 ]]; then
    checkpoint_build_validation_error="unexpected build metadata field(s): $unknown_keys"
    return 1
  fi

  if [[ "$format_count" -ne 1 || "$commit_count" -ne 1 ||
        "$dirty_count" -ne 1 || "$build_type_count" -ne 1 ||
        "$info_format" != "$expected_format" ||
        ! "$checkpoint_build_commit" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ||
        "$checkpoint_build_dirty" != false ||
        "$checkpoint_build_type" != Release ]]; then
    return 1
  fi

  if [[ "$runner_kind" == local ]]; then
    if [[ "$acceleration_count" -ne 0 ||
          "$sha256_acceleration_count" -ne 0 ]]; then
      checkpoint_build_validation_error='Local build metadata claims an unused acceleration backend'
      return 1
    fi
  elif [[ "$acceleration_count" -ne 1 ||
          "$sha256_acceleration_count" -ne 1 ||
          "$checkpoint_build_acceleration" != intel-hexl-runtime-dispatch ||
          "$checkpoint_build_sha256_acceleration" != openssl ]]; then
    return 1
  fi

  if [[ "$runner_kind" != local &&
        ( "$compiler_count" -ne 0 || "$architecture_count" -ne 0 ||
          "$field_backend_count" -ne 0 ||
          "$vectorization_count" -ne 0 || "$cpu_target_count" -ne 0 ||
          "$hexl_count" -ne 0 ||
          "$fhe_backend_count" -ne 0 || "$threading_count" -ne 0 ||
          "$benchmark_roles_count" -ne 0 ||
          "$computation_integrity_count" -ne 0 ||
          "$computation_delegation_count" -ne 0 ||
          "$computation_server_count" -ne 0 ||
          "$payload_execution_count" -ne 0 ||
          "$payload_worker_threads_count" -ne 0 ) ]]; then
    checkpoint_build_validation_error='non-Local build metadata contains Local-only fields'
    return 1
  fi

  if [[ "$runner_kind" == base || "$runner_kind" == packed ]]; then
    if [[ "$gkr_claim_transition_count" -ne 1 ||
          "$gkr_claim_transition" != selector-interpolation-v1 ||
          "$gkr_multiplication_count" -ne 1 ||
          "$gkr_multiplication" != gruen-stripped-h0-v1 ]]; then
      checkpoint_build_validation_error='GKR protocol metadata is not exact'
      return 1
    fi
  elif [[ "$gkr_claim_transition_count" -ne 0 ||
          "$gkr_multiplication_count" -ne 0 ]]; then
    checkpoint_build_validation_error='baseline build metadata contains GKR protocol fields'
    return 1
  fi

  if [[ "$runner_kind" == packed ]]; then
    if [[ "$fiat_shamir_count" -ne 1 ||
          "$fiat_shamir" != single-transcript-gkr-then-packing-v1 ]]; then
      checkpoint_build_validation_error='packed Fiat-Shamir metadata is not exact'
      return 1
    fi
  elif [[ "$fiat_shamir_count" -ne 0 ]]; then
    checkpoint_build_validation_error='non-packed build metadata contains a packed Fiat-Shamir field'
    return 1
  fi

  case "$runner_kind" in
    packed)
      if [[ "$campaign_balanced_count" -ne 1 || "$campaign_balanced" != folded,laned ||
            "$campaign_mulheavy_count" -ne 1 || "$campaign_mulheavy" != folded ||
            "$campaign_lanes_count" -ne 1 || "$campaign_lanes" != 1,128,16384 ]]; then
        checkpoint_build_validation_error='packed target campaign metadata is not exact'
        return 1
      fi
      ;;
    base)
      if [[ "$campaign_balanced_count" -ne 1 || "$campaign_balanced" != base ||
            "$campaign_mulheavy_count" -ne 1 || "$campaign_mulheavy" != base ||
            "$campaign_lanes_count" -ne 0 ]]; then
        checkpoint_build_validation_error='Base target campaign metadata is not exact'
        return 1
      fi
      ;;
    *)
      if [[ "$campaign_balanced_count" -ne 0 || "$campaign_mulheavy_count" -ne 0 ||
            "$campaign_lanes_count" -ne 0 ]]; then
        checkpoint_build_validation_error='baseline build metadata contains proof campaign fields'
        return 1
      fi
      ;;
  esac

  case "$runner_kind" in
    packed)
      if [[ "$gate_mle_count" -ne 1 ||
            "$gate_mle" != folded:wide-local-adjoint-foldable,laned:structured-sparse-basefold ||
            "$benchmark_variant_count" -ne 0 ||
            "$integrity_count" -ne 0 ||
            "$switch_policy_count" -ne 0 ||
            "$target_data_limbs_count" -ne 0 ||
            "$variants_count" -ne 1 || "$exchange_count" -ne 1 ||
            "$schedule_policy_count" -ne 1 ||
            "$quick_repetitions_count" -ne 1 ||
            "$balanced_repetitions_count" -ne 1 ||
            "$mulheavy_repetitions_count" -ne 1 ||
            "$quick_queries_count" -ne 1 ||
            "$balanced_queries_count" -ne 1 ||
            "$mulheavy_queries_count" -ne 1 ||
            "$basefold_log_rate_count" -ne 1 ||
            "$quick_ciphertext_hash_count" -ne 1 ||
            "$balanced_ciphertext_hash_count" -ne 1 ||
            "$mulheavy_ciphertext_hash_count" -ne 1 ||
            "$balanced_admitted_count" -ne 1 ||
            "$mulheavy_admitted_count" -ne 1 ||
            "$packed_variants" != folded,laned ||
            "$packed_exchange" != one-request-one-response ||
            "$packed_schedule_policy" != committed-conservative-no-search ||
            "$packed_quick_repetitions" != 4 ||
            "$packed_balanced_repetitions" != 120 ||
            "$packed_mulheavy_repetitions" != 120 ||
            "$packed_quick_queries" != 4 ||
            "$packed_balanced_queries" != 150 ||
            "$packed_mulheavy_queries" != 150 ||
            "$packed_basefold_log_rate" != 3 ||
            "$packed_quick_ciphertext_hash" != simpleCTHash/v2 ||
            "$packed_balanced_ciphertext_hash" != poseidon/v2 ||
            "$packed_mulheavy_ciphertext_hash" != poseidon/v2 ||
            "$packed_balanced_admitted" != true ||
            "$packed_mulheavy_admitted" != true ]]; then
        checkpoint_build_validation_error='packed profile or protocol metadata is not exact'
        return 1
      fi
      ;;
    base)
      if [[ "$gate_mle_count" -ne 1 ||
            "$gate_mle" != wide-local-adjoint-foldable ||
            "$benchmark_variant_count" -ne 0 ||
            "$integrity_count" -ne 0 ||
            "$switch_policy_count" -ne 0 ||
            "$target_data_limbs_count" -ne 0 ||
            "$variants_count" -ne 0 || "$exchange_count" -ne 0 ||
            "$schedule_policy_count" -ne 0 ||
            "$quick_repetitions_count" -ne 0 ||
            "$balanced_repetitions_count" -ne 0 ||
            "$mulheavy_repetitions_count" -ne 0 ||
            "$quick_queries_count" -ne 0 ||
            "$balanced_queries_count" -ne 0 ||
            "$mulheavy_queries_count" -ne 0 ||
            "$basefold_log_rate_count" -ne 0 ||
            "$quick_ciphertext_hash_count" -ne 0 ||
            "$balanced_ciphertext_hash_count" -ne 0 ||
            "$mulheavy_ciphertext_hash_count" -ne 0 ||
            "$balanced_admitted_count" -ne 0 ||
            "$mulheavy_admitted_count" -ne 0 ]]; then
        checkpoint_build_validation_error='Base build metadata contains packed-only fields'
        return 1
      fi
      ;;
    noIntegrity)
      if [[ "$gate_mle_count" -ne 0 ||
            "$benchmark_variant_count" -ne 1 ||
            "$benchmark_variant" != noIntegrity ||
            "$integrity_count" -ne 1 || "$integrity" != none ||
            "$exchange_count" -ne 1 ||
            "$packed_exchange" != one-request-one-response ||
            "$switch_policy_count" -ne 1 ||
            "$switch_policy" != one-after-each-ctct-multiplication-layer ||
            "$target_data_limbs_count" -ne 1 ||
            "$target_data_limbs" != 9 ||
            "$variants_count" -ne 0 ||
            "$schedule_policy_count" -ne 0 ||
            "$quick_repetitions_count" -ne 0 ||
            "$balanced_repetitions_count" -ne 0 ||
            "$mulheavy_repetitions_count" -ne 0 ||
            "$quick_queries_count" -ne 0 ||
            "$balanced_queries_count" -ne 0 ||
            "$mulheavy_queries_count" -ne 0 ||
            "$basefold_log_rate_count" -ne 0 ||
            "$quick_ciphertext_hash_count" -ne 0 ||
            "$balanced_ciphertext_hash_count" -ne 0 ||
            "$mulheavy_ciphertext_hash_count" -ne 0 ||
            "$balanced_admitted_count" -ne 0 ||
            "$mulheavy_admitted_count" -ne 0 ]]; then
        checkpoint_build_validation_error='noIntegrity build metadata is not exact'
        return 1
      fi
      ;;
    local)
      if [[ "$compiler_count" -ne 1 ||
            -z "$checkpoint_build_compiler" ||
            "$architecture_count" -ne 1 ||
            "$architecture" != x86-64 ||
            "$field_backend_count" -ne 1 ||
            "$field_backend" != scalar-fp65537 ||
            "$vectorization_count" -ne 1 ||
            "$vectorization" != enabled ||
            "$cpu_target_count" -ne 1 || "$cpu_target" != native ||
            "$hexl_count" -ne 1 || "$hexl" != not-used ||
            "$fhe_backend_count" -ne 1 || "$fhe_backend" != none ||
            "$threading_count" -ne 1 ||
            "$threading" != single-cpu-process ||
            "$benchmark_variant_count" -ne 1 ||
            "$benchmark_variant" != local ||
            "$benchmark_roles_count" -ne 1 ||
            "$benchmark_roles" != client-only ||
            "$computation_integrity_count" -ne 1 ||
            "$computation_integrity" != not-applicable ||
            "$computation_delegation_count" -ne 1 ||
            "$computation_delegation" != none ||
            "$computation_server_count" -ne 1 ||
            "$computation_server" != none ||
            "$payload_execution_count" -ne 1 ||
            "$payload_execution" != indexed-cross-slot-prefix-then-coordinate-major ||
            "$payload_worker_threads_count" -ne 1 ||
            "$payload_worker_threads" != 1 ||
            "$gate_mle_count" -ne 0 || "$integrity_count" -ne 0 ||
            "$exchange_count" -ne 0 || "$switch_policy_count" -ne 0 ||
            "$target_data_limbs_count" -ne 0 ||
            "$variants_count" -ne 0 ||
            "$schedule_policy_count" -ne 0 ||
            "$quick_repetitions_count" -ne 0 ||
            "$balanced_repetitions_count" -ne 0 ||
            "$mulheavy_repetitions_count" -ne 0 ||
            "$quick_queries_count" -ne 0 ||
            "$balanced_queries_count" -ne 0 ||
            "$mulheavy_queries_count" -ne 0 ||
            "$basefold_log_rate_count" -ne 0 ||
            "$quick_ciphertext_hash_count" -ne 0 ||
            "$balanced_ciphertext_hash_count" -ne 0 ||
            "$mulheavy_ciphertext_hash_count" -ne 0 ||
            "$balanced_admitted_count" -ne 0 ||
            "$mulheavy_admitted_count" -ne 0 ]]; then
        checkpoint_build_validation_error='Local isolation metadata is not exact'
        return 1
      fi
      ;;
    *)
      checkpoint_build_validation_error='unknown checkpoint runner kind'
      return 1
      ;;
  esac

  if [[ "$checkpoint_build_commit" != "$expected_commit" ]]; then
    checkpoint_build_validation_error='executable revision differs from source HEAD'
    return 1
  fi
  checkpoint_build_validation_error=''
  return 0
}
