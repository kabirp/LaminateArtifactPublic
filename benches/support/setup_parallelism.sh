#!/usr/bin/env bash

# Select setup workers from the caller's allowed CPU mask before the launcher
# pins itself to the observer. read_physical_core_key is supplied by the runner.
# Results are returned in setup_threads and setup_cpu_list.
select_setup_parallelism() {
  local allowed_list="$1"
  local observer_core="$2"
  local serial_cpu="$3"
  local requested="$4"
  local limit=256
  if [[ "$requested" != auto ]]; then
    if [[ ! "$requested" =~ ^[1-9][0-9]{0,2}$ ]] || ((requested > 256)); then
      printf 'ERROR: LAMINATE_SETUP_THREADS must be an integer in 1..256.\n' >&2
      return 1
    fi
    limit="$requested"
  fi
  if [[ -z "$allowed_list" || "$allowed_list" == *, || "$allowed_list" == ,* ||
        "$allowed_list" == *,,* ]]; then
    printf 'ERROR: setup requires a valid allowed CPU list.\n' >&2
    return 1
  fi
  local -a segments selected
  IFS=',' read -r -a segments <<< "$allowed_list"
  selected=()
  local segment lower upper cpu cpu_core previous=-1 serial_allowed=false
  for segment in "${segments[@]}"; do
    if [[ "$segment" =~ ^(0|[1-9][0-9]{0,5})(-(0|[1-9][0-9]{0,5}))?$ ]]; then
      lower="${BASH_REMATCH[1]}"
      upper="${BASH_REMATCH[3]:-$lower}"
    else
      printf 'ERROR: invalid allowed CPU segment: %s\n' "$segment" >&2
      return 1
    fi
    if ((lower <= previous || upper < lower)); then
      printf 'ERROR: allowed CPU ranges must be ordered and disjoint.\n' >&2
      return 1
    fi
    previous="$upper"
    if ((serial_cpu >= lower && serial_cpu <= upper)); then
      serial_allowed=true
    fi
    for ((cpu=lower; cpu<=upper && ${#selected[@]}<limit; ++cpu)); do
      cpu_core=''
      if ! read_physical_core_key "$cpu" cpu_core; then
        printf 'ERROR: cannot inspect setup CPU %s topology.\n' "$cpu" >&2
        return 1
      fi
      if [[ "$cpu_core" != "$observer_core" ]]; then
        selected+=("$cpu")
      fi
    done
  done
  if [[ "$requested" != auto ]] && ((${#selected[@]} < requested)); then
    printf 'ERROR: requested %s setup workers, but only %s allowed CPUs remain outside the observer core.\n' \
      "$requested" "${#selected[@]}" >&2
    return 1
  fi
  setup_threads="${#selected[@]}"
  if ((setup_threads == 0)); then
    printf 'ERROR: no allowed setup CPU remains outside the observer core.\n' >&2
    return 1
  fi
  if ((setup_threads == 1)); then
    cpu_core=''
    if [[ "$serial_allowed" != true ]] ||
       ! read_physical_core_key "$serial_cpu" cpu_core ||
       [[ "$cpu_core" == "$observer_core" ]]; then
      printf 'ERROR: LAMINATE_SETUP_CPU must be allowed and outside the observer core for serial setup.\n' >&2
      return 1
    fi
    setup_cpu_list="$serial_cpu"
  else
    local IFS=','
    setup_cpu_list="${selected[*]}"
  fi
}
