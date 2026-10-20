"""Canonical payload geometry checked by the benchmark report renderers."""

PROFILE_GEOMETRY = {
    "quick": dict(depth=6, width=1_024, operations=13_311,
                  workload="diamond", add=1_023, add_plain=6_144,
                  mul=6_144, mul_plain=0, rotate=0),
    "target-balancedLaned": dict(depth=8, width=65_536, operations=1_048_576,
                            workload="balancedLaned", add=471_859,
                            add_plain=52_429, mul=524_288,
                            mul_plain=0, rotate=0),
    "target-mulHeavyPyramid": dict(depth=8, width=434_176, operations=1_048_576,
                            workload="mulHeavyPyramid", add=104_858,
                            add_plain=0, mul=891_290,
                            mul_plain=26_214, rotate=26_214),
}

GATE_KINDS = ("add", "add_plain", "mul", "mul_plain", "rotate")
GATE_LABELS = ("Add", "AddPlain", "Mul", "MulPlain", "Rotate")

def profile_geometry(profile: str, workload: str) -> dict[str, int | str]:
    """Require the workload identity recorded for the selected profile."""
    expected = PROFILE_GEOMETRY.get(profile)
    if expected is not None and expected["workload"] == workload:
        return expected
    raise ValueError(f"{profile} has an unsupported payload workload: {workload}")


def gate_counts(expected: dict[str, int | str]) -> tuple[int, ...]:
    return tuple(int(expected[kind]) for kind in GATE_KINDS)


def gate_summary(counts: tuple[int, ...]) -> str:
    return ", ".join(f"{label} {count:,}"
                     for label, count in zip(GATE_LABELS, counts))


def is_budgeted_workload(workload: str) -> bool:
    """These circuits always report all five operation counts, including zeros."""
    return workload in ("balancedLaned", "mulHeavyPyramid")
