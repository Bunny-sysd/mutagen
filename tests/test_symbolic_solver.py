from mutagen.symbolic_solver import (
    extract_comparison_constraints,
    generate_constraint_seeds,
    solve_and_inject_seeds,
)


def test_extract_comparison_constraints():
    code = """
    if (magic == 0xDEADBEEF) {
        if (strcmp(buf, "ADMIN_SECRET") == 0) {
            return 1;
        }
    }
    """
    constraints = extract_comparison_constraints(code)
    assert 0xDEADBEEF in constraints["magic_hex"]
    assert "ADMIN_SECRET" in constraints["strings"]

def test_generate_constraint_seeds():
    constraints = {
        "magic_hex": [0xDEADBEEF],
        "strings": ["SECRET"],
        "integers": [512],
    }
    seeds = generate_constraint_seeds(constraints)
    assert any(b"SECRET" in s for s in seeds)
    assert len(seeds) > 0

def test_solve_and_inject_seeds():
    code = 'if (strcmp(buf, "TOKEN123") == 0) {}'
    initial_seeds = [b"A" * 10]
    updated = solve_and_inject_seeds(code, initial_seeds)
    assert len(updated) > len(initial_seeds)
    assert any(b"TOKEN123" in s for s in updated)
