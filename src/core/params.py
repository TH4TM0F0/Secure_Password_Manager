from sympy import randprime, factorint


def generate_prime(n_digits: int = 50) -> int:
    """Generate a large prime with exactly n_digits decimal digits."""
    lower_bound = 10 ** (n_digits - 1)
    upper_bound = 10 ** n_digits - 1
    return randprime(lower_bound, upper_bound)


def generate_primitive_root(q: int) -> int:
    """Find a primitive root modulo q using factorization of q-1."""
    phi_q = q - 1
    factors = factorint(phi_q)

    for a in range(2, 100000):
        if all(pow(a, (q - 1) // p, q) != 1 for p in factors):
            return a
    return -1