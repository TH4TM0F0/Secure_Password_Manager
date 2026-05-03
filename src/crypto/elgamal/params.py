from pathlib import Path
from src.core.params import generate_prime, generate_primitive_root
import json


BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
CONFIG_DIR = BASE_DIR / "data" / "config"
ElGamal_CONFIG_FILE = CONFIG_DIR / "elgamal_params.json"


def create_elgamal_config_file(n_digits: int = 50):
    """Create ElGamal config file with prime p and primitive root a."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        if not ElGamal_CONFIG_FILE.exists():
            with open(ElGamal_CONFIG_FILE, "w") as file:
                p = generate_prime(n_digits)
                a = generate_primitive_root(p)

                if a == -1:
                    raise ValueError("Failed to find a primitive root for ElGamal.")

                json.dump({
                    "p": p, 
                    "a": a
                    }, file, indent=4)
    except Exception as e:
        print(f"Error creating ElGamal config file: {e}")