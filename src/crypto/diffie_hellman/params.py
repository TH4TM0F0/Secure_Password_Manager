from pathlib import Path
from src.core.params import generate_prime, generate_primitive_root
import json


BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
CONFIG_DIR = BASE_DIR / "data" / "config"
Diffie_Hellman_CONFIG_FILE = CONFIG_DIR / "diffie_hellman_params.json"


def create_diffie_hellman_config_file(n_digits: int = 50):
    """Create Diffie-Hellman config file with prime q and primitive root alpha."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        if not Diffie_Hellman_CONFIG_FILE.exists():
            with open(Diffie_Hellman_CONFIG_FILE, "w") as file:
                q = generate_prime(n_digits)
                alpha = generate_primitive_root(q)

                if alpha == -1:
                    raise ValueError("Failed to find a primitive root for Diffie-Hellman.")

                json.dump({
                    "q": q, 
                    "alpha": alpha
                    }, file, indent=4)
    except Exception as e:
        print(f"Error creating Diffie-Hellman config file: {e}")