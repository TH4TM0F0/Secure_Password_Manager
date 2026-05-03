from pathlib import Path
from src.crypto.elgamal.params import create_elgamal_config_file 
from secrets import randbelow
import subprocess
import json
import os


BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
CONFIG_FILE = BASE_DIR / "data" / "config" / "elgamal_params.json"
KEY_DIR = BASE_DIR / "data" / "keys"


class ElgamalKeyManager:
    def __init__(self, username: str):
        self.__config_file = CONFIG_FILE
        self.__username = username
        self.__key_dir = KEY_DIR
        self.__private_key_dir = KEY_DIR / f"{self.__username}_private_key.json"
        self.__public_key_dir = KEY_DIR / f"{self.__username}_public_key.json"
        self.__p = None
        self.__a = None
        self.__public_key = None
        self.__private_key = None


    @property
    def p(self): 
        return self.__p
    

    @property
    def a(self): 
        return self.__a
    

    @property
    def public_key(self): 
        return self.__public_key
    

    @property
    def private_key(self): 
        return self.__private_key


    def load_params(self):
        if not self.__config_file.exists():
            create_elgamal_config_file()

        with open(self.__config_file, "r") as file:
            params = json.load(file)
            self.__p = params["p"]
            self.__a = params["a"]


    def __save_public_key(self):
        self.__key_dir.mkdir(parents = True, exist_ok = True)
        with open(self.__public_key_dir, "w") as file:
            json.dump({
                "username" : self.__username,   
                "p" : self.__p ,
                "a" : self.__a ,
                "public key" : self.__public_key
            }, file , indent = 4)


    def __save_private_key(self):
        self.__key_dir.mkdir(parents = True, exist_ok = True)
        with open(self.__private_key_dir, "w") as file:
            json.dump({
                "private key" : self.__private_key
            }, file , indent = 4)

        subprocess.run(
            ["icacls", str(self.__private_key_dir), "/inheritance:r", "/grant", f"{os.getlogin()}:(F)"],
            capture_output = True, text = True
        )


    def __generate_public_key(self):
        self.__public_key = pow(self.__a, self.__private_key, self.__p)


    def __generate_private_key(self):
        self.__private_key = randbelow(self.__p - 3) + 2


    def generate_keys(self):
        if self.load_keys():
            return
        self.load_params()
        self.__generate_private_key()
        self.__save_private_key()
        self.__generate_public_key()
        self.__save_public_key()


    def load_keys(self) -> bool:
        priv_path = self.__private_key_dir
        pub_path = self.__public_key_dir
        if not priv_path.exists() or not pub_path.exists():
            return False
        with open(priv_path) as f:
            self.__private_key = json.load(f)["private key"]
        with open(pub_path) as f:
            data = json.load(f)
            self.__public_key = data["public key"]
            self.__p = data["p"]
            self.__a = data["a"]
        return True