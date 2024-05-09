import json
import os
import pathlib
import sys
import platform
from typing import Union

from src.utils.singleton import Singleton
from src.logs.cryptor_logger import create_logger
from conf_globals.globals import G_LOG_LEVEL

Path = pathlib.Path
clog = create_logger("CryptorSettings", G_LOG_LEVEL)

system = platform.system().lower()
if "windows" in system:
    clog.info("Target System Windows")
    program_data_path = os.getenv("LOCALAPPDATA")
    config_folder = Path(program_data_path + "\\r0fld4nc3\\Apps\\Cryptor")
elif "linux" in system or "unix" in system:
    clog.info("Target System Linux/Unix")
    program_data_path = Path("/usr/local/var/")
    config_folder = Path(program_data_path) / "r0fld4nc3" / "Apps" / "Cryptor"
elif "darwin" in system or "mac" in system:
    clog.info("Target System MacOS")
    # Write to user-writable locations, like ~/Applications
    program_data_path = Path(Path.home() / "Applications")
    config_folder = Path(program_data_path) / "r0fld4nc3" / "Apps" / "Cryptor"
else:
    clog.info("Target System Other")
    clog.info(system)
    program_data_path = Path.cwd()
    config_folder = Path(program_data_path) / r"\r0fld4nc3" / "Apps" / "Cryptor"

clog.info(f"Config folder: {config_folder}")

class Settings(metaclass=Singleton):

    def __init__(self):
        self.settings = {
            "app-version": "",
            "salt-token": "",
            "check-updates": False,
            "save-on-encrypt": False
        }
        self._config_file_name = "cryptor-settings.json"
        self.config_dir = Path(config_folder)
        self.config_file = Path(config_folder) / self._config_file_name

    def set_app_version(self, version: str):
        self.settings["app-version"] = version
        self.save_config()

        return self

    def get_app_version(self) -> str:
        self.load_config()
        v = self.settings.get("app-version")
        return v

    def set_salt_token(self, token: Union[str, bytes]) -> None:
        if not isinstance(token, str):
            token = token.decode()

        self.settings["salt-token"] = token
        self.save_config()

    def get_salt_token(self) -> bytes:
        self.load_config()
        t = self.settings.get("salt-token", b'').encode()
        return t

    def set_save_file_on_encrypt(self, save_on_encrypt: Union[bool, int]) -> None:
        if not isinstance(save_on_encrypt, bool):
            save_on_encrypt = bool(save_on_encrypt)

        self.settings["save-on-encrypt"] = save_on_encrypt
        self.save_config()

    def get_save_file_on_encrypt(self) -> bool:
        self.load_config()
        v = self.settings.get("save-on-encrypt", False)
        return v

    def set_check_updates(self, check_updates: Union[bool, int]) -> None:
        if not isinstance(check_updates, bool):
            check_updates = bool(check_updates)

        self.settings["check-updates"] = check_updates
        self.save_config()

    def get_check_updates(self) -> bool:
        self.load_config()
        v = self.settings.get("check-updates", False)
        return v

    def save_config(self) -> Path:
        if self.config_dir == '' or not Path(self.config_dir).exists():
            os.makedirs(self.config_dir)
            clog.info(f"Generated config folder {self.config_dir}")

        with open(self.config_file, 'w', encoding="utf-8") as config_file:
            config_file.write(json.dumps(self.settings, indent=2))
            clog.info(f"Saved config {self.config_file}")

        return self.config_file

    def load_config(self) -> dict:
        if self.config_dir == '' or not Path(self.config_dir).exists()\
                or not Path(self.config_file).exists():
            clog.debug(f"Config does not exist.")
            return {}

        self.clean_save_file()

        clog.debug(f"Loading config {self.config_file}")
        config_error = False
        with open(self.config_file, 'r', encoding="utf-8") as config_file:
            try:
                self.settings = json.load(config_file)
            except Exception as e:
                clog.error("An error occurred trying to read config file.")
                clog.error(e)
                config_error = True

        if config_error:
            clog.info("Generating new config file.")
            with open(self.config_file, 'w', encoding="utf-8") as config_file:
                config_file.write(json.dumps(self.settings, indent=2))
        clog.debug(self.settings)

        return self.settings

    def get_config_dir(self) -> Path:
        if not self.config_dir or not Path(self.config_dir).exists:
            return Path(os.path.dirname(sys.executable))

        return self.config_dir

    def clean_save_file(self) -> bool:
        """
        Removes unused keys from the save file.
        :return: `bool`
        """

        if not self.config_dir or not Path(self.config_dir).exists():
            clog.info("No config folder found.")
            return False

        with open(self.config_file, 'r', encoding="utf-8") as config_file:
            settings = dict(json.load(config_file))

        for setting in reversed(list(settings.keys())):
            if setting not in self.settings.keys():
                settings.pop(setting)
                clog.debug(f"Cleared unused settings key: {setting}")

        with open(self.config_file, 'w', encoding="utf-8") as config_file:
            config_file.write(json.dumps(settings, indent=2))
            clog.debug(f"Saved cleaned config: {self.config_file}")

        clog.info("Cleaned-up saved file")

        return True
