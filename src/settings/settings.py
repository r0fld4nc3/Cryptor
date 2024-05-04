import json
import os
import pathlib
import sys
import platform
from typing import Union
from src.utils.singleton import Singleton
from src.logs.cryptor_logger import create_logger

clog = create_logger("CryptorSettings", 1)

system = platform.system().lower()
if "windows" in system:
    clog.info("Target System Windows")
    program_data_path = os.getenv("LOCALAPPDATA")
    config_folder = pathlib.Path(program_data_path + "\\r0fld4nc3\\Apps\\Cryptor")
elif "linux" in system or "unix" in system:
    clog.info("Target System Linux/Unix")
    program_data_path = pathlib.Path("/usr/local/var/")
    config_folder = pathlib.Path(program_data_path) / "r0fld4nc3" / "Apps" / "Cryptor"
elif "darwin" in system or "mac" in system:
    clog.info("Target System MacOS")
    # Write to user-writable locations, like ~/Applications
    program_data_path = pathlib.Path(pathlib.Path.home() / "Applications")
    config_folder = pathlib.Path(program_data_path) / "r0fld4nc3" / "Apps" / "Cryptor"
else:
    clog.info("Target System Other")
    clog.info(system)
    program_data_path = pathlib.Path.cwd()
    config_folder = pathlib.Path(program_data_path) / r"\r0fld4nc3" / "Apps" / "Cryptor"

clog.info(f"Config folder: {config_folder}")

class Settings(metaclass=Singleton):

    def __init__(self):
        self.settings = {
                "app-version": "",
                "salt-token": "",
        }
        self._config_file_name = "cryptor-settings.json"
        self.config_dir = pathlib.Path(config_folder)
        self.config_file = pathlib.Path(config_folder) / self._config_file_name

    def set_app_version(self, version: str):
        self.settings["app-version"] = version
        self.save_config()

        return self

    def get_app_version(self):
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

    def save_config(self):
        if self.config_dir == '' or not pathlib.Path(self.config_dir).exists():
            os.makedirs(self.config_dir)
            clog.info(f"Generated config folder {self.config_dir}")

        with open(self.config_file, 'w', encoding="utf-8") as config_file:
            config_file.write(json.dumps(self.settings, indent=2))
            clog.info(f"Saved config {self.config_file}")

    def load_config(self):
        if self.config_dir == '' or not pathlib.Path(self.config_dir).exists()\
                or not pathlib.Path(self.config_file).exists():
            clog.debug(f"Config does not exist.")
            return False

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

    def get_config_dir(self) -> pathlib.Path:
        if not self.config_dir or not pathlib.Path(self.config_dir).exists:
            return pathlib.Path(os.path.dirname(sys.executable))

        return self.config_dir

    def clean_save_file(self):
        """
        Removes unused keys from the save file.
        :return: `bool`
        """

        if not self.config_dir or not pathlib.Path(self.config_dir).exists():
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
