import json
import os
import pathlib
import sys
from typing import Union

from conf_globals.globals import config_folder
from src.utils import Singleton
from src.logs import create_logger
from conf_globals.globals import G_LOG_LEVEL

Path = pathlib.Path

log = create_logger("CryptorSettings", G_LOG_LEVEL)

class Settings(metaclass=Singleton):

    def __init__(self):
        self.settings = {
            "app-version": "",
            "salt-token": "",
            "check-updates": False,
            "save-on-encrypt": False,
            "last-checked-update": 0, # int timestamp
            "theme": ""
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

    def set_check_for_updates(self, check_updates: Union[bool, int]) -> None:
        if not isinstance(check_updates, bool):
            check_updates = bool(check_updates)

        self.settings["check-updates"] = check_updates
        self.save_config()

    def get_check_for_updates(self) -> bool:
        self.load_config()
        v = self.settings.get("check-updates", False)
        return v

    def set_last_checked_update(self, last_checked: int) -> None:
        self.settings["last-checked-update"] = int(last_checked)
        self.save_config()

    def get_last_checked_update(self) -> int:
        self.load_config()
        v = self.settings.get("last-checked-update", 0)
        if not isinstance(v, int):
            v = 0
        return v

    def set_theme(self, theme: str):
        self.settings["theme"] = theme
        self.save_config()

        return self

    def get_theme(self) -> str:
        self.load_config()
        return self.settings.get("theme", "Dark Blue")

    def save_config(self) -> Path:
        if self.config_dir == '' or not Path(self.config_dir).exists():
            os.makedirs(self.config_dir)
            log.info(f"Generated config folder {self.config_dir}")

        with open(self.config_file, 'w', encoding="utf-8") as config_file:
            config_file.write(json.dumps(self.settings, indent=2))
            log.info(f"Saved config {self.config_file}")

        return self.config_file

    def load_config(self) -> dict:
        if self.config_dir == '' or not Path(self.config_dir).exists()\
                or not Path(self.config_file).exists():
            log.debug(f"Config does not exist.")
            return {}

        self.clean_save_file()

        log.debug(f"Loading config {self.config_file}")
        config_error = False
        with open(self.config_file, 'r', encoding="utf-8") as config_file:
            try:
                self.settings = json.load(config_file)
            except Exception as e:
                log.error("An error occurred trying to read config file.")
                log.error(e)
                config_error = True

        if config_error:
            log.info("Generating new config file.")
            with open(self.config_file, 'w', encoding="utf-8") as config_file:
                config_file.write(json.dumps(self.settings, indent=2))
        log.debug(self.settings)

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
            log.info("No config folder found.")
            return False

        with open(self.config_file, 'r', encoding="utf-8") as config_file:
            settings = dict(json.load(config_file))

        for setting in reversed(list(settings.keys())):
            if setting not in self.settings.keys():
                settings.pop(setting)
                log.debug(f"Cleared unused settings key: {setting}")

        with open(self.config_file, 'w', encoding="utf-8") as config_file:
            config_file.write(json.dumps(settings, indent=2))
            log.debug(f"Saved cleaned config: {self.config_file}")

        log.info("Cleaned-up saved file")

        return True
