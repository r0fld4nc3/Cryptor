import requests
import json

from src.logs.cryptor_logger import create_logger
from conf_globals.globals import G_LOG_LEVEL

updlog = create_logger("Updater", G_LOG_LEVEL)

class Updater:
    def __init__(self):
        self.owner = "r0fld4nc3"
        self.repo_name = "Cryptor"
        self.download_cancelled = False

        self.repo = f"{self.owner}/{self.repo_name}"
        self.url = f"https://api.github.com/repos/{self.repo}/releases/latest"

        self._release_tag = "tag_name"
        self._assets_tag = "assets"
        self._download_url = "browser_download_url"

        self.pulled_release = {}
        self.download_location = ""  # Local disk location to save the downloaded file.

        self.local_version = "0.0.0"

    def check_for_update(self) -> bool:
        updlog.info("Checking for Cryptor update...")

        try:
            # allow_redirects=False because of vulnerability https://security.snyk.io/vuln/SNYK-PYTHON-REQUESTS-5595532
            updlog.info(f"Requesting from {self.url}")
            response = requests.get(self.url, timeout=60, allow_redirects=False)
        except requests.ConnectionError as con_err:
            updlog.error(f"Unable to establish connection to update repo.")
            updlog.error(con_err)
            return False

        if not response.status_code == 200:
            updlog.error("Not a valid repository.")

        pulled_release = response.json()
        self.pulled_release = {
                "name":     f"{self.repo_name}",
                "latest":   pulled_release[self._release_tag],
                "download": pulled_release[self._assets_tag][0][self._download_url],
                "asset":    pulled_release[self._assets_tag][0][self._download_url].split("/")[-1]
        }

        updlog.debug(f"Release info:\n{json.dumps(self.pulled_release, indent=2)}")

        is_new_version = self.compare_release_versions(self.pulled_release.get("latest"), self.local_version)

        return is_new_version

    def compare_release_versions(self, pulled, existing) -> bool:
        _pulled_version = list(str(pulled).lower().split("v")[1].split("."))
        _pulled_major = self._to_int(_pulled_version[0])
        _pulled_minor = self._to_int(_pulled_version[1])
        _pulled_micro = self._to_int(_pulled_version[2])

        try:
            _existing_version = list(str(existing).lower().split("v")[1].split("."))
        except IndexError:
            _existing_version = list(str(existing).lower().split("."))
        _existing_major = self._to_int(_existing_version[0])
        _existing_minor = self._to_int(_existing_version[1])
        _existing_micro = self._to_int(_existing_version[2])

        updlog.debug(f"Pulled:   {_pulled_version}, [{_pulled_major}, {_pulled_minor}, {_pulled_micro}]")
        updlog.debug(f"Existing: {_existing_version}, [{_existing_major}, {_existing_minor}, {_existing_micro}]")

        if _pulled_major > _existing_major:
            updlog.info(
                f"There is a new version available: {'.'.join(_pulled_version)} > {'.'.join(_existing_version)}")
            return True

        if _pulled_minor > _existing_minor:
            if _existing_major <= _pulled_major:
                updlog.info(f"There is a new version available: {'.'.join(_pulled_version)} > {'.'.join(_existing_version)}")
                return True

        if _pulled_micro > _existing_micro:
            if _existing_major <= _pulled_major and _existing_minor <= _pulled_minor:
                updlog.info(f"There is a new version available: {'.'.join(_pulled_version)} > {'.'.join(_existing_version)}")
                return True

        if updlog.level >= 10:
            updlog.info(f"No updates found: {'.'.join(_pulled_version)} (repo) ==> {'.'.join(_existing_version)} (current)")
        else:
            updlog.info("No updates found.")
        return False

    def set_current_version(self, version_str: str) -> None:
        self.local_version = version_str

    @staticmethod
    def _to_int(value):
        _out = value
        try:
            _out = int(value)
        except ValueError:
            updlog.error(f"Unable to convert {value} to int.")
            _out = value

        return _out
