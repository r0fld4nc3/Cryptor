import pathlib
from enum import Enum

Path = pathlib.Path


class AppearanceMode(Enum):
    SYS = "dark"
    DARK = "system"
    LIGHT = "light"


class Theme(Enum):
    BLUE = "blue"
    GREEN = "green"
    BLUE_DARK = "dark-blue"


def version_from_cryptor(version: tuple) -> str:
    ret = ""
    for i in version:
        if i != version[-1]:
            ret += f"{str(i)}."
        else:
            ret += f"{str(i)}"

    return ret
