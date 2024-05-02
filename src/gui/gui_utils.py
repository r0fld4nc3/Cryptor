import pathlib
from enum import Enum
import datetime

Path = pathlib.Path


class AppearanceMode(Enum):
    SYS = "dark"
    DARK = "system"
    LIGHT = "light"


class Theme(Enum):
    BLUE = "blue"
    GREEN = "green"
    BLUE_DARK = "dark-blue"


def version_from_cryptor(version: tuple):
    ret = ""
    for i in version:
        if i != version[-1]:
            ret += f"{str(i)}."
        else:
            ret += f"{str(i)}"

    return ret


def get_now():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
