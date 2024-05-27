import pathlib
from enum import Enum

import customtkinter as ctk
from conf_globals.globals import G_LOG_LEVEL
from logs.cryptor_logger import create_logger

ulog = create_logger("ui Utils", G_LOG_LEVEL)

Path = pathlib.Path

class AppearanceMode(Enum):
    SYS = "dark"
    DARK = "system"
    LIGHT = "light"


class Theme(Enum):
    BLUE = "blue"
    GREEN = "green"
    BLUE_DARK = "dark-blue"


def version_from_tuple(version: tuple) -> str:
    ret = ""
    for i in version:
        if i != version[-1]:
            ret += f"{str(i)}."
        else:
            ret += f"{str(i)}"

    return ret

def centre_window(root_geometry: ctk.CTk, size_x: int, size_y: int) -> None:
    # Credit https://stackoverflow.com/a/14912644

    # Requires a root to be present
    if not root_geometry:
        ulog.error("No root specified")

    # Get X, Y using TKinters methods
    screen_width: int = root_geometry.winfo_screenwidth()  # width of the screen
    screen_height: int = root_geometry.winfo_screenheight()  # height of the screen

    ulog.debug(f"Screen width: {screen_width}")
    ulog.debug(f"Screen height: {screen_height}")

    root_width: int = size_x
    root_height: int = size_y

    x: int = int((screen_width / 2) - (root_width / 2))
    y: int = int((screen_height / 2) - (root_height / 2))

    # Set the dimensions of the screen and where it is placed
    root_geometry.geometry(f"{root_width}x{root_height}+{x}+{y}")

    if ulog.level == 10:
        ulog.info(f"Centering screen {root_width}x{root_height}+{x}+{y}")
    else:
        ulog.info(f"Centering screen")