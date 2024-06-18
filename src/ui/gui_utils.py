import pathlib
from enum import Enum
from typing import Union

import customtkinter as ctk

from conf_globals.globals import G_LOG_LEVEL
from logs import create_logger

log = create_logger("UI Utils", G_LOG_LEVEL)

Path = pathlib.Path

THEMES_FOLDER = Path.cwd() / "src" / "ui" / "themes"

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
        log.error("No root specified")

    # Get X, Y using TKinters methods
    screen_width: int = root_geometry.winfo_screenwidth()  # width of the screen
    screen_height: int = root_geometry.winfo_screenheight()  # height of the screen

    log.debug(f"Screen width: {screen_width}")
    log.debug(f"Screen height: {screen_height}")

    root_width: int = size_x
    root_height: int = size_y

    x: int = int((screen_width / 2) - (root_width / 2))
    y: int = int((screen_height / 2) - (root_height / 2))

    # Set the dimensions of the screen and where it is placed
    root_geometry.geometry(f"{root_width}x{root_height}+{x}+{y}")

    if log.level == 10:
        log.info(f"Centering screen {root_width}x{root_height}+{x}+{y}")
    else:
        log.info(f"Centering screen")

def theme_name_from_theme_file(theme_file: Union[str, Path]):
    if isinstance(theme_file, str):
        # Wowweee...
        theme_name = ' '.join(str(w).capitalize() for w in theme_file.replace('\\', '/').replace('-', ' ').split('/')[-1].split('.json')[0].split(' '))
    elif isinstance(theme_file, Path):
        theme_name = ' '.join([str(w).capitalize() for w in theme_file.name.split('.')[0].split('-')])
    else:
        return False

    log.debug(f"Theme Name: {theme_name}")

    return theme_name

def get_custom_theme(theme_name: str):
    log.info(f"Getting custom theme {theme_name}")
    theme_file_name = '-'.join(theme_name.lower().split(' ')) + ".json"

    theme_file = THEMES_FOLDER / theme_file_name

    if not theme_file.exists():
        log.info(f"Theme doesn't appear to exist in custom themes folder. Attempting built-in customtkinter")
        # If the theme file doesn't exist, try to get from the built-in customtkinter themes
        # Simply return the theme name like so: Dark Blue
        theme_file = ' '.join([str(w).capitalize() for w in theme_name.split(' ')])
        log.info(f"Theme file: {theme_file}")
    else:
        log.info(f"Theme file: {theme_file}")

    return theme_name_from_theme_file(theme_file)