import logging
import pathlib
from os import makedirs

from conf_globals.globals import config_folder

Path = pathlib.Path

log_file = config_folder / "cryptor.log"

LEVELS = {
    0: logging.DEBUG,
    1: logging.INFO,
    2: logging.WARNING,
    3: logging.ERROR
}

def create_logger(logger_name: str, level: int) -> logging.Logger:
    # Create needed folder if it doesn't exist
    if not config_folder.exists():
        makedirs(config_folder, exist_ok=True)

    logger = logging.getLogger(logger_name)

    logger.setLevel(LEVELS.get(level, 1))

    handler_stream = logging.StreamHandler()
    handler_file = logging.FileHandler(log_file)

    formatter = logging.Formatter("[%(name)s] [%(asctime)s] [%(levelname)s] %(message)s", datefmt="%d-%m-%Y %H:%M:%S")
    handler_stream.setFormatter(formatter)
    handler_file.setFormatter(formatter)

    if not any(isinstance(handler, logging.StreamHandler) for handler in logger.handlers):
        logger.addHandler(handler_stream)

    if not any(isinstance(handler, logging.FileHandler) and handler.baseFilename == log_file for handler in logger.handlers):
        logger.addHandler(handler_file)

    return logger


def reset_log_file() -> None:
    if Path(log_file).exists():
        with open(log_file, 'w') as f:
            f.write('')
