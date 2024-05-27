import logging
import pathlib

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
    logger = logging.getLogger(logger_name)

    logger.setLevel(LEVELS.get(level, 1))

    handler_stream = logging.StreamHandler()
    handler_file = logging.FileHandler(log_file)

    formatter = logging.Formatter("[%(name)s] [%(asctime)s] [%(levelname)s] %(message)s", datefmt="%d-%m-%Y %H:%M:%S")
    handler_stream.setFormatter(formatter)
    handler_file.setFormatter(formatter)

    logger.addHandler(handler_stream)
    logger.addHandler(handler_file)

    return logger


def reset_log_file() -> None:
    if Path(log_file).exists():
        with open(log_file, 'w') as f:
            f.write('')
