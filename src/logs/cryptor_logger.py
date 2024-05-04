import logging
import pathlib

log_file = "cryptor.log"

LOG_LEVELS = {
    0: logging.DEBUG,
    1: logging.INFO,
    2: logging.WARNING,
    3: logging.ERROR
}

def create_logger(logger_name: str, level: int):
    logger = logging.getLogger(logger_name)

    logger.setLevel(LOG_LEVELS.get(level, 1))

    handler_stream = logging.StreamHandler()
    handler_file = logging.FileHandler(log_file)

    formatter = logging.Formatter("[%(name)s] [%(asctime)s] [%(levelname)s] %(message)s", datefmt="%d-%m-%Y %H:%M:%S")
    handler_stream.setFormatter(formatter)
    handler_file.setFormatter(formatter)

    logger.addHandler(handler_stream)
    logger.addHandler(handler_file)

    return logger


def reset_log_file():
    if pathlib.Path(log_file).exists():
        with open(log_file, 'w') as f:
            f.write('')


cryptor_log = create_logger("CryptorLog", 6)
