import base64
import pathlib
from typing import Union

# Cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

from logs import create_logger
from conf_globals.globals import G_LOG_LEVEL
import utils

log = create_logger("Cryptor", G_LOG_LEVEL)

Path = pathlib.Path


class Cryptor:
    VERSION = (0, 0, 2)

    def __init__(self) -> None:
        self.token: bytes = b'' # A token to act as the hashing key
        self.salt: bytes = b'' # Used to mix in with string hashing

        self.cipher = None # The cipher object that will hash the strings

        self.encrypted: bytes = b'' # The final hashed string
        self.decrypted: bytes = b'' # The final unhashed string

    def init_session(self, token: str = None) -> bytes:
        if not token:
            log.info(f"Generating session without explicit token")
            key = self.generate_key_from_string(Fernet.generate_key().decode())
        else:
            log.info(f"Generating session from given input")
            token = utils.ensure_str(token)
            key = self.generate_key_from_string(token)

        self.cipher = Fernet(key)
        self.token = key

        log.info("Assigned key to token")

        return utils.ensure_bytes(self.token)

    def encrypt(self, to_encrypt: Union[bytes, str]) -> tuple[bytes, bytes]:
        log.info("Beginning encryption process")

        if not self.cipher:
            # No manual session generated
            log.info("No manual session initialised. Initialising with empty token")
            self.init_session()

        self.encrypted = self.cipher.encrypt(utils.ensure_bytes(to_encrypt))
        log.info(f"Encrypted")
        log.debug(f"Token={self.token.decode()}")
        log.debug(f"Encrypted={self.encrypted.decode()}")

        log.info("Encryption finished")

        return utils.ensure_bytes(self.token), utils.ensure_bytes(self.encrypted)

    def decrypt(self, token: Union[bytes, str], string: Union[bytes, str]) -> bytes:
        log.info(f"Beginning decryption process")

        self.token = utils.ensure_bytes(token)

        try:
            self.cipher = Fernet(utils.ensure_bytes(self.token))
        except ValueError as invalid_token_error:
            log.error(f"{invalid_token_error}. The supplied key was: '{self.token.decode()}'")

        try:
            self.decrypted = self.cipher.decrypt(utils.ensure_bytes(string))
        except InvalidToken as input_error:
            log.error(f"Invalid encrypted password provided: {input_error}")
        except AttributeError as input_error:
            log.error(f"{input_error}")

        log.info(f"Decryption finished")

        return utils.ensure_bytes(self.decrypted)

    def generate_key_from_string(self, input_string) -> bytes:
        # Convert input string to bytes
        input_bytes = input_string.encode()

        # Derive a key using PBKDF2 with SHA-256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Length of the key
            salt=self.salt,  # Add a salt to the input
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(input_bytes))
        log.info("Generated Cipher key")

        return utils.ensure_bytes(key)

    def set_salt(self, new_salt: Union[str, bytes]) -> bytes:
        new_salt = utils.ensure_bytes(new_salt)
        self.salt = new_salt

        log.info("Set new Salt token")

        return utils.ensure_bytes(self.salt)