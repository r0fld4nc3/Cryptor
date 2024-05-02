import pathlib
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
import base64

from src.logs.cryptor_logger import create_logger
clog = create_logger("Cryptor", 1)

Path = pathlib.Path


class Cryptor:
    VERSION = (0, 0, 1)

    def __init__(self) -> None:
        self.token: bytes = b''
        self.salt: bytes = b''

        self.cipher = None

        self.encrypted: bytes = b''
        self.unencrypted: bytes = b''
        self.decrypted: bytes = b''

    def generate_session(self, token: str = None) -> bytes:
        if not token:
            clog.info(f"Generating session without explicit token")
            key = self.generate_key_from_string(Fernet.generate_key().decode())
        else:
            clog.info(f"Generating session from given input")
            if isinstance(token, bytes):
                clog.info("Token is bytes. Decoding.")
                # It's bytes
                token = token.decode()
            key = self.generate_key_from_string(token)

        self.cipher = Fernet(key)
        self.token = key

        clog.info("Assigned key to token")

        return self.token

    def encrypt(self, to_encrypt: Union[bytes, str]) -> tuple[bytes, bytes]:
        clog.info("Beginning encryption process")
        if isinstance(to_encrypt, bytes):
            clog.info(f"Decoding bytes to encrypt")
            self.unencrypted = to_encrypt.decode()
        else:
            self.unencrypted = to_encrypt

        if not isinstance(to_encrypt, bytes):
            clog.info(f"Encoding to bytes to encrypt")
            to_encrypt = to_encrypt.encode()

        self.encrypted = self.cipher.encrypt(to_encrypt)
        clog.info(f"Encrypted")
        clog.debug(f"Token={self.token.decode()}")
        clog.debug(f"Encrypted={self.encrypted.decode()}")

        clog.info("Encryption finished")

        return self.token, self.encrypted

    def decrypt(self, token: Union[bytes, str], string: Union[bytes, str]) -> bytes:
        clog.info(f"Beginning decryption process")
        if not isinstance(string, str):
            clog.info(f"Decoding incoming bytes")
            string = string.decode()

        if not isinstance(token, str):
            token = token.decode()

        self.token = token
        try:
            self.cipher = Fernet(self.token)
        except ValueError as invalid_token_error:
            clog.error(f"{invalid_token_error}. The supplied key was: '{self.token}'")

        try:
            self.decrypted = self.cipher.decrypt(string)
        except InvalidToken as input_error:
            clog.error(f"Invalid encrypted password provided: {input_error}")
        except AttributeError as input_error:
            clog.error(f"{input_error}")

        clog.info(f"Decryption finished")

        return self.decrypted

    def generate_key_from_string(self, input_string):
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
        clog.info("Generated Cipher key")

        return key

    def set_salt(self, new_token: Union[str, bytes]) -> bytes:
        if not isinstance(new_token, bytes):
            new_token = new_token.encode()

        self.salt = new_token

        clog.info("Set new Salt token")

        return self.salt
