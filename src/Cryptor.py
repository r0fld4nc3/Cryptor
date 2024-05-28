from ui.cryptor_gui import CryptorUI
from src.logs.cryptor_logger import reset_log_file

if __name__ == "__main__":
    reset_log_file()
    ui = CryptorUI()
    ui.show()
