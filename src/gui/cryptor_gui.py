import customtkinter as cti
import tkinter as tk
from src.cryptor.cryptor import Cryptor
from .gui_utils import *
import socket
import platform

from src.logs.cryptor_logger import create_logger, reset_log_file
from src.settings.settings import Settings

clog = create_logger("CryptorUI", 0)


class CryptorUI:
    FONT_ROBOTO = {"family": "Roboto", "size": 14}
    # If this value is anything but empty, it will ignore settings and use this predefined token
    SALT_FIXED: bytes = ''

    def __init__(self):
        self.settings = Settings()
        self.settings.load_config()
        self.settings.set_app_version(version_from_cryptor(Cryptor.VERSION))
        # SALT should control the fixed salt token
        # If it is set to empty, then it will be user defined (file -> set salt token)
        # If it is filled, then it will disregard whatever the settings use and use the fixed token
        if self.__is_salt_fixed():
            clog.debug("Salt token is predefined. Will ignore from settings")
            self.salt: bytes = self.SALT_FIXED
        else:
            self.salt: bytes = self.settings.get_salt_token()
            clog.debug(f"Salt token is not predefined. Will use from settings {self.salt.decode()}")

        self.root = None

        self.title = "Cryptor %VERSION%".replace("%VERSION%", version_from_cryptor(Cryptor.VERSION))

        self.appearance = AppearanceMode.DARK.value
        self.theme = Theme.BLUE_DARK.value

        self.window_size = (500, 330)

        self.tab_encrypt = "Encrypt"
        self.tab_decrypt = "Decrypt"
        self.tab_from_file = "From File"

        # Widgets of importance values
        # Tab Encrypt
        self.password_input_field = None
        # self.generated_token_field = None
        # self.generated_encr_pass_field = None
        # Tab Decrypt
        self.token_input_field = None
        self.encr_pass_field = None
        self.decrypted_pass_field = None
        # General
        self.main_font = None
        self.encrypted_run_feedback_var = None

        self.token_var: bytes = b''
        self.encrypted_password_var: bytes = b''
        self.decrypted_pass_var = None

        # Reset log file
        reset_log_file()

        clog.info(f"{self.title}")

    def run(self):
        clog.info(f"Initialising UI elements")

        cti.set_appearance_mode(self.appearance)
        cti.set_default_color_theme(self.theme)

        self.root = cti.CTk()
        self.root.geometry(f"{self.window_size[0]}x{self.window_size[1]}")
        self.root.title(self.title)

        # Menu Bar
        menu_bar = tk.Menu(self.root, background="#212121", foreground="white",
                           activebackground="#212121", activeforeground="white")
        self.root.config(menu=menu_bar)

        # File Menu
        if not self.__is_salt_fixed():
            # Only add if we need it. May change in the future, as things need to be added regardless of fixed salt
            menu_file = tk.Menu(menu_bar, tearoff=False, background="#212121", foreground="white")
            menu_file.add_command(label="Set Salt Token", command=self.set_salt_token)
            menu_file.add_separator()
            menu_file.add_command(label="Exit", command=self.root.quit)
            menu_bar.add_cascade(label="File", menu=menu_file)

        self.main_font = cti.CTkFont(**self.FONT_ROBOTO)

        frame = cti.CTkFrame(master=self.root)
        frame.pack(fill="both", expand=True)

        tabview = cti.CTkTabview(master=frame, width=500)
        tabview.grid(row=0, column=2, padx=(20, 0), pady=(20, 0), sticky="nsew")

        # ============= CREATE TAB ENCRYPT ===================
        tabview.add(self.tab_encrypt)
        tabview.tab(self.tab_encrypt)

        # Password Input Field
        self.password_input_field = cti.CTkEntry(master=tabview.tab(self.tab_encrypt),
                                                 placeholder_text="Password",
                                                 width=500,
                                                 font=self.main_font)
        self.password_input_field.pack(padx=10, pady=0)

        # buttons_frame_1 = cti.CTkFrame(master=tabview.tab(self.tab_encrypt))
        # buttons_frame_1.pack(fill="x", padx=50, pady=10)

        self.encrypted_run_feedback_var = cti.StringVar()
        # Button Begin Encrypt
        button_encrypt = cti.CTkButton(master=tabview.tab(self.tab_encrypt),
                                       text="Encrypt",
                                       command=self.do_encrypt,
                                       font=self.main_font)
        # button_save_token_file = cti.CTkButton(master=buttons_frame_1,
        #                                text="Save to file",
        #                                command=self.save_tokens_to_file,
        #                                font=self.main_font)
        button_encrypt.pack(padx=(6, 3), pady=12, side=cti.TOP, expand=False, fill=cti.X)
        # button_save_token_file.pack(padx=(3, 6), side=cti.LEFT, expand=True, fill=cti.X)

        encrypt_run_status = cti.CTkLabel(master=tabview.tab(self.tab_encrypt),
                                          textvariable=self.encrypted_run_feedback_var,
                                          font=self.main_font)
        encrypt_run_status.pack()

        # Token Field
        # self.token_var = cti.StringVar()
        # self.generated_token_field = cti.CTkEntry(master=tabview.tab(self.tab_encrypt),
        #                                           textvariable=self.token_var,
        #                                           width=500, font=self.main_font)
        # self.generated_token_field.configure(state="disabled")
        # self.generated_token_field.pack(padx=10, pady=12)

        # Copy Token Button
        # copy_token_button = cti.CTkButton(master=tabview.tab(self.tab_encrypt),
        #                                   text="Copy Token",
        #                                   command=self.copy_token,
        #                                   font=self.main_font)
        # copy_token_button.pack()

        # Encrypted Password Field
        # self.encrypted_password_var = cti.StringVar()
        # self.generated_encr_pass_field = cti.CTkEntry(master=tabview.tab(self.tab_encrypt),
        #                                               textvariable=self.encrypted_password_var,
        #                                               width=500,
        #                                               font=self.main_font)
        # self.generated_encr_pass_field.configure(state="disabled")
        # self.generated_encr_pass_field.pack(padx=10, pady=12)

        # Copy Encrypted Password Button
        # copy_encrypted_password_button = cti.CTkButton(master=tabview.tab(self.tab_encrypt),
        #                                                text="Copy Encrypted Password",
        #                                                command=self.copy_encrypted_password,
        #                                                font=self.main_font)
        # copy_encrypted_password_button.pack()

        # ============= CREATE TAB DECRYPT ===================
        tabview.add(self.tab_decrypt)
        tabview.tab(self.tab_decrypt)

        # Token Input Field
        self.token_input_field = cti.CTkEntry(master=tabview.tab(self.tab_decrypt),
                                              placeholder_text="Please supply a Token",
                                              width=500,
                                              font=self.main_font)
        self.token_input_field.pack(padx=10, pady=6)

        # Password Input Field
        self.encr_pass_field = cti.CTkEntry(master=tabview.tab(self.tab_decrypt),
                                            placeholder_text="Please supply an Encrypted Password",
                                            width=500,
                                            font=self.main_font)
        self.encr_pass_field.pack(padx=10, pady=0)

        # Button Begin Decrypt
        button_decrypt = cti.CTkButton(master=tabview.tab(self.tab_decrypt),
                                       text="Decrypt",
                                       command=self.do_decrypt,
                                       font=self.main_font)
        button_decrypt.pack(padx=0, pady=12)

        # Decrypted Password Field
        self.decrypted_pass_var = cti.StringVar()
        self.decrypted_pass_field = cti.CTkEntry(master=tabview.tab(self.tab_decrypt),
                                                 textvariable=self.decrypted_pass_var,
                                                 width=500,
                                                 font=self.main_font)
        self.decrypted_pass_field.pack(padx=10, pady=0)

        # Button Copy Decrypted Password
        button_copy_decrypted_password = cti.CTkButton(master=tabview.tab(self.tab_decrypt),
                                                       text="Copy Password",
                                                       command=self.copy_decrypted_password,
                                                       font=self.main_font)
        button_copy_decrypted_password.pack(padx=0, pady=12)

        # ============= CREATE TAB FROM FILES ===================
        tabview.add(self.tab_from_file)
        tabview.pack(padx=10, pady=12)

        label_wip = cti.CTkLabel(master=tabview.tab(self.tab_from_file),
                                 text="Under construction",
                                 text_color="Yellow",
                                 font=self.main_font)
        label_wip.pack(padx=0, pady=12)

        # Label Credits
        label_credits = cti.CTkLabel(master=frame,
                                     text="© r0fld4nc3",
                                     font=self.main_font)
        label_credits.pack()

        clog.info(f"Running mainloop")

        self.root.mainloop()

        # TODO: Why does this run everytime we accept the salt token
        self.settings.save_config()

        clog.info("Shutdown")

    def do_encrypt(self):
        clog.info(f"Encrypting")
        # Generate a key
        session = Cryptor()
        session.set_salt(self.salt)

        password = self.password_input_field.get()

        if not password:
            return False

        # Passing password as token, so it's not a random token/session each time
        session.generate_session(token=password)
        token, encrypted = session.encrypt(password.encode())

        self.token_var = token.decode()
        self.encrypted_password_var = encrypted.decode()

        clog.info("Encryption finished")

        saved_file = self.save_tokens_to_file()
        if not saved_file:
            self.encrypted_run_feedback_var.set(f"Ran on {get_now()} - WARNING: No file saved")
        else:
            self.encrypted_run_feedback_var.set(f"Ran on {get_now()}")

        return True

    def copy_token(self):
        if self.token_var:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.token_var)
            clog.info(f"Copied token to clipboard")
        else:
            clog.warning(f"No token to copy to clipboard")

    def copy_encrypted_password(self):
        if self.encrypted_password_var:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.encrypted_password_var)
            clog.info(f"Copied encrypted password to clipboard")
        else:
            clog.warning(f"No encrypted password to copy to clipboard")

    def copy_decrypted_password(self):
        if self.decrypted_pass_var:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.decrypted_pass_var.get())
            clog.info(f"Copied decrypted password to clipboard")
        else:
            clog.warning(f"No decrypted password to copy to clipboard")

    def do_decrypt(self):
        clog.info(f"Beginning decryption")

        token = self.token_input_field.get()
        encrypted_password = self.encr_pass_field.get()

        if not token and not encrypted_password:
            clog.warning(f"No token and encrypted password provided")
            return False

        # Decrypt
        session = Cryptor()
        session.set_salt(self.salt)
        decrypted = session.decrypt(token, encrypted_password)

        self.decrypted_pass_var.set(decrypted.decode())

        clog.info(f"Decryption finished")

    def save_tokens_to_file(self):
        clog.info(f"Save tokens to file")

        file_suffix = "_tokens"

        file_path = Path.home()
        file_name = socket.gethostname() + "_tokens.txt"

        if "Windows" in platform.platform():
            clog.info(f"Platform is Windows")
            file_path = file_path / "Desktop"

        clog.info(f"Suggested file: {file_path / file_name}")

        tokens_file = cti.filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", ".txt")],
                                                       title="Save tokens file",
                                                       initialdir=file_path,
                                                       initialfile=file_name)

        # Add _tokens to file if not exists
        if file_suffix not in tokens_file:
            _path = Path(tokens_file).parent
            _name = Path(tokens_file).name
            clog.info(f"Re-adding suffix '{file_suffix}' to file name {_name}")
            _suffix = Path(tokens_file).suffix
            _name = _name.replace(_suffix, "")

            _name += f"{file_suffix}{_suffix}"
            tokens_file = str(_path / _name)

        user_name = Path(tokens_file).name.replace("_tokens", '').replace(Path(tokens_file).suffix, "")
        clog.info(f"Generated User Name {user_name}")

        if tokens_file != file_suffix:
            with open(tokens_file, 'w') as f:
                f.write(f"[USER]\n{user_name}\n\n[TOKEN]\n{self.token_var}\n\n[PASSWORD]\n{self.encrypted_password_var}")
            clog.info(f"Wrote {tokens_file}")
        else:
            clog.warning(f"Aborted. Returned tokens file: {tokens_file}")
            tokens_file = ''

        return tokens_file

    def set_salt_token(self) -> bytes:
        # Launch a prompt window
        dialog = cti.CTkInputDialog(text="New Salt Token:", title="Set Salt Token")
        new_token = dialog.get_input()  # If nothing/aborted returns '' or None

        # If SALT is predefined, then just return that
        # Don't save it to file
        if self.__is_salt_fixed():
            self.salt = self.SALT_FIXED
            return self.salt

        # Is None means the user specifically cancelled the operation
        if new_token is not None:
            self.salt = new_token

            self.settings.set_salt_token(self.salt)

        return self.salt

    def __is_salt_fixed(self):
        if self.SALT_FIXED:
            return True

        return False


if __name__ == "__main__":
    ui = CryptorUI()
    ui.run()
