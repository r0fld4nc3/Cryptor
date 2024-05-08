import socket
import platform
import webbrowser
from typing import Union
from concurrent.futures import ThreadPoolExecutor

import customtkinter as cti
import tkinter as tk

from src.utils import utils
from src.gui.gui_utils import *
from src.cryptor.cryptor import Cryptor
from src.settings.settings import Settings
from src.logs.cryptor_logger import create_logger, reset_log_file
from src.updater.updater import Updater

cuilog = create_logger("CryptorUI", 1)
cuislog = create_logger("CryptorSettingsUI", 1)


class CryptorUI:
    FONT_ROBOTO = {"family": "Roboto", "size": 14}
    # If this value is anything but empty, it will ignore settings and use this predefined token
    SALT_FIXED: bytes = ''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Settings
        self.settings = Settings()
        self.settings.load_config()
        self.settings.set_app_version(version_from_cryptor(Cryptor.VERSION))
        self.toplevel_settings_class = CryptorSettingsUI
        self.settings_gui = None

        # Updater
        self.has_update: bool = False
        self.updater: Union[Updater, None] = None
        if self.settings.get_check_updates():
            self.updater = Updater()
            self.updater.set_current_version(version_from_cryptor(Cryptor.VERSION))
            self.check_for_update()

        # General
        self.root = None
        self.main_font = None
        self.screen_x: int = 0
        self.screen_y: int = 0

        # SALT should control the fixed salt token
        # If it is set to empty, then it will be user defined (file -> set salt token)
        # If it is filled, then it will disregard whatever the settings use and use the fixed token
        if self.__is_salt_fixed():
            cuilog.debug("Salt token is predefined. Will ignore from settings")
            self.salt: bytes = self.SALT_FIXED
        else:
            self.salt: bytes = self.settings.get_salt_token()
            cuilog.debug(f"Salt token is not predefined. Will use from settings {self.salt.decode()}")

        self.title = "Cryptor %VERSION%".replace("%VERSION%", version_from_cryptor(Cryptor.VERSION))

        self.appearance = AppearanceMode.DARK.value
        self.theme = Theme.BLUE_DARK.value

        self.window_size = (500, 400)

        self.tab_encrypt = "Encrypt"
        self.tab_decrypt = "Decrypt"
        self.tab_from_file = "From File"

        # Widgets of importance values
        self.label_credits = None
        # Tab Encrypt
        self.password_input_field = None
        self.generated_token_field = None
        self.generated_encrypted_pass_field = None
        # Tab Decrypt
        self.token_input_field = None
        self.encrypted_pass_field = None
        self.decrypted_pass_field = None
        self.button_show_token = None
        self.button_show_encrypted_password = None
        self.button_show_decrypted_password = None

        # Vars that hold display info
        self.token_var: Union[cti.StringVar, str] = ''  # These need to be defined later becase there is not root Tkinter window
        self.encrypted_password_var: Union[cti.StringVar, str] = ''  # These need to be defined later becase there is not root Tkinter window
        self.decrypted_password_var: Union[cti.StringVar, str] = ''  # These need to be defined later becase there is not root Tkinter window
        self.encrypted_run_feedback_var = None

        self.is_encrypted_token_shown = False
        self.is_encrypted_password_shown = False
        self.is_decrypted_password_shown = False

        # Reset log file
        reset_log_file()

        cuilog.info(f"{self.title}")

    def show(self):
        cuilog.info(f"Initialising UI elements")

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
        # Only add if we need it. May change in the future, as things need to be added regardless of fixed salt
        menu_file = tk.Menu(menu_bar, tearoff=False, background="#212121", foreground="white")
        if not self.__is_salt_fixed():
            menu_file.add_command(label="Set Salt Token", command=self.set_salt_token)
        menu_file.add_command(label="Settings", command=self.open_settings_gui)
        menu_file.add_separator()
        menu_file.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=menu_file)

        self.main_font = cti.CTkFont(**self.FONT_ROBOTO)

        frame = cti.CTkFrame(master=self.root, fg_color="transparent")
        frame.pack(fill="both", expand=True)

        tabview = cti.CTkTabview(master=frame, width=500, fg_color="transparent")
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

        self.encrypted_run_feedback_var = cti.StringVar()
        # Button Begin Encrypt
        button_encrypt = cti.CTkButton(master=tabview.tab(self.tab_encrypt),
                                       text="Encrypt",
                                       command=self.do_encrypt,
                                       font=self.main_font)
        button_encrypt.pack(padx=(6, 3), pady=12, side=cti.TOP, expand=False, fill=cti.X)

        # Token Field
        self.token_var = cti.StringVar()
        self.generated_token_field = cti.CTkEntry(master=tabview.tab(self.tab_encrypt),
                                                  textvariable=self.token_var,
                                                  show='*',
                                                  width=500,
                                                  font=self.main_font)
        self.generated_token_field.configure(state="disabled")
        self.generated_token_field.pack(padx=10, pady=12)

        # Copy/Show Token Buttons Frame
        frame_btns_copy_show_encrypted_token = cti.CTkFrame(master=tabview.tab(self.tab_encrypt), fg_color="transparent")
        frame_btns_copy_show_encrypted_token.pack(fill="x", padx=50, pady=0)

        # Copy Token Button
        copy_token_button = cti.CTkButton(master=frame_btns_copy_show_encrypted_token,
                                          text="Copy Token",
                                          command=self.copy_token,
                                          font=self.main_font)

        # Show Token Button
        self.button_show_token = cti.CTkButton(master=frame_btns_copy_show_encrypted_token,
                                               text="Show Token",
                                               command=self.show_token,
                                               font=self.main_font)
        copy_token_button.pack(padx=(0, 6), side=cti.LEFT, expand=True, fill=cti.X)
        self.button_show_token.pack(padx=(6, 0), side=cti.LEFT, expand=True, fill=cti.X)

        # Encrypted Password Field
        self.encrypted_password_var = cti.StringVar()
        self.generated_encrypted_pass_field = cti.CTkEntry(master=tabview.tab(self.tab_encrypt),
                                                           textvariable=self.encrypted_password_var,
                                                           show='*',
                                                           width=500,
                                                           font=self.main_font)
        self.generated_encrypted_pass_field.configure(state="disabled")
        self.generated_encrypted_pass_field.pack(padx=10, pady=12)

        # Copy/Show Token Buttons Frame
        frame_btns_copy_show_encrypted_pw = cti.CTkFrame(master=tabview.tab(self.tab_encrypt), fg_color="transparent")
        frame_btns_copy_show_encrypted_pw.pack(fill="x", padx=50, pady=0)

        # Copy Encrypted Password Button
        copy_encrypted_password_button = cti.CTkButton(master=frame_btns_copy_show_encrypted_pw,
                                                       text="Copy Password",
                                                       command=self.copy_encrypted_password,
                                                       font=self.main_font)

        # Show Encrypted Password Button
        self.button_show_encrypted_password = cti.CTkButton(master=frame_btns_copy_show_encrypted_pw,
                                                            text="Show Password",
                                                            command=self.show_encrypted_password,
                                                            font=self.main_font)

        copy_encrypted_password_button.pack(padx=(0, 6), side=cti.LEFT, expand=True, fill=cti.X)
        self.button_show_encrypted_password.pack(padx=(6, 0), side=cti.LEFT, expand=True, fill=cti.X)

        # Set and Pack info label for run status
        encrypt_run_status = cti.CTkLabel(master=tabview.tab(self.tab_encrypt),
                                          textvariable=self.encrypted_run_feedback_var,
                                          font=self.main_font)
        encrypt_run_status.pack(side=cti.BOTTOM, expand=True, fill=cti.X)

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
        self.encrypted_pass_field = cti.CTkEntry(master=tabview.tab(self.tab_decrypt),
                                                 placeholder_text="Please supply an Encrypted Password",
                                                 width=500,
                                                 font=self.main_font)
        self.encrypted_pass_field.pack(padx=10, pady=0)

        # Button Begin Decrypt
        button_decrypt = cti.CTkButton(master=tabview.tab(self.tab_decrypt),
                                       text="Decrypt",
                                       command=self.do_decrypt,
                                       font=self.main_font)
        button_decrypt.pack(padx=0, pady=12)

        # Decrypted Password Field
        self.decrypted_password_var = cti.StringVar()
        self.decrypted_pass_field = cti.CTkEntry(master=tabview.tab(self.tab_decrypt),
                                                 textvariable=self.decrypted_password_var,
                                                 width=500,
                                                 font=self.main_font,
                                                 show="*")
        self.decrypted_pass_field.pack(padx=10, pady=0)

        frame_btns_copy_show_decrypted_pw = cti.CTkFrame(master=tabview.tab(self.tab_decrypt), fg_color="transparent")
        frame_btns_copy_show_decrypted_pw.pack(fill="x", padx=50, pady=10)

        # Button Copy Decrypted Password
        button_copy_decrypted_password = cti.CTkButton(master=frame_btns_copy_show_decrypted_pw,
                                                       text="Copy Password",
                                                       command=self.copy_decrypted_password,
                                                       font=self.main_font)

        # Button Show Decrypted Password
        self.button_show_decrypted_password = cti.CTkButton(master=frame_btns_copy_show_decrypted_pw,
                                                            text="Show Password",
                                                            command=self.show_decrypted_password,
                                                            font=self.main_font)

        button_copy_decrypted_password.pack(padx=(0, 6), side=cti.LEFT, expand=True, fill=cti.X)
        self.button_show_decrypted_password.pack(padx=(6, 0), side=cti.LEFT, expand=True, fill=cti.X)

        # ============= CREATE TAB FROM FILES ===================
        tabview.add(self.tab_from_file)
        tabview.pack(padx=10, pady=12)

        label_wip = cti.CTkLabel(master=tabview.tab(self.tab_from_file),
                                 text="Under construction",
                                 text_color="Yellow",
                                 font=self.main_font)
        label_wip.pack(padx=0, pady=12)

        # Label Credits
        self.label_credits = cti.CTkLabel(master=frame,
                                     text="© r0fld4nc3",
                                     font=self.main_font)
        self.label_credits.pack()

        self.__centre_window()

        # Check for update
        if self.updater and self.has_update:
            self.__label_update_available()

        cuilog.info(f"Running mainloop")

        self.root.mainloop()

        # TODO: Why does this run everytime we accept the salt token
        self.settings.save_config()

        cuilog.info("Shutdown")

    def do_encrypt(self):
        cuilog.info(f"Encrypting")
        # Generate a key
        cryptor = Cryptor()
        cryptor.set_salt(self.salt)

        password = self.password_input_field.get()

        if not password:
            self.reset_encryption_fields()
            return False

        # Passing password as token, so it's not a random token/session each time
        cryptor.init_session(token=password)
        token, encrypted = cryptor.encrypt(password.encode())

        self.token_var.set(utils.ensure_str(token))
        self.encrypted_password_var.set(utils.ensure_str(encrypted))

        cuilog.info("Encryption finished")

        if self.settings.get_save_file_on_encrypt():
            saved_file = self.save_tokens_to_file()
            if not saved_file:
                self.encrypted_run_feedback_var.set(f"Ran on {utils.get_now()} - WARNING: No file saved")
            else:
                self.encrypted_run_feedback_var.set(f"Ran on {utils.get_now()}")
        else:
             self.encrypted_run_feedback_var.set(f"Ran on {utils.get_now()}")

        return True

    def copy_token(self):
        if self.token_var.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(utils.ensure_str(self.token_var.get()))
            cuilog.info(f"Copied token to clipboard")
        else:
            cuilog.warning(f"No token to copy to clipboard")

    def copy_encrypted_password(self):
        if self.encrypted_password_var.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(utils.ensure_str(self.encrypted_password_var.get()))
            cuilog.info(f"Copied encrypted password to clipboard")
        else:
            cuilog.warning(f"No encrypted password to copy to clipboard")

    def copy_decrypted_password(self):
        if self.decrypted_password_var:
            self.root.clipboard_clear()
            self.root.clipboard_append(utils.ensure_str(self.decrypted_password_var.get()))
            cuilog.info(f"Copied decrypted password to clipboard")
        else:
            cuilog.warning(f"No decrypted password to copy to clipboard")

    def show_decrypted_password(self):
        if not self.decrypted_password_var.get():
            return

        if self.is_decrypted_password_shown:
            cuilog.info("Hiding decrypted password")
            self.decrypted_pass_field.configure(show='*')
            self.button_show_decrypted_password.configure(text="Show Password")
            self.is_decrypted_password_shown = False
        else:
            cuilog.info("Showing decrypted password")
            self.decrypted_pass_field.configure(show='')
            self.button_show_decrypted_password.configure(text="Hide Password")
            self.is_decrypted_password_shown = True

    def show_token(self):
        if not self.token_var.get():
            return

        if self.is_encrypted_token_shown:
            cuilog.info("Hiding token")
            self.generated_token_field.configure(show='*')
            self.button_show_token.configure(text="Show Token")
            self.is_encrypted_token_shown = False
        else:
            cuilog.info("Showing token")
            self.generated_token_field.configure(show='')
            self.button_show_token.configure(text="Hide Token")
            self.is_encrypted_token_shown = True

    def show_encrypted_password(self):
        if not self.encrypted_password_var.get():
            return

        if self.is_encrypted_password_shown:
            cuilog.info("Hiding token")
            self.generated_encrypted_pass_field.configure(show='*')
            self.button_show_encrypted_password.configure(text="Show Password")
            self.is_encrypted_password_shown = False
        else:
            cuilog.info("Showing token")
            self.generated_encrypted_pass_field.configure(show='')
            self.button_show_encrypted_password.configure(text="Hide Password")
            self.is_encrypted_password_shown = True

    def do_decrypt(self):
        cuilog.info(f"Beginning decryption")

        token = self.token_input_field.get()
        encrypted_password = self.encrypted_pass_field.get()

        if not token and not encrypted_password:
            cuilog.warning(f"No token and encrypted password provided")
            self.reset_decryption_fields()
            return False


        # Decrypt
        session = Cryptor()
        session.set_salt(self.salt)
        decrypted = session.decrypt(token, encrypted_password)

        self.decrypted_password_var.set(utils.ensure_str(decrypted))

        cuilog.info(f"Decryption finished")

    def save_tokens_to_file(self) -> str:
        cuilog.info(f"Save tokens to file")

        file_suffix = "_tokens"

        file_path = Path.home()
        file_name = socket.gethostname() + "_tokens.txt"

        if "Windows" in platform.platform():
            cuilog.info(f"Platform is Windows")
            file_path = file_path / "Desktop"

        cuilog.info(f"Suggested file: {file_path / file_name}")

        tokens_file = cti.filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", ".txt")],
                                                       title="Save tokens file",
                                                       initialdir=file_path,
                                                       initialfile=file_name)

        # Add _tokens to file if not exists
        if file_suffix not in tokens_file:
            _path = Path(tokens_file).parent
            _name = Path(tokens_file).name
            cuilog.debug(f"Re-adding suffix '{file_suffix}' to file name {_name}")
            _suffix = Path(tokens_file).suffix
            _name = _name.replace(_suffix, "")

            _name += f"{file_suffix}{_suffix}"
            tokens_file = str(_path / _name)

        user_name = Path(tokens_file).name.replace("_tokens", '').replace(Path(tokens_file).suffix, "")
        cuilog.info(f"Generated User Name {user_name}")

        if tokens_file != file_suffix:
            with open(tokens_file, 'w') as f:
                f.write(f"[HOST]\n{user_name}\n\n"
                        f"[TOKEN]\n{utils.ensure_str(self.token_var.get())}\n\n"
                        f"[PASSWORD]\n{utils.ensure_str(self.encrypted_password_var.get())}")
            cuilog.info(f"Wrote {tokens_file}")
        else:
            cuilog.warning(f"Aborted. Returned tokens file: {tokens_file}")
            tokens_file = ''

        return tokens_file

    def set_salt_token(self) -> bytes:
        # Launch a prompt window
        dialog = cti.CTkInputDialog(text="New Salt Token:", title="Set Salt Token")
        _x = self.root.winfo_x() + int(self.root.winfo_width() / 6)
        _y = self.root.winfo_y() + int(self.root.winfo_height() / 5)
        dialog.geometry(f"+{_x}+{_y}")
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

        return utils.ensure_bytes(self.salt)

    def open_settings_gui(self):
        # Check if instanstiated
        if self.settings_gui is None:
            cuilog.info("Instantiating Settings Window")
            self.settings_gui = self.toplevel_settings_class(settings=self.settings)
        else:
            if not self.settings_gui.winfo_exists():
                cuilog.info("Settings Window existed but is closed. Re-instantiating")
                self.settings_gui = self.toplevel_settings_class(settings=self.settings)
            else:
                cuilog.info("Settings Window is visible")

        self.settings_gui.grab_set()

    def reset_encryption_fields(self):
        self.token_var.set('')
        self.encrypted_password_var.set('')
        self.encrypted_run_feedback_var.set(f"Ran on {utils.get_now()} - Reset fields")
        cuilog.info("Reset encryption fields")

    def reset_decryption_fields(self):
        self.token_input_field.configure(textvariable='')
        self.encrypted_pass_field.configure(textvariable='')
        self.decrypted_password_var.set('')
        cuilog.info("Reset decryption fields")

    def check_for_update(self):
        if not self.updater:
            return

        cuilog.info("Checking for Updates")
        with ThreadPoolExecutor() as executor:
            thread_update = executor.submit(self.updater.check_for_update)
        self.has_update = thread_update.result()

    def __label_update_available(self):
        cuilog.info("Binding Hyperlink Label")
        self.label_credits.configure(text="© r0fld4nc3 (Update available)", text_color="#769dff", cursor="hand2")
        self.label_credits.bind("<Button-1>", lambda e: webbrowser.open(f"http://www.github.com/{self.updater.repo}"))

    def __is_salt_fixed(self) -> bool:
        if self.SALT_FIXED:
            return True

        return False

    def __centre_window(self) -> None:
        # Credit https://stackoverflow.com/a/14912644

        # Requires a root to be present
        if not self.root:
            cuilog.error("No root specified")

        # Get X, Y using TKinters methods
        screen_width: int = self.root.winfo_screenwidth()  # width of the screen
        screen_height: int = self.root.winfo_screenheight()  # height of the screen

        cuilog.debug(f"Screen width: {screen_width}")
        cuilog.debug(f"Screen height: {screen_height}")

        root_width: int = self.window_size[0]
        root_height: int = self.window_size[1]

        x: int = int((screen_width / 2) - (root_width / 2))
        y: int = int((screen_height / 2) - (root_height / 2))

        # Set the dimensions of the screen and where it is placed
        self.root.geometry(f"{root_width}x{root_height}+{x}+{y}")

        if cuilog.level == 10:
            cuilog.info(f"Centering screen {root_width}x{root_height}+{x}+{y}")
        else:
            cuilog.info(f"Centering screen")


class CryptorSettingsUI(cti.CTkToplevel):
    FONT_ROBOTO = {"family": "Roboto", "size": 14}

    def __init__(self, settings=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not settings:
            self.settings = Settings()
            self.settings.load_config()
        else:
            self.settings = settings

        self.w_title = "Cryptor Settings"

        self.appearance = AppearanceMode.DARK.value
        self.theme = Theme.BLUE_DARK.value

        # Widgets of importance values
        self.save_file_on_encrypt_var = None
        self.check_for_updates_var = None

        # General
        self.w_size = (500, 400)
        self.offset_x = 50
        self.offset_y = 50
        self.main_font = cti.CTkFont(**self.FONT_ROBOTO)

        # ==============================
        # ============= UI =============
        # ==============================
        cuislog.info(f"Initialising UI elements")

        cti.set_appearance_mode(self.appearance)
        cti.set_default_color_theme(self.theme)

        self.title(self.w_title)
        self.geometry(f"{self.w_size[0]}x{self.w_size[1]}+{self.offset_x}+{self.offset_y}")

        # ============ MAIN FRAME ============
        main_frame = cti.CTkScrollableFrame(master=self, width=self.w_size[0] - 15,
                                            height=self.w_size[1] - 20,
                                            corner_radius=0, fg_color="transparent")
        main_frame.grid(row=0, column=0, sticky="nsew")

        # Radio Save On Hash
        self.save_file_on_encrypt_var = cti.IntVar()
        self.save_file_on_encrypt_var.set(int(self.settings.get_save_file_on_encrypt()))
        switch_save_on_hash = cti.CTkSwitch(master=main_frame,
                                            text="Save File on Encrypt",
                                            variable=self.save_file_on_encrypt_var,
                                            command=None,
                                            onvalue=True, offvalue=False)
        switch_save_on_hash.pack(pady=20)

        # Radio Check Updates on Startup
        self.check_for_updates_var = cti.IntVar()
        self.check_for_updates_var.set(int(self.settings.get_check_updates()))
        switch_check_for_updates = cti.CTkSwitch(master=main_frame,
                                            text="Check for updates",
                                            variable=self.check_for_updates_var,
                                            command=None,
                                            onvalue=True, offvalue=False)
        switch_check_for_updates.pack(pady=20)

        # Button Accept
        button_accept = cti.CTkButton(master=main_frame,
                                      text="Accept",
                                      command=self.accept_settings,
                                      font=self.main_font)
        button_accept.pack(pady=12)

        self.__centre_window()

    def accept_settings(self):
        self.settings.set_save_file_on_encrypt(self.save_file_on_encrypt_var.get())
        self.settings.set_check_updates(self.check_for_updates_var.get())
        self.destroy()

    def __centre_window(self) -> None:
        # Credit https://stackoverflow.com/a/14912644

        # Get X, Y using TKinters methods
        screen_width: int = self.winfo_screenwidth()  # width of the screen
        screen_height: int = self.winfo_screenheight()  # height of the screen

        cuislog.debug(f"Screen width: {screen_width}")
        cuislog.debug(f"Screen height: {screen_height}")

        root_width: int = self.w_size[0]
        root_height: int = self.w_size[1]

        x: int = int((screen_width / 2) - (root_width / 2)) + self.offset_x
        y: int = int((screen_height / 2) - (root_height / 2)) + self.offset_y

        # Set the dimensions of the screen and where it is placed
        self.geometry(f"{root_width}x{root_height}+{x}+{y}")

        if cuislog.level == 10:
            cuislog.info(f"Centering screen {root_width}x{root_height}+{x}+{y}")
        else:
            cuislog.info(f"Centering screen")


if __name__ == "__main__":
    ui = CryptorUI()
    ui.show()
