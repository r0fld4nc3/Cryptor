import pathlib
import socket
import platform
import webbrowser
from time import sleep
from typing import Union

import customtkinter as ctk
import tkinter as tk

from conf_globals.globals import G_LOG_LEVEL
import utils
from ui.gui_utils import AppearanceMode, Theme, version_from_tuple, centre_window, get_custom_theme
from cryptor.cryptor import Cryptor
from settings import Settings
from logs import create_logger
from updater import Updater

log = create_logger("CryptorUI", G_LOG_LEVEL)
settingslog = create_logger("CryptorSettingsUI", G_LOG_LEVEL)

Path = pathlib.Path

class CryptorUI:
    _app_version = 'v' + ".".join([str(v) for v in Cryptor.VERSION[0:3]])
    if len(Cryptor.VERSION) > 3:
        _app_version += "-"
        _app_version += "-".join(str(v) for v in Cryptor.VERSION[3:])
    FONT_SIZE = 14
    FONT_ROBOTO = {"family": "Roboto", "size": FONT_SIZE}
    FONT_ROBOTO_BOLD = {"family": "Roboto", "size": FONT_SIZE, "weight": "bold"}
    # If this value is anything but empty, it will ignore settings and use this predefined token
    SALT_FIXED: bytes = ''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Settings
        self.settings = Settings()
        self.settings.load_config()
        self.settings.set_app_version(version_from_tuple(Cryptor.VERSION))
        self.toplevel_settings_class = CryptorSettingsUI
        self.settings_gui = None

        self.task_queue = utils.ThreadedQueue()
        self.task_queue.start_workers()

        # General - Tkinter
        self.root: Union[None, ctk.CTk] = None
        self.font_roboto: Union[None, ctk.CTkFont] = None
        self.font_roboto_bold: Union[None, ctk.CTkFont] = None
        self.screen_x: int = 0
        self.screen_y: int = 0
        # SALT should control the fixed salt token
        # If it is set to empty, then it will be user defined (file -> set salt token)
        # If it is filled, then it will disregard whatever the settings use and use the fixed token
        if self.__is_salt_fixed():
            log.debug("Salt token is predefined. Will ignore from settings")
            self.salt: bytes = self.SALT_FIXED
        else:
            self.salt: bytes = self.settings.get_salt_token()
            log.debug(f"Salt token is not predefined. Will use from settings {self.salt.decode()}")

        self.title = "Cryptor %VERSION%".replace("%VERSION%", version_from_tuple(Cryptor.VERSION))
        self.theme_selections = {
            "Dark Blue": [AppearanceMode.DARK.value, Theme.BLUE_DARK.value],
            "Light Blue": [AppearanceMode.LIGHT.value, Theme.BLUE.value],
            "Dark Green": [AppearanceMode.DARK.value, Theme.GREEN.value],
            "Light Green": [AppearanceMode.LIGHT.value, Theme.GREEN.value],
        }
        self.user_theme = self.settings.get_theme()
        self.col_light_green: str = "#2CC985"
        self.col_dark_green: str = "#2FA572"
        self.col_light_blue: str = "#3B8ED0"
        self.col_dark_blue: str = "#1F538D"
        self.col_btn_hover_blue: str = "#36719F"
        self.col_btn_hover_green: str = "#0C955A"

        # Updater
        self.check_update_cooldown = 60 * 30  # seconds
        self.has_update: bool = False
        self.updater: Union[Updater, None] = None
        if self.settings.get_check_for_updates():
            self.updater = Updater("r0fld4nc3", "Cryptor")
            self.updater.set_local_version(self._app_version)
            self.task_queue.add_task(self.check_for_update)

        self.window_size = (500, 400)

        self.tab_encrypt = "Encrypt"
        self.tab_decrypt = "Decrypt"
        self.tab_from_file = "From File"

        # Widgets of importance values
        self.label_credits = None
        self.tabview = None
        # Tab Encrypt
        self.button_encrypt = None
        self.button_copy_token = None
        self.button_copy_encrypted_password = None
        self.password_input_field = None
        self.generated_token_field = None
        self.generated_encrypted_pass_field = None
        self.button_show_encrypted_password = None
        # Tab Decrypt
        self.button_decrypt = None
        self.button_copy_decrypted_password = None
        self.token_input_field = None
        self.encrypted_pass_field = None
        self.decrypted_pass_field = None
        self.button_show_token = None
        self.button_show_decrypted_password = None
        self.combobox_theme = None
        # Menubar
        self.menu_file = None

        # Vars that hold display info
        self.token_var: Union[ctk.StringVar, str] = ''  # These need to be defined later becase there is not root Tkinter window
        self.encrypted_password_var: Union[ctk.StringVar, str] = ''  # These need to be defined later becase there is not root Tkinter window
        self.decrypted_password_var: Union[ctk.StringVar, str] = ''  # These need to be defined later becase there is not root Tkinter window
        self.encrypted_run_feedback_var = None

        self.is_encrypted_token_shown = False
        self.is_encrypted_password_shown = False
        self.is_decrypted_password_shown = False

        log.info(f"{self.title}")

    def show(self):
        log.info(f"Initialising UI elements")

        self.set_theme(self.settings.get_theme())

        self.root = ctk.CTk()
        self.root.geometry(f"{self.window_size[0]}x{self.window_size[1]}")
        self.root.title(self.title)

        # Menu Bar
        menu_bar = tk.Menu(self.root, background="#212121", foreground="white",
                           activebackground="#212121", activeforeground="white")
        self.root.config(menu=menu_bar)

        # File Menu
        # Only add if we need it. May change in the future, as things need to be added regardless of fixed salt
        self.menu_file = tk.Menu(menu_bar, tearoff=False, background="#212121", foreground="white")
        if not self.__is_salt_fixed():
            self.menu_file.add_command(label="Set Salt Token", command=self.set_salt_token)
        self.menu_file.add_command(label="Settings", command=self.open_settings_gui)
        self.menu_file.add_separator()
        self.menu_file.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=self.menu_file)

        self.font_roboto = ctk.CTkFont(**self.FONT_ROBOTO)

        frame = ctk.CTkFrame(master=self.root, fg_color="transparent")
        frame.pack(fill="both", expand=True)

        self.tabview = ctk.CTkTabview(master=frame, width=500, fg_color="transparent")
        self.tabview.grid(row=0, column=2, padx=(20, 0), pady=(20, 0), sticky="nsew")

        # ============================================= TAB ENCRYPT ===================================================
        self.tabview.add(self.tab_encrypt)
        self.tabview.tab(self.tab_encrypt)

        # Password Input Field
        self.password_input_field = ctk.CTkEntry(master=self.tabview.tab(self.tab_encrypt),
                                                 placeholder_text="Password",
                                                 width=500,
                                                 font=self.font_roboto)
        self.password_input_field.pack(padx=10, pady=0)

        self.encrypted_run_feedback_var = ctk.StringVar()
        # Button Begin Encrypt
        self.button_encrypt = ctk.CTkButton(master=self.tabview.tab(self.tab_encrypt),
                                       text="Encrypt",
                                       command=self.do_encrypt,
                                       font=self.font_roboto)
        self.button_encrypt.pack(padx=(6, 3), pady=12, side=ctk.TOP, expand=False, fill=ctk.X)

        # Token Field
        self.token_var = ctk.StringVar()
        self.generated_token_field = ctk.CTkEntry(master=self.tabview.tab(self.tab_encrypt),
                                                  textvariable=self.token_var,
                                                  show='*',
                                                  width=500,
                                                  font=self.font_roboto)
        self.generated_token_field.configure(state="disabled")
        self.generated_token_field.pack(padx=10, pady=12)

        # Copy/Show Token Buttons Frame
        frame_btns_copy_show_encrypted_token = ctk.CTkFrame(master=self.tabview.tab(self.tab_encrypt), fg_color="transparent")
        frame_btns_copy_show_encrypted_token.pack(fill="x", padx=50, pady=0)

        # Copy Token Button
        self.button_copy_token = ctk.CTkButton(master=frame_btns_copy_show_encrypted_token,
                                               text="Copy Token",
                                               command=self.copy_token,
                                               font=self.font_roboto)

        # Show Token Button
        self.button_show_token = ctk.CTkButton(master=frame_btns_copy_show_encrypted_token,
                                               text="Show Token",
                                               command=self.show_token,
                                               font=self.font_roboto)
        self.button_copy_token.pack(padx=(0, 6), side=ctk.LEFT, expand=True, fill=ctk.X)
        self.button_show_token.pack(padx=(6, 0), side=ctk.LEFT, expand=True, fill=ctk.X)

        # Encrypted Password Field
        self.encrypted_password_var = ctk.StringVar()
        self.generated_encrypted_pass_field = ctk.CTkEntry(master=self.tabview.tab(self.tab_encrypt),
                                                           textvariable=self.encrypted_password_var,
                                                           show='*',
                                                           width=500,
                                                           font=self.font_roboto)
        self.generated_encrypted_pass_field.configure(state="disabled")
        self.generated_encrypted_pass_field.pack(padx=10, pady=12)

        # Copy/Show Token Buttons Frame
        frame_btns_copy_show_encrypted_pw = ctk.CTkFrame(master=self.tabview.tab(self.tab_encrypt), fg_color="transparent")
        frame_btns_copy_show_encrypted_pw.pack(fill="x", padx=50, pady=0)

        # Copy Encrypted Password Button
        self.button_copy_encrypted_password = ctk.CTkButton(master=frame_btns_copy_show_encrypted_pw,
                                                            text="Copy Password",
                                                            command=self.copy_encrypted_password,
                                                            font=self.font_roboto)

        # Show Encrypted Password Button
        self.button_show_encrypted_password = ctk.CTkButton(master=frame_btns_copy_show_encrypted_pw,
                                                            text="Show Password",
                                                            command=self.show_encrypted_password,
                                                            font=self.font_roboto)

        self.button_copy_encrypted_password.pack(padx=(0, 6), side=ctk.LEFT, expand=True, fill=ctk.X)
        self.button_show_encrypted_password.pack(padx=(6, 0), side=ctk.LEFT, expand=True, fill=ctk.X)

        # Set and Pack info label for run status
        encrypt_run_status = ctk.CTkLabel(master=self.tabview.tab(self.tab_encrypt),
                                          textvariable=self.encrypted_run_feedback_var,
                                          font=self.font_roboto)
        encrypt_run_status.pack(side=ctk.BOTTOM, expand=True, fill=ctk.X)

        # ============================================= TAB DECRYPT ===================================================
        self.tabview.add(self.tab_decrypt)
        self.tabview.tab(self.tab_decrypt)

        # Token Input Field
        self.token_input_field = ctk.CTkEntry(master=self.tabview.tab(self.tab_decrypt),
                                              placeholder_text="Please supply a Token",
                                              width=500,
                                              font=self.font_roboto)
        self.token_input_field.pack(padx=10, pady=6)

        # Password Input Field
        self.encrypted_pass_field = ctk.CTkEntry(master=self.tabview.tab(self.tab_decrypt),
                                                 placeholder_text="Please supply an Encrypted Password",
                                                 width=500,
                                                 font=self.font_roboto)
        self.encrypted_pass_field.pack(padx=10, pady=0)

        # Button Begin Decrypt
        self.button_decrypt = ctk.CTkButton(master=self.tabview.tab(self.tab_decrypt),
                                       text="Decrypt",
                                       command=self.do_decrypt,
                                       font=self.font_roboto)
        self.button_decrypt.pack(padx=0, pady=12)

        # Decrypted Password Field
        self.decrypted_password_var = ctk.StringVar()
        self.decrypted_pass_field = ctk.CTkEntry(master=self.tabview.tab(self.tab_decrypt),
                                                 textvariable=self.decrypted_password_var,
                                                 width=500,
                                                 font=self.font_roboto,
                                                 show="*")
        self.decrypted_pass_field.pack(padx=10, pady=0)

        frame_btns_copy_show_decrypted_pw = ctk.CTkFrame(master=self.tabview.tab(self.tab_decrypt), fg_color="transparent")
        frame_btns_copy_show_decrypted_pw.pack(fill="x", padx=50, pady=10)

        # Button Copy Decrypted Password
        self.button_copy_decrypted_password = ctk.CTkButton(master=frame_btns_copy_show_decrypted_pw,
                                                       text="Copy Password",
                                                       command=self.copy_decrypted_password,
                                                       font=self.font_roboto)

        # Button Show Decrypted Password
        self.button_show_decrypted_password = ctk.CTkButton(master=frame_btns_copy_show_decrypted_pw,
                                                            text="Show Password",
                                                            command=self.show_decrypted_password,
                                                            font=self.font_roboto)

        self.button_copy_decrypted_password.pack(padx=(0, 6), side=ctk.LEFT, expand=True, fill=ctk.X)
        self.button_show_decrypted_password.pack(padx=(6, 0), side=ctk.LEFT, expand=True, fill=ctk.X)

        # ============================================ TAB FROM FILES ==================================================
        self.tabview.add(self.tab_from_file)
        self.tabview.pack(padx=10, pady=12)

        label_wip = ctk.CTkLabel(master=self.tabview.tab(self.tab_from_file),
                                 text="Under construction",
                                 text_color="Yellow",
                                 font=self.font_roboto)
        label_wip.pack(padx=0, pady=12)

        # ============================================== COMBOBOX THEME ==============================================
        label_theme_combobox = ctk.CTkLabel(master=frame, font=self.font_roboto, text="Theme")
        self.combobox_theme = ctk.CTkComboBox(master=frame,
                                              font=self.font_roboto,
                                              dropdown_font=self.font_roboto,
                                              values=list(self.theme_selections.keys()),
                                              command=self._theme_apply_callback)

        label_theme_combobox.pack(padx=(10, 10), pady=(0, 10), side=ctk.LEFT, expand=False, fill=ctk.X)
        self.combobox_theme.pack(padx=(10, 10), pady=(0, 10), side=ctk.LEFT, expand=False, fill=ctk.X)
        self.combobox_theme.set(self.user_theme)
        # =============================================================================================================

        # ================================================== CREDITS ==================================================
        self.label_credits = ctk.CTkLabel(master=frame,
                                          text="© r0fld4nc3",
                                          font=self.font_roboto)
        self.label_credits.pack()

        self._set_themed_elements()

        centre_window(self.root, self.window_size[0], self.window_size[1])

        log.info(f"Running mainloop")

        self.root.mainloop()

        # TODO: Why does this run everytime we accept the salt token
        self.settings.save_config()

        self.task_queue.stop_workers()

        log.info("Shutdown")

    def do_encrypt(self) -> bool:
        log.info(f"Encrypting")
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

        log.info("Encryption finished")

        if self.settings.get_save_file_on_encrypt():
            saved_file = self.save_tokens_to_file()
            if not saved_file:
                self.encrypted_run_feedback_var.set(f"Ran on {utils.get_now()} - WARNING: No file saved")
            else:
                self.encrypted_run_feedback_var.set(f"Ran on {utils.get_now()}")
        else:
             self.encrypted_run_feedback_var.set(f"Ran on {utils.get_now()}")

        return True

    def copy_token(self) -> None:
        if self.token_var.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(utils.ensure_str(self.token_var.get()))
            log.info(f"Copied token to clipboard")
        else:
            log.warning(f"No token to copy to clipboard")

    def copy_encrypted_password(self) -> None:
        if self.encrypted_password_var.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(utils.ensure_str(self.encrypted_password_var.get()))
            log.info(f"Copied encrypted password to clipboard")
        else:
            log.warning(f"No encrypted password to copy to clipboard")

    def copy_decrypted_password(self) -> None:
        if self.decrypted_password_var:
            self.root.clipboard_clear()
            self.root.clipboard_append(utils.ensure_str(self.decrypted_password_var.get()))
            log.info(f"Copied decrypted password to clipboard")
        else:
            log.warning(f"No decrypted password to copy to clipboard")

    def show_decrypted_password(self) -> None:
        if not self.decrypted_password_var.get():
            return

        if self.is_decrypted_password_shown:
            log.info("Hiding decrypted password")
            self.decrypted_pass_field.configure(show='*')
            self.button_show_decrypted_password.configure(text="Show Password")
            self.is_decrypted_password_shown = False
        else:
            log.info("Showing decrypted password")
            self.decrypted_pass_field.configure(show='')
            self.button_show_decrypted_password.configure(text="Hide Password")
            self.is_decrypted_password_shown = True

    def show_token(self) -> None:
        if not self.token_var.get():
            return

        if self.is_encrypted_token_shown:
            log.info("Hiding token")
            self.generated_token_field.configure(show='*')
            self.button_show_token.configure(text="Show Token")
            self.is_encrypted_token_shown = False
        else:
            log.info("Showing token")
            self.generated_token_field.configure(show='')
            self.button_show_token.configure(text="Hide Token")
            self.is_encrypted_token_shown = True

    def show_encrypted_password(self) -> None:
        if not self.encrypted_password_var.get():
            return

        if self.is_encrypted_password_shown:
            log.info("Hiding token")
            self.generated_encrypted_pass_field.configure(show='*')
            self.button_show_encrypted_password.configure(text="Show Password")
            self.is_encrypted_password_shown = False
        else:
            log.info("Showing token")
            self.generated_encrypted_pass_field.configure(show='')
            self.button_show_encrypted_password.configure(text="Hide Password")
            self.is_encrypted_password_shown = True

    def do_decrypt(self) -> bool:
        log.info(f"Beginning decryption")

        token = self.token_input_field.get()
        encrypted_password = self.encrypted_pass_field.get()

        if not token and not encrypted_password:
            log.warning(f"No token and encrypted password provided")
            self.reset_decryption_fields()
            return False


        # Decrypt
        session = Cryptor()
        session.set_salt(self.salt)
        decrypted = session.decrypt(token, encrypted_password)

        self.decrypted_password_var.set(utils.ensure_str(decrypted))

        log.info(f"Decryption finished")

        return True

    def save_tokens_to_file(self) -> str:
        log.info(f"Save tokens to file")

        file_suffix = "_tokens"

        file_path = Path.home()
        file_name = socket.gethostname() + "_tokens.txt"

        if "Windows" in platform.platform():
            log.info(f"Platform is Windows")
            file_path = file_path / "Desktop"

        log.info(f"Suggested file: {file_path / file_name}")

        tokens_file = ctk.filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", ".txt")],
                                                       title="Save tokens file",
                                                       initialdir=file_path,
                                                       initialfile=file_name)

        # Add _tokens to file if not exists
        if file_suffix not in tokens_file:
            _path = Path(tokens_file).parent
            _name = Path(tokens_file).name
            log.debug(f"Re-adding suffix '{file_suffix}' to file name {_name}")
            _suffix = Path(tokens_file).suffix
            _name = _name.replace(_suffix, "")

            _name += f"{file_suffix}{_suffix}"
            tokens_file = str(_path / _name)

        user_name = Path(tokens_file).name.replace("_tokens", '').replace(Path(tokens_file).suffix, "")
        log.info(f"Generated User Name {user_name}")

        if tokens_file != file_suffix:
            with open(tokens_file, 'w') as f:
                f.write(f"[HOST]\n{user_name}\n\n"
                        f"[TOKEN]\n{utils.ensure_str(self.token_var.get())}\n\n"
                        f"[PASSWORD]\n{utils.ensure_str(self.encrypted_password_var.get())}")
            log.info(f"Wrote {tokens_file}")
        else:
            log.warning(f"Aborted. Returned tokens file: {tokens_file}")
            tokens_file = ''

        return tokens_file

    def set_salt_token(self) -> bytes:
        # Launch a prompt window
        dialog = ctk.CTkInputDialog(text="New Salt Token:", title="Set Salt Token")
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
            log.info("Instantiating Settings Window")
            self.settings_gui = self.toplevel_settings_class(settings=self.settings)
        else:
            if not self.settings_gui.winfo_exists():
                log.info("Settings Window existed but is closed. Re-instantiating")
                self.settings_gui = self.toplevel_settings_class(settings=self.settings)
            else:
                log.info("Settings Window is visible")

        self.settings_gui.grab_set()

    def reset_encryption_fields(self) -> None:
        self.token_var.set('')
        self.encrypted_password_var.set('')
        self.encrypted_run_feedback_var.set(f"Ran on {utils.get_now()} - Reset fields")
        log.info("Reset encryption fields")

    def reset_decryption_fields(self) -> None:
        self.token_input_field.configure(textvariable='')
        self.encrypted_pass_field.configure(textvariable='')
        self.decrypted_password_var.set('')
        log.info("Reset decryption fields")

    def check_for_update(self) -> bool:
        sleep(2)
        log.info("Checking for Updates")

        # Check today's date and last checked date
        do_check = False
        now = utils.get_now(ts=True)
        last_checked = self.settings.get_last_checked_update()

        if now >= last_checked + self.check_update_cooldown:
            do_check = True

        log.info(f"Today: {now} | Last:  {last_checked} | {do_check}")

        if do_check:
            self.has_update = self.updater.check_for_update()
            self.settings.set_last_checked_update(now)

        if self.has_update:
            self.__label_update_available()

        return self.has_update

    def set_theme(self, theme_name: str):
        theme_name = get_custom_theme(theme_name)

        if not theme_name:
            theme_name = list(self.theme_selections.keys())[0]

        log.info(f"Set theme {theme_name}")

        appearance, theme = self.theme_selections.get(theme_name)
        ctk.set_appearance_mode(appearance)
        ctk.set_default_color_theme(theme)

        self.settings.set_theme(theme_name)

    def _theme_apply_callback(self, choice):
        settingslog.debug(f"Theme combobox selected: {choice} {self.theme_selections[choice][1]}")
        self.set_theme(choice)
        self.user_theme = choice

        self._set_themed_elements()

    def _set_themed_elements(self):
        theme = self.user_theme.lower()

        if "blue" in theme:
            if "dark" in theme:
                text_col = "White"
                fg_col = self.col_dark_blue
                button_hover_col = self.col_btn_hover_blue
                dropdown_hover_col = self.col_dark_blue
                dropdown_text_col = "White"
                menu_bar_text_col = "White"
                menu_bar_bg_col = self.col_dark_blue
            else:
                text_col = "White"
                fg_col = self.col_light_blue
                button_hover_col = self.col_btn_hover_blue
                dropdown_hover_col = self.col_light_blue
                dropdown_text_col = "Black"
                menu_bar_text_col = "Black"
                menu_bar_bg_col = "White"
        elif "green" in theme:
            if "dark" in theme:
                text_col = "White"
                fg_col = self.col_dark_green
                button_hover_col = self.col_btn_hover_green
                dropdown_hover_col = self.col_dark_green
                dropdown_text_col = "White"
                menu_bar_text_col = "White"
                menu_bar_bg_col = self.col_dark_green
            else:
                text_col = "Black"
                fg_col = self.col_light_green
                button_hover_col = self.col_btn_hover_green
                dropdown_hover_col = self.col_light_green
                dropdown_text_col = "Black"
                menu_bar_text_col = "Black"
                menu_bar_bg_col = self.col_light_green
        else:
            text_col = "White"
            fg_col = "Light Pink"
            button_hover_col = "Pink"
            dropdown_hover_col = "Light Pink"
            dropdown_text_col = "Pink"
            menu_bar_text_col = "White"
            menu_bar_bg_col = "Pink"

        self.tabview.configure(text_color=text_col, segmented_button_selected_color=fg_col)
        self.button_encrypt.configure(text_color=text_col, fg_color=fg_col, hover_color=button_hover_col)
        self.button_copy_token.configure(text_color=text_col, fg_color=fg_col, hover_color=button_hover_col)
        self.button_show_token.configure(text_color=text_col, fg_color=fg_col, hover_color=button_hover_col)
        self.button_copy_encrypted_password.configure(text_color=text_col, fg_color=fg_col, hover_color=button_hover_col)
        self.button_show_encrypted_password.configure(text_color=text_col, fg_color=fg_col, hover_color=button_hover_col)
        self.button_decrypt.configure(text_color=text_col, fg_color=fg_col, hover_color=button_hover_col)
        self.button_copy_decrypted_password.configure(text_color=text_col, fg_color=fg_col, hover_color=button_hover_col)
        self.button_show_decrypted_password.configure(text_color=text_col, fg_color=fg_col, hover_color=button_hover_col)

        self.combobox_theme.configure(border_color=fg_col, button_color=fg_col,
                                      dropdown_hover_color=dropdown_hover_col, dropdown_text_color=dropdown_text_col,
                                      state="readonly")

        # Menu Bar
        self.menu_file.configure(background=menu_bar_bg_col, foreground=menu_bar_text_col)

        # Settings GUI
        if self.settings_gui:
            self.settings_gui.switch_check_for_updates.configure(text_color=text_col)

    def __label_update_available(self) -> None:
        log.info("Binding Hyperlink Label")
        self.label_credits.configure(text="© r0fld4nc3 (Update available)", text_color="#769dff", cursor="hand2")
        self.label_credits.bind("<Button-1>", lambda e: webbrowser.open(f"http://www.github.com/{self.updater.repo}"))

    def __is_salt_fixed(self) -> bool:
        if self.SALT_FIXED:
            return True

        return False


class CryptorSettingsUI(ctk.CTkToplevel):
    FONT_ROBOTO = {"family": "Roboto", "size": 14}
    SETTING_BG_COLOUR = "#343638"

    def __init__(self, settings=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not settings:
            self.settings = Settings()
            self.settings.load_config()
        else:
            self.settings = settings

        self.w_title = "Cryptor Settings"

        # Widgets of importance values
        self.save_file_on_encrypt_var = None
        self.check_for_updates_var = None

        # General
        self.w_size = (300, 400)
        self.offset_x = 50
        self.offset_y = 50
        self.main_font = ctk.CTkFont(**self.FONT_ROBOTO)

        # ==============================
        # ============= ui =============
        # ==============================
        settingslog.info(f"Initialising UI elements")

        self.title(self.w_title)
        self.geometry(f"{self.w_size[0]}x{self.w_size[1]}+{self.offset_x}+{self.offset_y}")

        # ============ MAIN FRAME ============
        main_frame = ctk.CTkFrame(master=self, width=self.w_size[0] - 15,
                                  height=self.w_size[1] - 20,
                                  corner_radius=0, fg_color="transparent")
        main_frame.pack(side="left", fill="both", expand=True, padx=10)

        scroll_frame = ctk.CTkScrollableFrame(master=main_frame, width=self.w_size[0] - 15,
                                              height=self.w_size[1] - 20,
                                              corner_radius=0, fg_color="transparent")
        scroll_frame.grid(row=0, column=0, sticky="nsew")
        # Adjust the padding of the scrollbar by adding an empty column to the left of the scrollbar
        main_frame.grid_columnconfigure(0, weight=1)  # Allow the scrollbar column to expand
        scroll_frame.grid_columnconfigure(1, minsize=5)  # Add an empty column for padding
        scrollbar = scroll_frame._scrollbar
        scrollbar.grid(row=1, column=2, sticky="ns")  # Adjust the column index as needed

        # Radio Save On Hash
        self.save_file_on_encrypt_var = ctk.IntVar()
        self.save_file_on_encrypt_var.set(int(self.settings.get_save_file_on_encrypt()))
        switch_save_on_hash = ctk.CTkSwitch(master=scroll_frame,
                                            text="Save File on Encrypt",
                                            variable=self.save_file_on_encrypt_var,
                                            command=None,
                                            onvalue=True, offvalue=False,
                                            bg_color=CryptorSettingsUI.SETTING_BG_COLOUR)
        switch_save_on_hash.pack(fill="both", expand=True, pady=20)

        # Radio Check Updates on Startup
        self.check_for_updates_var = ctk.IntVar()
        self.check_for_updates_var.set(int(self.settings.get_check_for_updates()))
        switch_check_for_updates = ctk.CTkSwitch(master=scroll_frame,
                                                 text="Check for updates",
                                                 variable=self.check_for_updates_var,
                                                 command=None,
                                                 onvalue=True, offvalue=False,
                                                 bg_color=CryptorSettingsUI.SETTING_BG_COLOUR)
        switch_check_for_updates.pack(fill="both", expand=True)

        # Button Accept
        self.button_accept = ctk.CTkButton(master=scroll_frame,
                                      text="Accept",
                                      command=self.accept_settings,
                                      font=self.main_font)
        self.button_accept.pack(pady=20)

        centre_window(self, self.w_size[0], self.w_size[1])

    def accept_settings(self) -> None:
        self.settings.set_save_file_on_encrypt(self.save_file_on_encrypt_var.get())
        self.settings.set_check_for_updates(self.check_for_updates_var.get())
        self.destroy()


if __name__ == "__main__":
    ui = CryptorUI()
    ui.show()
