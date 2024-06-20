import os
import pathlib
import platform

Path = pathlib.Path

G_LOG_LEVEL = 1
G_THREAD_NUM_WORKERS = 2

HOST: str = "r0fld4nc3"
APP_FOLDER: str = "Apps"
APP_NAME: str = "cryptor"

system = platform.system().lower()
if "windows" in system:
    print("Target System Windows")
    program_data_path = os.getenv("LOCALAPPDATA")
elif "linux" in system or "unix" in system:
    print("Target System Linux/Unix")
    program_data_path = Path(os.path.expanduser('~')) / ".local/share/"
elif "darwin" in system or "mac" in system:
    print("Target System MacOS")
    # Write to user-writable locations, like ~/.local/share/
    program_data_path = Path(os.path.expanduser('~')) / ".local/share/"
else:
    print("Target System Other")
    print(system)
    program_data_path = Path.cwd()

config_folder = Path(program_data_path) / HOST / APP_FOLDER / APP_NAME

print(f"Config folder: {config_folder}")