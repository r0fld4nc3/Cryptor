import datetime
from typing import Union

def get_now():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def ensure_bytes(obj: Union[str, bytes]) -> bytes:
    if not isinstance(obj, bytes):
        obj = obj.encode("utf-8")
    return obj

def ensure_str(obj) -> str:
    if isinstance(obj, bytes):
        obj = obj.decode()
    else:
        obj = str(obj)

    return obj