#!/usr/bin/env python
import os
import platform
import ctypes
from pathlib import Path

def find_owner(path) -> str:
    system = platform.system()
    path = str(path)

    if system == "Windows":
        return _get_windows_owner(path)
    else:
        return _get_unix_owner(path)
    
def _get_unix_owner(path: str) -> str:
    try:
        p = Path(path)
        return f"{p.owner()}"
    except Exception:
        return "unknown:unknown"

def _get_windows_owner(path: str) -> str:
    import ctypes
    from ctypes import wintypes

    GetNamedSecurityInfoW = ctypes.windll.advapi32.GetNamedSecurityInfoW
    LookupAccountSidW = ctypes.windll.advapi32.LookupAccountSidW
    LocalFree = ctypes.windll.kernel32.LocalFree

    OWNER_SECURITY_INFORMATION = 0x00000001
    SE_FILE_OBJECT = 1

    pSidOwner = ctypes.c_void_p()
    pSD = ctypes.c_void_p()

    result = GetNamedSecurityInfoW(
        ctypes.c_wchar_p(path),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        ctypes.byref(pSidOwner),
        None, None, None,
        ctypes.byref(pSD)
    )

    if result != 0:
        return "unknown"

    name = ctypes.create_unicode_buffer(256)
    domain = ctypes.create_unicode_buffer(256)
    name_size = wintypes.DWORD(len(name))
    domain_size = wintypes.DWORD(len(domain))
    sid_name_use = wintypes.DWORD()

    success = LookupAccountSidW(
        None,
        pSidOwner,
        name,
        ctypes.byref(name_size),
        domain,
        ctypes.byref(domain_size),
        ctypes.byref(sid_name_use)
    )

    LocalFree(pSD)

    if not success:
        return "unknown"

    return f"{name.value}"
