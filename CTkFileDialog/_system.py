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

def get_permissions(path):
    system = platform.system()
    if system == "Windows":
        return get_permissions_windows(path)
    elif system in ("Linux", "Darwin"):
        return get_permissions_unix(path)
    else:
        return f"Plataforma no soportada: {system}"

# --- Linux/macOS ---
def get_permissions_unix(path):
    import ctypes.util

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    class Stat(ctypes.Structure):
        _fields_ = [
            ("st_dev", ctypes.c_ulong),
            ("st_ino", ctypes.c_ulong),
            ("st_nlink", ctypes.c_ulong),
            ("st_mode", ctypes.c_uint),
            ("st_uid", ctypes.c_uint),
            ("st_gid", ctypes.c_uint),
            ("st_rdev", ctypes.c_ulong),
            ("st_size", ctypes.c_long),
            ("st_blksize", ctypes.c_long),
            ("st_blocks", ctypes.c_long),
            ("st_atime", ctypes.c_long),
            ("st_mtime", ctypes.c_long),
            ("st_ctime", ctypes.c_long),
        ]

    libc.stat.argtypes = [ctypes.c_char_p, ctypes.POINTER(Stat)]
    libc.stat.restype = ctypes.c_int

    statbuf = Stat()
    if libc.stat(path.encode(), ctypes.byref(statbuf)) != 0:
        err = ctypes.get_errno()
        return f"Error al obtener stat: {os.strerror(err)}"

    mode = statbuf.st_mode

    # Construir permisos como string estilo ls -l
    def mode_to_string(mode):
        perms = ['-'] * 10

        if os.path.isdir(path):
            perms[0] = 'd'

        perm_flags = [
            (0o400, 'r'), (0o200, 'w'), (0o100, 'x'),  # user
            (0o040, 'r'), (0o020, 'w'), (0o010, 'x'),  # group
            (0o004, 'r'), (0o002, 'w'), (0o001, 'x'),  # others
        ]

        for i, (bit, char) in enumerate(perm_flags):
            if mode & bit:
                perms[i+1] = char

        return ''.join(perms)

    return mode_to_string(mode)

# --- Windows (simplificado) ---
def get_permissions_windows(path):
    FILE_ATTRIBUTE_READONLY = 0x01

    attrs = ctypes.windll.kernel32.GetFileAttributesW(ctypes.c_wchar_p(path))
    if attrs == -1:
        return "Error al obtener atributos"

    readonly = bool(attrs & FILE_ATTRIBUTE_READONLY)

    can_read = True
    can_write = not readonly
    can_exec = path.lower().endswith(('.exe', '.bat', '.cmd', '.com'))

    return f"{'r' if can_read else '-'}{'w' if can_write else '-'}{'x' if can_exec else '-'}"

if __name__ == "__main__":
    p = get_permissions('/etc/hosts')

    print(p)
