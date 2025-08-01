import os
import platform
import ctypes

def get_owner(path):
    system = platform.system()
    if system == "Windows":
        return get_owner_windows(path)
    elif system in ("Linux", "Darwin"):
        return get_owner_unix(path)
    else:
        return f"Plataforma no soportada: {system}"

# --- Windows ---
def get_owner_windows(path):
    import ctypes.wintypes as wintypes

    OWNER_SECURITY_INFORMATION = 0x00000001

    path = os.path.abspath(path)
    lpFileName = ctypes.c_wchar_p(path)

    needed = wintypes.DWORD(0)
    ctypes.windll.advapi32.GetFileSecurityW(lpFileName, OWNER_SECURITY_INFORMATION, None, 0, ctypes.byref(needed))

    if needed.value == 0:
        return "Error: no se pudo determinar el tamaño del descriptor"

    security_descriptor = ctypes.create_string_buffer(needed.value)
    if not ctypes.windll.advapi32.GetFileSecurityW(lpFileName, OWNER_SECURITY_INFORMATION, security_descriptor, needed, ctypes.byref(needed)):
        return "Error al obtener el descriptor de seguridad"

    pOwner = ctypes.c_void_p()
    ownerDefaulted = wintypes.BOOL()
    if not ctypes.windll.advapi32.GetSecurityDescriptorOwner(security_descriptor, ctypes.byref(pOwner), ctypes.byref(ownerDefaulted)):
        return "Error al obtener propietario"

    name_size = wintypes.DWORD(0)
    domain_size = wintypes.DWORD(0)
    sid_name_use = wintypes.DWORD()
    ctypes.windll.advapi32.LookupAccountSidW(None, pOwner, None, ctypes.byref(name_size), None, ctypes.byref(domain_size), ctypes.byref(sid_name_use))

    name = ctypes.create_unicode_buffer(name_size.value)
    domain = ctypes.create_unicode_buffer(domain_size.value)

    if not ctypes.windll.advapi32.LookupAccountSidW(None, pOwner, name, ctypes.byref(name_size), domain, ctypes.byref(domain_size), ctypes.byref(sid_name_use)):
        return "Error al buscar SID"

    return f"{domain.value}\\{name.value}" if domain.value else name.value

def get_owner_unix(path):
    import ctypes
    import ctypes.util
    import os

    libc_path = ctypes.util.find_library("c")
    if not libc_path:
        return "No se encontró libc"

    libc = ctypes.CDLL(libc_path, use_errno=True)

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

    class Passwd(ctypes.Structure):
        _fields_ = [
            ("pw_name", ctypes.c_char_p),
            ("pw_passwd", ctypes.c_char_p),
            ("pw_uid", ctypes.c_uint),
            ("pw_gid", ctypes.c_uint),
            ("pw_gecos", ctypes.c_char_p),
            ("pw_dir", ctypes.c_char_p),
            ("pw_shell", ctypes.c_char_p),
        ]

    libc.stat.argtypes = [ctypes.c_char_p, ctypes.POINTER(Stat)]
    libc.stat.restype = ctypes.c_int

    statbuf = Stat()

    # Validar ruta
    path_bytes = path.encode()
    if not os.path.exists(path):
        return f"Ruta inválida: {path}"

    # Llamar a stat
    if libc.stat(path_bytes, ctypes.byref(statbuf)) != 0:
        errno = ctypes.get_errno()
        return f"Error al hacer stat(): {os.strerror(errno)}"

    # Llamar a getpwuid
    libc.getpwuid.argtypes = [ctypes.c_uint]
    libc.getpwuid.restype = ctypes.POINTER(Passwd)

    pw_ptr = libc.getpwuid(statbuf.st_uid)

    # Protección fuerte contra puntero nulo
    if not pw_ptr:
        return f"UID sin nombre ({statbuf.st_uid})"

    try:
        pw_name = pw_ptr.contents.pw_name
        if not pw_name:
            return f"Nombre vacío para UID {statbuf.st_uid}"
        return pw_name.decode("utf-8", errors="replace")
    except Exception as e:
        return f"Error al decodificar nombre: {e}"

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
