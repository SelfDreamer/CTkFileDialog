"""
This module is part of the CTkFileDialog library.

It defines system path constants that point to useful directories such as the 
user's home, config, cache, and data folders, as well as the system PATH and temp directory.

These constants follow the XDG Base Directory Specification where possible,
and serve as a utility for file dialogs and other filesystem operations within the library.

Available constants:

- PWD:        Current working directory where the program was launched.
- HOME:       User's home directory.
- TEMP:       Temporary directory, resolved from common environment variables or defaulting to /tmp.
- CONFIG_DIR: XDG-compliant user configuration directory (e.g., ~/.config).
- CACHE_DIR:  XDG-compliant user cache directory (e.g., ~/.cache).
- DATA_DIR:   XDG-compliant user data directory (e.g., ~/.local/share).
- PATH:       List of directories in the system PATH environment variable.
- VENV:       Path to the active Python virtual environment (VIRTUAL_ENV or CONDA_PREFIX).

Author: Flick
Repository: https://github.com/FlickGMD/CTkFileDialog
"""

from .constants import PWD, HOME, PATH, TEMP, CONFIG_DIR, CACHE_DIR, DATA_DIR, VENV, PATHS

__all__ = [
        'PWD',
        'HOME',
        'PATH',
        'TEMP',
        'CACHE_DIR',
        'CONFIG_DIR',
        'DATA_DIR',
        'VENV',
        'PATHS',
        ]
