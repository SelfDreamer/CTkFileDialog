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
- VENV:       Path to the active Python virtual environment, or PWD if none is active.

Author: Flick
Repository: https://github.com/FlickGMD/CTkFileDialog
"""

from pathlib import Path
import os

# Current working directory (e.g., where the program was launched)
PWD = str(Path.cwd())

# User's home directory (e.g., /home/user or C:\Users\user)
HOME = str(Path.home())

# System PATH split into a list of directories
PATH = os.getenv('PATH').split(':')

# Temporary directory (fallback to /tmp if no env vars are set)
TEMP = os.getenv('TMPDIR') or os.getenv('TEMP') or os.getenv('TMP') 

# XDG-compliant user configuration directory (default: ~/.config)
CONFIG_DIR = os.getenv('XDG_CONFIG_HOME', str(Path(HOME) / '.config'))

# XDG-compliant user cache directory (default: ~/.cache)
CACHE_DIR = os.getenv('XDG_CACHE_HOME', str(Path(HOME) / '.cache'))

# XDG-compliant user data directory (default: ~/.local/share)
DATA_DIR = os.getenv('XDG_DATA_HOME', str(Path(HOME) / '.local' / 'share'))

# Active Python virtual environment (venv or conda), fallback to PWD 
VENV = os.getenv("VIRTUAL_ENV") or os.getenv("CONDA_PREFIX") or PWD

# All paths in a single dictionary for easy access
PATHS = {
    "HOME": HOME,
    "PWD": PWD,
    "TEMP": TEMP,
    "CONFIG_DIR": CONFIG_DIR,
    "DATA_DIR": DATA_DIR,
    "CACHE_DIR": CACHE_DIR,
    "PATH": PATH, 
    'VENV': VENV
}
