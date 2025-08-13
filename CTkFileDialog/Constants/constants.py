#!/usr/bin/env python
from pathlib import Path
import os

# Current working directory (e.g., where the program was launched)
PWD = str(Path.cwd())

# User's home directory (e.g., /home/user or C:\Users\user)
HOME = str(Path.home())

# System PATH split into a list of directories
PATH = os.getenv('PATH').split(os.pathsep)

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
