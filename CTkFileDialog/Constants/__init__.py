#!/usr/bin/env python
from pathlib import Path 
import os 

PWD        = str( Path.cwd() )
HOME       = str( Path.home() ) 
PATH       = os.getenv(key='PATH').split(sep=':')
TEMP       = os.getenv('TMPDIR') or os.getenv('TEMP') or os.getenv('TMP') or '/tmp'
CONFIG_DIR = os.getenv('XDG_CONFIG_HOME', str(Path(HOME) / '.config'))
CACHE_DIR  = os.getenv('XDG_CACHE_HOME', str(Path(HOME) / '.cache'))
DATA_DIR   = os.getenv('XDG_DATA_HOME', str(Path(HOME) / '.local' / 'share'))
PATHS = {
        "HOME": HOME,
        "PWD": PWD,
        "TEMP": TEMP,
        "CONFIG_DIR": CONFIG_DIR, 
        "DATA_DIR": DATA_DIR,
        "CACHE_DIR": CACHE_DIR,
        "PATH": PATH
        }
