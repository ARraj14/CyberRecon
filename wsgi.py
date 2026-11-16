"""
CyberRecon production WSGI entry point.

Production WSGI servers such as Gunicorn import
the Flask application from this module.
"""

import sys
from pathlib import Path

SRC_PATH = Path(__file__).resolve().parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from cyberrecon.app import create_app


app = create_app()