"""
CyberRecon local development launcher.

Use this file only for local development.

Production deployments should use:

    gunicorn wsgi:app
"""

import os
import sys
from pathlib import Path

SRC_PATH = Path(__file__).resolve().parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from cyberrecon.app import create_app


app = create_app()


if __name__ == "__main__":
    debug_enabled = (
        os.environ.get(
            "CYBERRECON_DEBUG",
            "0",
        )
        == "1"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=debug_enabled,
    )