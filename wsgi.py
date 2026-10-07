"""
CyberRecon production WSGI entry point.

Production WSGI servers such as Gunicorn import
the Flask application from this module.
"""

from cyberrecon.app import create_app


app = create_app()