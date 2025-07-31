#!/usr/bin/env python3
"""
WSGI configuration for PythonAnywhere deployment.
"""

import sys
import os

# Add your project directory to the sys.path
path = '/home/yourusername/babylon-address-verifier'  # Update this path
if path not in sys.path:
    sys.path.insert(0, path)

from app import app as application

if __name__ == "__main__":
    application.run()