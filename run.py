"""
run.py — single-command startup.

Usage:
    python run.py

The server starts on http://localhost:5000
"""

import sys
import os

# Make sure the project root is on the Python path so that
# `from backend.xxx import yyy` works from any working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import create_app

if __name__ == '__main__':
    app = create_app()
    print("\n🚀  ELFscope")
    print("   http://localhost:5000\n")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
