"""
Standalone Isolated Sandbox Engine Microservice Runner
Runs on a separate, dedicated port (Default: 5000) from the main Django project.

Usage:
    py run_sandbox.py [PORT]
    py run_sandbox.py 5000
"""
import sys
import os

# Ensure current directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from myapp.sandbox_engine import run_standalone_server

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    run_standalone_server(port=port)
