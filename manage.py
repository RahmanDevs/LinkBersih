#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.dev')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)

# Run the command
if __name__ == '__main__':
    main()

# Menjalankan Dev Mode (default): uv run python -m uvicorn config.asgi:application --reload

# Menjalankan prod (secara spesifik): DJANGO_SETTINGS_MODULE=config.settings.prod uv run python -m uvicorn config.asgi:application