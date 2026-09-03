# config/settings/prod.py
import os
from .base import *

DEBUG = False

# Ambil allowed hosts & secret key dari Environment Variables
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')
SECRET_KEY = os.environ.get('DJANGO_SECRET')

# Keamanan HTTPS / Cookie
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True

# Database Production (misal: PostgreSQL) bisa dikonfigurasi via env var