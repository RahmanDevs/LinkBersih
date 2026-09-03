# config/settings/dev.py
from .base import *

DEBUG = True

ALLOWED_HOSTS = ['127.0.0.1', 'localhost']

# Database SQLite untuk lokal
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# (Opsional) Tambahkan django-debug-toolbar di mode dev jika digunakan