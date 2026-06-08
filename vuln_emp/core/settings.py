from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

# VULNERABILITY #9 — DEBUG=True exposes full stack traces and settings to anyone
SECRET_KEY = 'super-secret-key-123'  # VULNERABILITY #2 — Weak, hardcoded secret key

DEBUG = True  # VULNERABILITY #9 — Never True in production

ALLOWED_HOSTS = ['*']  # Allows any host — insecure in production

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'employees',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # VULNERABILITY #8 — CsrfViewMiddleware is intentionally REMOVED
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = []  # VULNERABILITY — No password strength requirements

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework config
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.AllowAny',  # VULNERABILITY — API open to all by default
    ),
}

# VULNERABILITY #2 — JWT with weak secret, no expiry rotation, long lifetime
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=999),  # Token never expires
    'SIGNING_KEY': 'weak-jwt-secret',              # Hardcoded weak key
    'ALGORITHM': 'HS256',
}

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/dashboard/'