SECRET_KEY = "django-insecure-abc123"
DEBUG = True
ROOT_URLCONF = "conf.urls"
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}
