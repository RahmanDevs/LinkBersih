from django.urls import path
from .views import logger_view

# URL Pattern
urlpatterns = [
    path("", logger_view, name="logger"),
]