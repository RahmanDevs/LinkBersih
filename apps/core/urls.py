from django.urls import path
from .views import home_view

# URL Pattern from homepage
urlpatterns = [
    path("", home_view, name="home"),
]