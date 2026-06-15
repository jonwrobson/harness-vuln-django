"""Root URL configuration for the vulndjango project."""
from django.urls import include, path

urlpatterns = [
    path("", include("core.urls")),
]
