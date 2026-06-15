"""URL routing for the core app (all vulnerable endpoints)."""
from django.urls import path

from . import views

urlpatterns = [
    # (A) SCA: unsafe yaml.load on request body
    path("api/config", views.config, name="config"),
    # (B) CHAIN: SSRF source -> insecure deserialization sink
    path("api/proxy", views.proxy, name="proxy"),
    # (C) NORMAL: SQL injection
    path("api/user", views.user, name="user"),
]
