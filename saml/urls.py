from django.urls import path, re_path
from .views import index, acs, metadata, user

urlpatterns = [
    re_path(r'^$', index, name='index'),
    re_path(r'^acs/$', acs, name='acs'),
    re_path(r'^metadata/$', metadata, name='metadata'),
    path('user/', user, name='user'),
]