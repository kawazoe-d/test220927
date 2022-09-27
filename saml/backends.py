from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ObjectDoesNotExist
from .models import AuthUser

class EmailAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, **kwargs):
        try:
            user = AuthUser.objects.get(username=username)
        except ObjectDoesNotExist:
            return None
        return user