from __future__ import unicode_literals

from django.db import models


class AuthUserToken(models.Model):
    id = models.IntegerField(primary_key=True)
    username = models.CharField(max_length=255)
    token = models.CharField(max_length=255)
    expiretime = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'auth_user_token'