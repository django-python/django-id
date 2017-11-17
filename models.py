# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import User

class Session(models.Model):
    TYPE = (
        (1, 'Sign up'),
        (2, 'Restore password'),
    )

    session_key = models.CharField(max_length=40)
    date        = models.DateTimeField(auto_now=True)
    user        = models.ForeignKey(User, models.SET_NULL, blank=True, null=True)
    type        = models.IntegerField(choices=TYPE, default=None)


class OAuth(models.Model):
    SERVER = (
        (1, 'Google'),
        (2, 'Yandex'),
        (3, 'Mail.ru'),
    )

    user     = models.ForeignKey(User, models.SET_NULL, blank=True, null=True)
    oauth_id = models.CharField(max_length=200)
    server   = models.IntegerField(choices=SERVER)
