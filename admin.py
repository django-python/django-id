# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin

# Register your models here.
from .models import Session, Oauth

class SessionAdmin(admin.ModelAdmin):
    list_display = ('session_key', 'user', 'type', 'date')
    list_filter = ('type',)

class OauthAdmin(admin.ModelAdmin):
    list_display = ('user', 'server', 'oauth_id')
    list_filter = ('server',)


admin.site.register(Session, SessionAdmin)
admin.site.register(Oauth, OauthAdmin)


