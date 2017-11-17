# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin

# Register your models here.
from .models import Session

class SessionAdmin(admin.ModelAdmin):
    list_display = ('session_key', 'user', 'type', 'date')
    list_filter = ('type',)

admin.site.register(Session, SessionAdmin)


