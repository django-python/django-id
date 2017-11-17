# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2017-11-15 21:28
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('id', '0002_session_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='session',
            name='type',
            field=models.IntegerField(choices=[(1, 'Sign up'), (2, 'Restore password')], default=None),
        ),
    ]