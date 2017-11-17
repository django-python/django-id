# -*- coding: utf-8 -*-
# Generated by Django 1.11.5 on 2017-11-17 11:37
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('id', '0003_auto_20171115_2128'),
    ]

    operations = [
        migrations.CreateModel(
            name='OAuth',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('oauth_id', models.CharField(max_length=200)),
                ('server', models.IntegerField(choices=[(1, 'Google'), (2, 'Yandex'), (3, 'Mail.ru')])),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]