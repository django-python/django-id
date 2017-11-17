# -*- coding: utf-8 -*-
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _
from validate_email import validate_email
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.conf import settings
from .models import Session
import random, hashlib, re

class OAuthSignUpForm(forms.Form):
    username = forms.CharField(max_length=254, label=_('Username'))

    def clean_username(self):
        username = self.cleaned_data['username']
        username = username.lower()

        match = re.search(r'^[a-z]+[a-z0-9]+[_-]*[a-z0-9]+$', username)
        if not match:
            raise forms.ValidationError(_("Enter a valid username. This value may contain only English letters, numbers, and _ - characters. Username should not begin with a number."))

        try:
            User.objects.get(username=username)
        except User.DoesNotExist:
            pass
        else:
            raise forms.ValidationError(_("A user with that username already exists."))


        return username

    #last_name  = forms.CharField(max_length=30, label=_('Last name'), required=True)
    #first_name = forms.CharField(max_length=30, label=_('First name'), required=True)
    #email      = forms.EmailField(max_length=254, label=_('Email'), required=False)


class SignUpForm(UserCreationForm):
    last_name  = forms.CharField(max_length=30, label=_('Last name'), required=True)
    first_name = forms.CharField(max_length=30, label=_('First name'), required=True)
    email      = forms.EmailField(max_length=254, label=_('Email'), required=True)

    def clean_username(self):
        username = self.cleaned_data['username']
        username = username.lower()

        match = re.search(r'^[a-z]+[a-z0-9]+[_-]*[a-z0-9]+$', username)
        if match:
            return username
        else:
            raise forms.ValidationError(_("Enter a valid username. This value may contain only English letters, numbers, and _ - characters. Username should not begin with a number."))

        return username


    def clean_email(self):
        email = self.cleaned_data['email']
        email = email.lower()

        if not validate_email(email,check_mx=True):
            raise forms.ValidationError(_("Enter a valid email address."))

        try:
            User.objects.get(email=email)
        except User.DoesNotExist:
            return email
        raise forms.ValidationError(_("User with this email is already exists."))


    def save(self, commit=True):
        user = super(SignUpForm, self).save(commit=False)
        email = self.cleaned_data['email']

        if commit:
            user.is_active = False
            user.save() # Save user

            # Generate session sha1
            session_key = ''
            for x in range(40):
                session_key = session_key + random.choice(list('123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM'))

            m = hashlib.sha1()
            m.update(session_key)
            session_key = m.hexdigest()

            # Save session db
            session = Session(session_key=session_key, user=user, type=1)
            session.save()
            session_key = session.session_key

            # Send email
            subject = render_to_string('id/email/signup.subject.txt', {}).strip()
            body    = render_to_string('id/email/signup.body.html', {'session_key':session_key})

            msg = EmailMessage(subject,body,settings.DEFAULT_FROM_EMAIL,[email])
            msg.content_subtype = "html"
            msg.send()

        return user


    class Meta:
        model = User
        fields = ('username', 'last_name', 'first_name', 'email', 'password1', 'password2', )
