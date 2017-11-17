# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.utils.translation import ugettext_lazy as _
from django.shortcuts import render, redirect
from django.contrib import messages, auth
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm, AuthenticationForm, UserCreationForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.models import User
from django.contrib.auth.views import login, logout_then_login
from django.conf import settings
from .forms import SignUpForm, OAuthSignUpForm
from .models import Session, Oauth

import requests
try:
    import urlparse
    from urllib import urlencode
except: # For Python 3
    import urllib.parse as urlparse
    from urllib.parse import urlencode


@login_required(login_url='/id/signin/')
def change_password(request):
    data = {'title':_('Password change'), }

    if request.method == 'POST':
        data['form'] = PasswordChangeForm(user=request.user, data=request.POST)

        if data['form'].is_valid():
            data['form'].save()
            update_session_auth_hash(request, data['form'].user)
            data['success'] = _('Password changed successfully.')
            return render(request, 'id/change_password.html', data)
        else:
            return render(request, 'id/change_password.html', data)
    else:
        data['form'] = PasswordChangeForm(request.user)
        return render(request, 'id/change_password.html', data)


def logout(request):
    auth.logout(request)
    return redirect('/')


def confirm_email(request, session_key):
    data = {'title':_('Activate account'), 'alert':{'message':_('Your email address was successfully verified')} }
    
    result = Session.objects.filter(session_key=session_key)
    result = result.last()

    if result is None:
        data = {'title':_('Activate account'), 'alert':{'message':_('Maybe your account has already been activated'), 'type':'danger'} }
        return render(request, 'id/confirm_email.html', data)

    if result.type != 1:
        data = {'title':_('Activate account'), 'alert':{'message':_('Maybe your account has already been activated'), 'type':'danger'} }
        return render(request, 'id/confirm_email.html', data)

    if result.user.is_active == True:
        data = {'title':_('Activate account'), 'alert':{'message':_('Maybe your account has already been activated'), 'type':'danger'} }
        return render(request, 'id/confirm_email.html', data)


    result.user.is_active = True
    result.user.save()
    result.delete()

    auth.login(request, result.user)
    return render(request, 'id/confirm_email.html', data)


def signin(request):
    data = {}

    if request.method == 'POST':
        data['form'] = AuthenticationForm(data=request.POST)
        if data['form'].is_valid():
            user = auth.authenticate(username=data['form'].cleaned_data.get('username'), password=data['form'].cleaned_data.get('password'))
            if user is not None and user.is_active:
                auth.login(request, user)
                return redirect(request.GET.get('next', '/'))
            else:
                data['form'].add_error('username', _('The username or password you entered is incorrect.'))

            return render(request, 'id/signin.html', data)
        else:
            if data['form'].cleaned_data.get('username') and data['form'].cleaned_data.get('password'):
                data['form'].add_error('username', _('The username or password you entered is incorrect.') )
            return render(request, 'id/signin.html', data)
    else:
        data['form'] = AuthenticationForm(request)
        return render(request, 'id/signin.html', data)


def signup(request):
    data = {'title':_('Sign up'), }

    if request.method == 'POST':
        data['form'] = SignUpForm(request.POST)
        if data['form'].is_valid():
            username = data['form'].save()

        return render(request, 'id/signup.html', data)
    else:
        data['form'] = SignUpForm()
        return render(request, 'id/signup.html', data)


def oauth_google(request):
    data = {'title':_('Sign up'), }

    if request.GET.get('code'):
        data = {
            'grant_type':'authorization_code',
            'code': request.GET.get('code'),
            'client_id': settings.ID_OAUTH_GOOGLE_CLIENT_ID,
            'client_secret': settings.ID_OAUTH_GOOGLE_SECRET_KEY,
            'redirect_uri': request.META.get('HTTP_X_FORWARDED_PROTO', request.scheme)+'://'+request.get_host()+request.path,
        }

        try:
            r = requests.post('https://www.googleapis.com/oauth2/v4/token', data=data, timeout=5.000)
        except requests.exceptions.Timeout:
            data = {'title':_('Error'), 'alert':{'message':_(u'Connection timeout %(site)s') % {'site':'googleapis.com'}, 'type':'danger'} }
            return render(request, 'id/alert.html', data)
        except requests.exceptions.TooManyRedirects:
            data = {'title':_('Error'), 'alert':{'message':_(u'Could not open the site, too many redirects'), 'type':'danger'} }
            return render(request, 'id/alert.html', data)
        except requests.exceptions.RequestException as err:
            data = {'title':_('Error'), 'alert':{'message':err, 'type':'danger'} }
            return render(request, 'id/alert.html', data)

        json = r.json()

        access_token = json.get('access_token')
        token_type   = json.get('token_type')
        expires_in   = json.get('expires_in')

        try:
            r = requests.get('https://www.googleapis.com/oauth2/v1/userinfo', params={'access_token':access_token}, timeout=5.000)
        except requests.exceptions.Timeout:
            data = {'title':_('Error'), 'alert':{'message':_(u'Connection timeout %(site)s') % {'site':'googleapis.com'}, 'type':'danger'} }
            return render(request, 'id/alert.html', data)
        except requests.exceptions.TooManyRedirects:
            data = {'title':_('Error'), 'alert':{'message':_(u'Could not open the site, too many redirects'), 'type':'danger'} }
            return render(request, 'id/alert.html', data)
        except requests.exceptions.RequestException as err:
            data = {'title':_('Error'), 'alert':{'message':err, 'type':'danger'} }
            return render(request, 'id/alert.html', data)


        json = r.json()

        if json.get('verified_email') != True:
            data = {'title':_('Error'), 'alert':{'message':_(u'You have not verified your email address'), 'type':'danger'} }
            return render(request, 'id/alert.html', data)

        request.session["oauth"] = {
            'server':1,
            'lastname':json.get('family_name'),
            'firstname':json.get('given_name'),
            'id':json.get('id'),
            'email':_email_alias(json.get('email')),
        }

        return redirect('/id/oauth/completion/')

    url = 'https://accounts.google.com/o/oauth2/v2/auth'
    params = {
        'client_id': settings.ID_OAUTH_GOOGLE_CLIENT_ID,
        'redirect_uri': request.META.get('HTTP_X_FORWARDED_PROTO', request.scheme)+'://'+request.get_host()+request.path,
        'response_type':'code',
        'scope':'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile',
    }

    url_parts = list(urlparse.urlparse(url))
    query = dict(urlparse.parse_qsl(url_parts[4]))
    query.update(params)
    url_parts[4] = urlencode(query)
    return redirect(urlparse.urlunparse(url_parts))


def oauth_completion(request):
    data = {}

    oauth = request.session["oauth"]
    if request.method == 'POST':
        data['form'] = OAuthSignUpForm(request.POST)
        if data['form'].is_valid():
            username = data['form'].cleaned_data.get('username')

            user = User(username=username, last_name=oauth.get('lastname'), first_name=oauth.get('firstname'), email=oauth.get('email'))
            user.save()

            #oauth = Oauth(oauth_id=oauth.get('id'), server=oauth.get('server'), user=user)
            #oauth.save()

            auth.login(request, user)
            return redirect('/') #FIXME next

        return render(request, 'id/oauth_completion.html', data)
    else:
        # Если пользователь уже зарегистрирован с этим email
        try:
            user = User.objects.get(email=oauth.get('email'))
        except User.DoesNotExist:
            pass
        else:
            auth.login(request, user)
            return redirect('/') #FIXME next

        # Выводим html страницу
        data['form'] = OAuthSignUpForm()
        return render(request, 'id/oauth_completion.html', data)


def _email_alias(email):
    email = email.lower().strip()

    user = email.rsplit('@', 1)[0]
    domain = email.rsplit('@', 1)[-1]
    if domain == 'ya.ru' or domain == 'yandex.by' or domain == 'yandex.com' or domain == 'yandex.kz' or domain == 'yandex.ua':
        return user+'@yandex.ru'

    return email










