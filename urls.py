from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'id/change/password/$', views.change_password),
    url(r'id/logout/$', views.logout),
    url(r'id/signin/$', views.signin),
    url(r'id/signup/$', views.signup),
    url(r'id/confirm/email/(?P<session_key>[0-9a-z]{40})/$', views.confirm_email),

    url(r'id/oauth/google/$', views.oauth_google),
    url(r'id/oauth/yandex/$', views.oauth_yandex),
    url(r'id/oauth/mailru/$', views.oauth_mailru),

    url(r'id/oauth/completion/$', views.oauth_completion),
]


