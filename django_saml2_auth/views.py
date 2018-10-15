#!/usr/bin/env python
# -*- coding:utf-8 -*-


from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from django import get_version
from pkg_resources import parse_version
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, get_user_model, get_backends
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.template import TemplateDoesNotExist
from django.http import HttpResponseRedirect
from django.utils.http import is_safe_url

from rest_auth.utils import jwt_encode
from leonardo.sso_auth.models import SSOConfiguration


try:
    import urllib2 as _urllib
except:
    import urllib.request as _urllib
    import urllib.error
    import urllib.parse

if parse_version(get_version()) >= parse_version('1.7'):
    from django.utils.module_loading import import_string
else:
    from django.utils.module_loading import import_by_path as import_string


def get_current_domain(r):
    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']
    return '{scheme}://{host}'.format(
        scheme='https' if r.is_secure() else 'http',
        host=r.get_host(),
    )


def get_reverse(objs):
    '''In order to support different django version, I have to do this '''
    if parse_version(get_version()) >= parse_version('2.0'):
        from django.urls import reverse
    else:
        from django.core.urlresolvers import reverse
    if objs.__class__.__name__ not in ['list', 'tuple']:
        objs = [objs]

    for obj in objs:
        try:
            return reverse(obj)
        except:
            pass
    raise Exception('We got a URL reverse issue: %s. This is a known issue but please still submit a ticket at https://github.com/fangli/django-saml2-auth/issues/new' % str(objs))


def _get_saml_client(domain, sso_configuration):
    acs_url = domain + get_reverse([acs, 'acs', 'django_saml2_auth:acs'])

    saml_settings = {
        'metadata': {
            'remote': [
                {
                    "url": sso_configuration.metadata_auto_conf_url,
                },
            ],
        },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST)
                    ],
                },
                'allow_unsolicited': True,
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }

    saml_settings['entityid'] = sso_configuration.entity_id

    spConfig = Saml2Config()
    spConfig.load(saml_settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client


@login_required
def welcome(r):
    try:
        return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
    except TemplateDoesNotExist:
        return HttpResponseRedirect(settings.SAML2_AUTH.get('DEFAULT_NEXT_URL', settings.BASE_URL))


def denied(r):
    return render(r, 'django_saml2_auth/denied.html')


def _create_new_user(username, email, firstname, lastname, sso_configuration):
    User = get_user_model()
    user = User.objects.create_user(username, email)
    user.first_name = firstname
    user.last_name = lastname
    user.is_active = sso_configuration.new_user_active
    user.save()
    return user


@csrf_exempt
def acs(r):
    saml_client = _get_saml_client(get_current_domain(r), r.session.get('sso_configuration'))
    resp = r.POST.get('SAMLResponse', None)
    next_url = r.session.get('login_next_url', settings.SAML2_AUTH.get('DEFAULT_NEXT_URL', settings.BASE_URL))

    if not resp:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    authn_response = saml_client.parse_authn_request_response(
        resp, entity.BINDING_HTTP_POST)
    if authn_response is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    user_identity = authn_response.get_identity()
    if user_identity is None:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    user_email = user_identity[r.session.get('sso_configuration').attr_user_email][0]
    user_name = user_identity[r.session.get('sso_configuration').attr_user_username][0]
    user_first_name = user_identity[r.session.get('sso_configuration').attr_user_firstname][0]
    user_last_name = user_identity[r.session.get('sso_configuration').attr_user_lastname][0]

    target_user = None
    is_new_user = False

    try:
        User = get_user_model()
        target_user = User.objects.get(email=user_email)
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('BEFORE_LOGIN', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['BEFORE_LOGIN'])(user_identity)
    except User.DoesNotExist:
        if r.session.get('sso_configuration').auto_create_user:
            target_user = _create_new_user(user_name, user_email, user_first_name, user_last_name)
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['CREATE_USER'])(user_identity)
        is_new_user = True

    r.session.flush()

    if target_user.is_active:
        target_user.backend = settings.AUTHENTICATION_BACKENDS[0]
        login(r, target_user)
    else:
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    if is_new_user:
        try:
            return render(r, 'django_saml2_auth/welcome.html', {'user': r.user})
        except TemplateDoesNotExist:
            return HttpResponseRedirect(next_url)
    else:
        jwt_token = jwt_encode(target_user)
        query = '?uid={}&token={}'.format(target_user.id, jwt_token)
        return redirect(settings.BASE_URL + next_url + query)


def signin(r):
    try:
        import urlparse as _urlparse
        from urllib import unquote
    except:
        import urllib.parse as _urlparse
        from urllib.parse import unquote
    next_url = r.GET.get('next', settings.SAML2_AUTH.get('DEFAULT_NEXT_URL', settings.BASE_URL))

    try:
        if 'next=' in unquote(next_url):
            next_url = _urlparse.parse_qs(_urlparse.urlparse(unquote(next_url)).query)['next'][0]
    except:
        next_url = r.GET.get('next', settings.SAML2_AUTH.get('DEFAULT_NEXT_URL', settings.BASE_URL))

    # Only permit signin requests where the next_url is a safe URL
    if not is_safe_url(next_url, None):
        return HttpResponseRedirect(get_reverse([denied, 'denied', 'django_saml2_auth:denied']))

    r.session['login_next_url'] = next_url

    sso_configuration_id = r.session.get('sso_config', False)

    sso_configuration = SSOConfiguration.objects.get(id=sso_configuration_id)
    r.session['sso_configuration'] = sso_configuration

    saml_client = _get_saml_client(get_current_domain(r), r.session.get('sso_configuration'))
    _, info = saml_client.prepare_for_authenticate()

    redirect_url = None

    for key, value in info['headers']:
        if key == 'Location':
            redirect_url = value
            break

    return HttpResponseRedirect(redirect_url)


def signout(r):
    logout(r)
    return render(r, 'django_saml2_auth/signout.html')
