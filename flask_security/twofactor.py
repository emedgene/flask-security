# -*- coding: utf-8 -*-
"""
    flask_security.two_factor
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security two_factor module

    :copyright: (c) 2016 by Gal Stainfeld, at Emedgene
"""

import base64
import os
import pyqrcode
import onetimepass

from flask import current_app as app, session, redirect
from werkzeug.exceptions import NotFound
from werkzeug.local import LocalProxy

from .utils import send_mail, config_value, get_message, url_for_security, do_flash, \
    SmsSenderFactory, get_post_login_redirect, login_user


# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def send_security_token(user, method, totp):
    """Sends the security token via email for the specified user.

    :param user: The user to send the code to
    :param method: The method in which the code will be sent ('mail' or 'sms') at the moment
    param token: The shared secret used for generating codes
    """
    token_to_be_sent = get_totp_password(totp)
    if method == 'mail':
        send_mail(config_value('EMAIL_SUBJECT_TWO_FACTOR'), user.email,
                  'two_factor_instructions', user=user, token=token_to_be_sent)
    elif method == 'sms':
        msg = "Use this code to log in: %s" % token_to_be_sent
        from_number = config_value('TWO_FACTOR_SMS_SERVICE_CONFIG')['PHONE_NUMBER']
        if 'phone_number' in session:
            to_number = session['phone_number']
            sms_sender = SmsSenderFactory.createSender(config_value('TWO_FACTOR_SMS_SERVICE'))
            sms_sender.send_sms(from_number=from_number, to_number=to_number, msg=msg)

    elif method == 'google_authenticator':
        # password are generated automatically in the google authenticator app. no need to send anything
        pass


def get_totp_uri(username, totp):
    """ Generate provisioning url for use with the qrcode scanner built into the app
    :param user:
    :return:
    """
    service_name = config_value('TWO_FACTOR_URI_SERVICE_NAME')
    return 'otpauth://totp/{0}:{1}?secret={2}&issuer={0}'.format(service_name, username, totp)

def verify_totp(token, user_totp, window=0):
    """ Verifies token for specific user_totp
    :param token - token to be check against user's secret
    :param user_totp - a uniqe shared secret of the user
    :param window - optional, compensate for clock skew, number of intervals to check on
        each side of the current time. (default is 0 - only check the current clock time)
    :return:
    """
    return onetimepass.valid_totp(token, user_totp, window=window)


def get_totp_password(token):
    """Get time-based one-time password on the basis of given secret and time"""
    return onetimepass.get_totp(token)


def generate_totp():
    return base64.b32encode(os.urandom(10)).decode('utf-8')


def generate_qrcode():
    if 'primary_method' in session and session['primary_method'] == 'google_authenticator' \
            and 'google_authenticator' in config_value('TWO_FACTOR_ENABLED_METHODS') \
            and 'username' in session and 'totp' in session:
        username = session['username']
        totp = session['totp']
        user = _datastore.find_user(username=session['username'])
        if user is None:
            return redirect(url_for_security('login'))
        url = pyqrcode.create(get_totp_uri(username, totp))
        from StringIO import StringIO
        stream = StringIO()
        url.svg(stream, scale=3)
        return stream.getvalue().encode('utf-8'), 200, {
            'Content-Type': 'image/svg+xml',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}
    else:
        do_flash(*get_message('TWO_FACTOR_PERMISSION_DENIED'))
        return redirect(url_for_security('login'))

def get_process_status():
    if 'username' not in session:
        do_flash(*get_message('TWO_FACTOR_PERMISSION_DENIED'))
        current_process = False
    else:
        if 'password_confirmed' in session and session['password_confirmed'] == True:
            current_process = 'change_method'
        else:
            current_process = 'first_login'
    return current_process

def complete_two_factor_process(user):
    user.totp = session['totp']
    user.two_factor_primary_method = session['primary_method']
    if 'phone_number' in session:
        user.phone_number = session['phone_number']
        del session['phone_number']

    _datastore.put(user)

    del session['primary_method']
    del session['totp']
    del session['username']

    # if we are changing two factor method
    if 'password_confirmed' in session:
        do_flash(*get_message('TWO_FACTOR_CHANGE_METHOD_SUCCESSFUL'))
        del session['password_confirmed']
    # if we are logging in for the first time
    else:
        do_flash(*get_message('TWO_FACTOR_LOGIN_SUCCESSFUL'))
        login_user(user)

    return