# -*- coding: utf-8 -*-
"""
    flask_security.two_factor
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security two_factor module

    :copyright: (c) 2016 by Gal Stainfeld.
"""

import base64
import os
import pyqrcode
import onetimepass

from flask import current_app as app, session, redirect
from werkzeug.local import LocalProxy

from .utils import send_mail, config_value, get_message, url_for, do_flash, SmsSenderFactory

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

        sms_sender = SmsSenderFactory.createSender(config_value('TWO_FACTOR_SMS_SERVICE'))
        sms_sender.send_sms(from_number=from_number, to_number=user.phone_number, msg=msg)

    elif method == 'google_authenticator':
        # password are generated automatically in the google authenticator app. no need to send anything
        pass


def get_totp_uri(username, totp):
    """ Generate provisioning url for use with the qrcode scanner built into the app
    :param user:
    :return:
    """
    protocol = config_value('TWO_FACTOR_URI_PROTOCOL')
    service_name = config_value('TWO_FACTOR_URI_SERVICE_NAME')
    return 'otpauth://{0}/{1}:{2}?secret={3}&issuer={1}'.format(protocol, \
                                                            service_name, username, totp)

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


def two_factor_generate_qrcode():
    if 'username' not in session or 'next_totp' not in session:
        return redirect(url_for('login'))
    username = session['username']
    totp = session['next_totp']
    user = _datastore.find_user(username=session['username'])
    if user is None:
        return redirect(url_for('login'))
    url = pyqrcode.create(get_totp_uri(username, totp))
    from StringIO import StringIO
    stream = StringIO()
    url.svg(stream, scale=3)
    return stream.getvalue().encode('utf-8'), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}