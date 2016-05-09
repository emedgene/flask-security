# -*- coding: utf-8 -*-
"""
    flask_security.views
    ~~~~~~~~~~~~~~~~~~~~

    Flask-Security views module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""
import pyqrcode
from flask import current_app, redirect, request, jsonify, \
    after_this_request, Blueprint, session
from flask_login import current_user
from werkzeug.datastructures import MultiDict
from werkzeug.local import LocalProxy

from .confirmable import send_confirmation_instructions, \
    confirm_user, confirm_email_token_status
from .decorators import login_required, anonymous_user_required
from .passwordless import send_login_instructions, \
    login_token_status
from .recoverable import reset_password_token_status, \
    send_reset_password_instructions, update_password
from .changeable import change_user_password
from .registerable import register_user
from .utils import config_value, do_flash, get_url, get_post_login_redirect, \
    get_post_register_redirect, get_message, login_user, logout_user, \
    url_for_security as url_for, slash_url_suffix, send_mail
from .twofactor import send_security_token, verify_totp, generate_totp, two_factor_generate_qrcode

# Convenient references
_security = LocalProxy(lambda: current_app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def _render_json(form, include_user=True, include_auth_token=False):
    has_errors = len(form.errors) > 0

    if has_errors:
        code = 400
        response = dict(errors=form.errors)
    else:
        code = 200
        response = dict()
        if include_user:
            response['user'] = dict(id=str(form.user.id))
        if include_auth_token:
            token = form.user.get_auth_token()
            response['user']['authentication_token'] = token

    return jsonify(dict(meta=dict(code=code), response=response))


def _commit(response=None):
    _datastore.commit()
    return response


def _ctx(endpoint):
    return _security._run_ctx_processor(endpoint)


@anonymous_user_required
def login():
    """View function for login view"""

    form_class = _security.login_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        login_user(form.user, remember=form.remember.data)
        after_this_request(_commit)

        if not request.json:
            return redirect(get_post_login_redirect(form.next.data))

    if request.json:
        return _render_json(form, include_auth_token=True)

    return _security.render_template(config_value('LOGIN_USER_TEMPLATE'),
                                     login_user_form=form,
                                     **_ctx('login'))


def logout():
    """View function which handles a logout request."""

    if current_user.is_authenticated:
        logout_user()

    return redirect(request.args.get('next', None) or
                    get_url(_security.post_logout_view))


@anonymous_user_required
def register():
    """View function which handles a registration request."""

    if _security.confirmable or request.json:
        form_class = _security.confirm_register_form
    else:
        form_class = _security.register_form

    if request.json:
        form_data = MultiDict(request.json)
    else:
        form_data = request.form

    form = form_class(form_data)

    if form.validate_on_submit():
        user = register_user(**form.to_dict())
        form.user = user

        if not _security.confirmable or _security.login_without_confirmation:
            after_this_request(_commit)
            login_user(user)

        if not request.json:
            if 'next' in form:
                redirect_url = get_post_register_redirect(form.next.data)
            else:
                redirect_url = get_post_register_redirect()

            return redirect(redirect_url)
        return _render_json(form, include_auth_token=True)

    if request.json:
        return _render_json(form)

    return _security.render_template(config_value('REGISTER_USER_TEMPLATE'),
                                     register_user_form=form,
                                     **_ctx('register'))


def send_login():
    """View function that sends login instructions for passwordless login"""

    form_class = _security.passwordless_login_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        send_login_instructions(form.user)
        if request.json is None:
            do_flash(*get_message('LOGIN_EMAIL_SENT', email=form.user.email))

    if request.json:
        return _render_json(form)

    return _security.render_template(config_value('SEND_LOGIN_TEMPLATE'),
                                     send_login_form=form,
                                     **_ctx('send_login'))


@anonymous_user_required
def token_login(token):
    """View function that handles passwordless login via a token"""

    expired, invalid, user = login_token_status(token)

    if invalid:
        do_flash(*get_message('INVALID_LOGIN_TOKEN'))
    if expired:
        send_login_instructions(user)
        do_flash(*get_message('LOGIN_EXPIRED', email=user.email,
                              within=_security.login_within))
    if invalid or expired:
        return redirect(url_for('login'))

    login_user(user)
    after_this_request(_commit)
    do_flash(*get_message('PASSWORDLESS_LOGIN_SUCCESSFUL'))

    return redirect(get_post_login_redirect())


def send_confirmation():
    """View function which sends confirmation instructions."""

    form_class = _security.send_confirmation_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        send_confirmation_instructions(form.user)
        if request.json is None:
            do_flash(*get_message('CONFIRMATION_REQUEST', email=form.user.email))

    if request.json:
        return _render_json(form)

    return _security.render_template(config_value('SEND_CONFIRMATION_TEMPLATE'),
                                     send_confirmation_form=form,
                                     **_ctx('send_confirmation'))


def confirm_email(token):
    """View function which handles a email confirmation request."""

    expired, invalid, user = confirm_email_token_status(token)

    if not user or invalid:
        invalid = True
        do_flash(*get_message('INVALID_CONFIRMATION_TOKEN'))
    if expired:
        send_confirmation_instructions(user)
        do_flash(*get_message('CONFIRMATION_EXPIRED', email=user.email,
                              within=_security.confirm_email_within))
    if invalid or expired:
        return redirect(get_url(_security.confirm_error_view) or
                        url_for('send_confirmation'))

    if user != current_user:
        logout_user()
        login_user(user)

    if confirm_user(user):
        after_this_request(_commit)
        msg = 'EMAIL_CONFIRMED'
    else:
        msg = 'ALREADY_CONFIRMED'

    do_flash(*get_message(msg))

    return redirect(get_url(_security.post_confirm_view) or
                    get_url(_security.post_login_view))


@anonymous_user_required
def forgot_password():
    """View function that handles a forgotten password request."""

    form_class = _security.forgot_password_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        send_reset_password_instructions(form.user)
        if request.json is None:
            do_flash(*get_message('PASSWORD_RESET_REQUEST', email=form.user.email))

    if request.json:
        return _render_json(form, include_user=False)

    return _security.render_template(config_value('FORGOT_PASSWORD_TEMPLATE'),
                                     forgot_password_form=form,
                                     **_ctx('forgot_password'))


@anonymous_user_required
def reset_password(token):
    """View function that handles a reset password request."""

    expired, invalid, user = reset_password_token_status(token)

    if invalid:
        do_flash(*get_message('INVALID_RESET_PASSWORD_TOKEN'))
    if expired:
        send_reset_password_instructions(user)
        do_flash(*get_message('PASSWORD_RESET_EXPIRED', email=user.email,
                              within=_security.reset_password_within))
    if invalid or expired:
        return redirect(url_for('forgot_password'))

    form = _security.reset_password_form()

    if form.validate_on_submit():
        after_this_request(_commit)
        update_password(user, form.password.data)
        do_flash(*get_message('PASSWORD_RESET'))
        login_user(user)
        return redirect(get_url(_security.post_reset_view) or
                        get_url(_security.post_login_view))

    return _security.render_template(config_value('RESET_PASSWORD_TEMPLATE'),
                                     reset_password_form=form,
                                     reset_password_token=token,
                                     **_ctx('reset_password'))


@login_required
def change_password():
    """View function which handles a change password request."""

    form_class = _security.change_password_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        after_this_request(_commit)
        change_user_password(current_user, form.new_password.data)
        if request.json is None:
            do_flash(*get_message('PASSWORD_CHANGE'))
            return redirect(get_url(_security.post_change_view) or
                            get_url(_security.post_login_view))

    if request.json:
        form.user = current_user
        return _render_json(form)

    return _security.render_template(config_value('CHANGE_PASSWORD_TEMPLATE'),
                                     change_password_form=form,
                                     **_ctx('change_password'))


@anonymous_user_required
def two_factor_login():
    """View function for two factor authentication login"""
    form_class = _security.login_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        session['username'] = form.user.username
        user = _datastore.find_user(username=session['username'])
        primary_method = user.two_factor_primary_method
        setup_form = _security.two_factor_setup_form()
        verify_code_form = _security.two_factor_verify_code_form()

        if primary_method is None:
            return _security.render_template(config_value('TWO_FACTOR_CHOOSE_METHOD_TEMPLATE'),
                                             two_factor_setup_form=setup_form,
                                             two_factor_verify_code_form=verify_code_form,
                                             setup_endpoint='two_factor_first_login_setup_function',
                                             qrcode_endpoint='two_factor_first_login_qrcode',
                                             token_validation_endpoint ='two_factor_first_login_token_validation',
                                             choices=config_value('TWO_FACTOR_ENABLED_METHODS'),
                                             **_ctx('two_factor_first_login_setup_function'))
        else:
            rescue_form = _security.two_factor_rescue_form()
            send_security_token(user=user, method=primary_method, totp=user.totp)
            return _security.render_template(config_value('TWO_FACTOR_VERIFY_CODE_TEMPLATE'),
                                             two_factor_verify_code_form=verify_code_form,
                                             two_factor_rescue_form=rescue_form,
                                             next_endpoint='two_factor_first_login_token_validation',
                                             rescue_endpoint='two_factor_rescue_function',
                                             rescue_mail=config_value('TWO_FACTOR_RESCUE_MAIL'),
                                             method=primary_method,
                                             problem=None,
                                             ** _ctx('two_factor_first_login_token_validation'))

    if request.json:
        form.user = current_user
        return _render_json(form)

    return _security.render_template(config_value('LOGIN_USER_TEMPLATE'),
                                     login_user_form=form,
                                     **_ctx('login'))


@anonymous_user_required
def two_factor_first_login_setup_function():
    """View function for validating the code entered during two factor authentication"""
    if 'username' in session:
        setup_endpoint, qrcode_endpoint, token_validation_endpoint = get_first_login_endpoints()
        return two_factor_setup_function(setup_endpoint, qrcode_endpoint, token_validation_endpoint)
    else:
        do_flash(*get_message('TWO_FACTOR_PERMISSION_DENIED'))
        login_user_form = _security.login_form()
        return _security.render_template(config_value('LOGIN_USER_TEMPLATE'),
                                         login_user_form=login_user_form,
                                         **_ctx('login'))


@anonymous_user_required
def two_factor_first_login_token_validation():
    """View function for validating the code entered during two factor authentication"""
    if 'username' in session:
        setup_endpoint, qrcode_endpoint, token_validation_endpoint = get_first_login_endpoints()
        return two_factor_token_validation(setup_endpoint, qrcode_endpoint, token_validation_endpoint)
    else:
        do_flash(*get_message('TWO_FACTOR_PASSWORD_CONFIRMATION_NEEDED'))
        login_user_form = _security.login_form()
        return _security.render_template(config_value('LOGIN_USER_TEMPLATE'),
                                         login_user_form=login_user_form,
                                         **_ctx('login'))

@anonymous_user_required
def two_factor_first_login_qrcode():
    if 'next_primary_method' in session and session['next_primary_method'] == 'google_authenticator' \
            and 'google_authenticator' in config_value('TWO_FACTOR_ENABLED_METHODS'):
        return two_factor_generate_qrcode()
    else:
        do_flash(*get_message('TWO_FACTOR_PERMISSION_DENIED'))
        login_user_form = _security.login_form()
        return _security.render_template(config_value('LOGIN_USER_TEMPLATE'),
                                         login_user_form=login_user_form,
                                         **_ctx('login'))


@anonymous_user_required
def two_factor_rescue_function():
    form_class = _security.two_factor_rescue_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit() and 'username' in session:
        user = _datastore.find_user(username=session['username'])
        problem = form.data
        # if the problem is that user can't access his smartphone device, we send him code through mail
        if problem == 'Can not access mobile device?':
            send_security_token(user=user, method='mail', totp=user.totp)
        # send app provider a mail message regarding trouble
        elif problem == 'Can not access mail account?':
            send_mail(config_value('EMAIL_SUBJECT_TWO_FACTOR_RESCUE'), config_value('TWO_FACTOR_RESCUE_MAIL'),
                      'two_factor_instructions', user=user)

    verify_code_form = _security.two_factor_verify_code_form()
    return _security.render_template(config_value('TWO_FACTOR_VERIFY_CODE_TEMPLATE'),
                                     two_factor_verify_code_form=verify_code_form,
                                     two_factor_rescue_form=form,
                                     next_endpoint='two_factor_first_login_token_validation',
                                     rescue_endpoint='two_factor_rescue_function',
                                     rescue_mail=config_value('TWO_FACTOR_RESCUE_MAIL'),
                                     method='mail'
                                     **_ctx('two_factor_first_login_token_validation'))


@login_required
def two_factor_change_method_password_confirmation():
    """View function which handles a change second factor method request."""
    form_class = _security.two_factor_change_method_verify_password_form

    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if form.validate_on_submit():
        session['username'] = current_user.username
        session['password_confirmed'] = True
        setup_form = _security.two_factor_setup_form()
        verify_code_form = _security.two_factor_verify_code_form()
        return _security.render_template(config_value('TWO_FACTOR_CHOOSE_METHOD_TEMPLATE'),
                                         two_factor_setup_form=setup_form,
                                         two_factor_verify_code_form=verify_code_form,
                                         setup_endpoint='two_factor_change_method_setup_function',
                                         qrcode_endpoint='two_factor_change_method_qrcode',
                                         token_validation_endpoint = 'two_factor_change_method_token_validation',
                                         choices=config_value('TWO_FACTOR_ENABLED_METHODS'),
                                         **_ctx('two_factor_change_method_setup_function'))
    if request.json:
        form.user = current_user
        return _render_json(form)

    return _security.render_template(config_value('TWO_FACTOR_CHANGE_METHOD_PASSWORD_CONFIRMATION_TEMPLATE'),
                                     two_factor_change_method_verify_password_form=form,
                                     **_ctx('two_factor_change_factor_password_confirmation'))


@login_required
def two_factor_change_method_setup_function():
    """View function for changing the two factor authentication method"""
    if 'password_confirmed' in session and session['password_confirmed'] == True \
                                       and 'username' in session \
                                       and session['username'] == current_user.username:
        setup_endpoint, qrcode_endpoint, token_validation_endpoint = get_change_method_endpoints()
        return two_factor_setup_function(setup_endpoint, qrcode_endpoint, token_validation_endpoint)
    else:
        do_flash(*get_message('TWO_FACTOR_PASSWORD_CONFIRMATION_NEEDED'))
        verify_password_form = _security.two_factor_change_method_verify_password_form()
        return _security.render_template(config_value('TWO_FACTOR_CHANGE_METHOD_PASSWORD_CONFIRMATION_TEMPLATE'),
                                     two_factor_change_method_verify_password_form=verify_password_form,
                                     **_ctx('two_factor_change_factor_password_confirmation'))

@login_required
def two_factor_change_method_token_validation():
    if 'password_confirmed' in session:
        setup_endpoint, qrcode_endpoint, token_validation_endpoint = get_change_method_endpoints()
        return two_factor_token_validation(setup_endpoint, qrcode_endpoint, token_validation_endpoint)
    else:
        do_flash(*get_message('TWO_FACTOR_PASSWORD_CONFIRMATION_NEEDED'))
        verify_password_form = _security.two_factor_change_method_verify_password_form()
        return _security.render_template(config_value('TWO_FACTOR_CHANGE_METHOD_PASSWORD_CONFIRMATION_TEMPLATE'),
                                         two_factor_change_method_verify_password_form=verify_password_form,
                                         **_ctx('two_factor_change_factor_password_confirmation'))


@login_required
def two_factor_change_method_qrcode():
    if 'next_primary_method' in session and session['next_primary_method'] == 'google_authenticator':
        return two_factor_generate_qrcode()
    else:
        do_flash(*get_message('TWO_FACTOR_PERMISSION_DENIED'))
        redirect(get_post_login_redirect())


def get_first_login_endpoints():
    setup_endpoint = 'two_factor_first_login_setup_function'
    qrcode_endpoint = 'two_factor_first_login_qrcode'
    token_validation_endpoint = 'two_factor_first_login_token_validation'
    return setup_endpoint, qrcode_endpoint, token_validation_endpoint


def get_change_method_endpoints():
    setup_endpoint = 'two_factor_change_method_setup_function'
    qrcode_endpoint = 'two_factor_change_method_qrcode'
    token_validation_endpoint = 'two_factor_change_method_token_validation'
    return setup_endpoint, qrcode_endpoint, token_validation_endpoint


def two_factor_setup_function(setup_endpoint, qrcode_endpoint, token_validation_endpoint):
    form_class = _security.two_factor_setup_form
    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    verify_code_form = _security.two_factor_verify_code_form()
    user = _datastore.find_user(username=session['username'])
    # if form.validate_on_submit():
    if form.data.has_key('setup') and (form.data['setup'] == 'mail' or \
                                                   form.data['setup'] == 'google_authenticator' or \
                                                   form.data['setup'] == 'sms'):
        # we add the choosen method to the template and perform its action.
        # next_totp and next_primarty_method are added to session to flag the user's choice
        session['next_totp'] = generate_totp()
        method = form['setup'].data
        if method in config_value('TWO_FACTOR_ENABLED_METHODS'):
            session['next_primary_method'] = method
        else:
            do_flash(*get_message('TWO_FACTOR_BAD_CONFIGURATIONS'))
            return redirect(url_for('login'))
        send_security_token(user=user, method=session['next_primary_method'], totp=session['next_totp'])
        return _security.render_template(config_value('TWO_FACTOR_CHOOSE_METHOD_TEMPLATE'),
                                         two_factor_setup_form=form,
                                         two_factor_verify_code_form=verify_code_form,
                                         setup_endpoint=setup_endpoint,
                                         qrcode_endpoint=qrcode_endpoint,
                                         token_validation_endpoint=token_validation_endpoint,
                                         choices=config_value('TWO_FACTOR_ENABLED_METHODS'),
                                         chosen_method=session['next_primary_method'],
                                         **_ctx(token_validation_endpoint))
    if request.json:
        form.user = current_user
        return _render_json(form)
    # same as if form was validated expect it does not contain the user's choice and its effect
    return _security.render_template(config_value('TWO_FACTOR_CHOOSE_METHOD_TEMPLATE'),
                                     two_factor_setup_form=form,
                                     two_factor_verify_code_form=verify_code_form,
                                     setup_endpoint=setup_endpoint,
                                     qrcode_endpoint=qrcode_endpoint,
                                     token_validation_endpoint=token_validation_endpoint,
                                     choices=config_value('TWO_FACTOR_ENABLED_METHODS'),
                                     **_ctx(setup_endpoint))


def two_factor_token_validation(setup_endpoint, qrcode_endpoint, token_validation_endpoint):
    form_class = _security.two_factor_verify_code_form
    if request.json:
        form = form_class(MultiDict(request.json))
    else:
        form = form_class()

    if 'username' not in session:
        # ERROR
        pass
    else:
        user = _datastore.find_user(username=session['username'])

    # if form.validate_on_submit():
    if not 'code' in form or 'next_totp' not in session:
        # ERROR
        pass
    else:
        code_entered = form['code'].data
    # codes sent by sms will be valid for another window cycle (30 seconds from each side of current time)
    if 'next_primary_method' in session and session['next_primary_method'] == 'google_authenticator':
        window = 0
    else:
        window = 1
    # Valid token was entered
    if verify_totp(token=code_entered, user_totp=session['next_totp'], window=window):
        user.totp = session['next_totp']
        user.two_factor_primary_method = session['next_primary_method']
        _datastore.put(user)
        del session['next_primary_method']
        del session['next_totp']
        del session['username']

        if token_validation_endpoint == 'two_factor_change_method_token_validation':
            do_flash(*get_message('TWO_FACTOR_CHANGE_METHOD_SUCCESSFUL'))
        else:
            login_user(user)
            do_flash(*get_message('TWO_FACTOR_LOGIN_SUCCESSFUL'))
        after_this_request(_commit)
        return redirect(get_post_login_redirect())
    # Invalid token was entered
    else:
        if token_validation_endpoint == 'two_factor_change_method_token_validation':
            do_flash(*get_message('TWO_FACTOR_CHANGED_METHOD_FAILED'))
        else:
            do_flash(*get_message('TWO_FACTOR_INVALID_TOKEN'))
        setup_form = _security.two_factor_setup_form()
        return _security.render_template(config_value('TWO_FACTOR_CHOOSE_METHOD_TEMPLATE'),
                                             two_factor_verify_code_form = form,
                                             two_factor_setup_form=setup_form,
                                             setup_endpoint=setup_endpoint,
                                             token_validaion_endpoint=token_validation_endpoint,
                                             qrcode_endpoint=qrcode_endpoint,
                                             choices=config_value('TWO_FACTOR_ENABLED_METHODS'),
                                             **_ctx(setup_endpoint))


def create_blueprint(state, import_name):
    """Creates the security extension blueprint"""

    bp = Blueprint(state.blueprint_name, import_name,
                   url_prefix=state.url_prefix,
                   subdomain=state.subdomain,
                   template_folder='templates')

    bp.route(state.logout_url, endpoint='logout')(logout)

    if state.passwordless:
        bp.route(state.login_url,
                 methods=['GET', 'POST'],
                 endpoint='login')(send_login)
        bp.route(state.login_url + slash_url_suffix(state.login_url, '<token>'),
                 endpoint='token_login')(token_login)

    elif state.two_factor:
        bp.route(state.login_url,
                 methods=['GET', 'POST'],
                 endpoint='login')(two_factor_login)
        bp.route(state.login_url + slash_url_suffix(state.login_url, 'two_factor_first_login_setup_function'),
                 methods=['GET', 'POST'],
                 endpoint='two_factor_first_login_setup_function')(two_factor_first_login_setup_function)
        bp.route(state.login_url + slash_url_suffix(state.login_url, 'two_factor_first_login_token_validation'),
                 methods=['GET', 'POST'],
                 endpoint='two_factor_first_login_token_validation')(two_factor_first_login_token_validation)
        bp.route(state.login_url + slash_url_suffix(state.login_url, 'two_factor_first_login_qrcode'),
                 endpoint='two_factor_first_login_qrcode')(two_factor_first_login_qrcode)
        bp.route(state.login_url + slash_url_suffix(state.login_url, 'two_factor_rescue_function'),
                endpoint='two_factor_rescue_function')(two_factor_rescue_function)


    else:
        bp.route(state.login_url,
                 methods=['GET', 'POST'],
                 endpoint='login')(login)

    if state.registerable:
        bp.route(state.register_url,
                 methods=['GET', 'POST'],
                 endpoint='register')(register)

    if state.recoverable:
        bp.route(state.reset_url,
                 methods=['GET', 'POST'],
                 endpoint='forgot_password')(forgot_password)
        bp.route(state.reset_url + slash_url_suffix(state.reset_url, '<token>'),
                 methods=['GET', 'POST'],
                 endpoint='reset_password')(reset_password)

    if state.changeable:
        bp.route(state.change_url,
                 methods=['GET', 'POST'],
                 endpoint='change_password')(change_password)
        bp.route(
            state.change_url + slash_url_suffix(state.change_url, 'two_factor_change_method_password_confirmation'),
            methods=['GET', 'POST'],
            endpoint='two_factor_change_method_password_confirmation')(two_factor_change_method_password_confirmation)
        bp.route(state.change_url + slash_url_suffix(state.change_url, 'two_factor_change_method_setup_function'),
                 methods=['GET', 'POST'],
                 endpoint='two_factor_change_method_setup_function')(two_factor_change_method_setup_function)
        bp.route(state.change_url + slash_url_suffix(state.change_url, 'two_factor_change_method_token_validation'),
                 methods=['GET', 'POST'],
                 endpoint='two_factor_change_method_token_validation')(two_factor_change_method_token_validation)
        bp.route(state.change_url + slash_url_suffix(state.login_url, 'two_factor_change_method_qrcode'),
                 endpoint='two_factor_change_method_qrcode')(two_factor_change_method_qrcode)

    if state.confirmable:
        bp.route(state.confirm_url,
                 methods=['GET', 'POST'],
                 endpoint='send_confirmation')(send_confirmation)
        bp.route(state.confirm_url + slash_url_suffix(state.confirm_url, '<token>'),
                 methods=['GET', 'POST'],
                 endpoint='confirm_email')(confirm_email)

    return bp
