# -*- coding: utf-8 -*-
"""
    test_two_factor
    ~~~~~~~~~~~~~~~~~

    two_factor tests
"""
import pytest

from flask import Flask
from flask_security.core import UserMixin
from flask_security.signals import two_factor_login_instructions_sent
from flask_security.utils import capture_two_factor_login_requests, string_types


pytestmark = pytest.mark.two_factor()


def test_two_factor_flag(app, client, get_message):
    recorded = []

    @two_factor_login_instructions_sent.connect_via(app)
    def on_two_factor_login_instructions_sent(app, user, login_token):
        assert isinstance(app, Flask)
        assert isinstance(user, UserMixin)
        assert isinstance(login_token, string_types)
        recorded.append(user)
