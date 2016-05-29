Two Factor Configurations
=========================
-  `Basic Two Factor Application <#Basic-two-factor-application>`_

Two factor authentication provides a second layer of security to any type of
login, requiring extra information or a secondary device to log in, in addition
to ones login credentials. The added feature includes the ability to add a
secondary authentication method using either via email, sms message, or Google
Authenticator.

Basic Two Factor Application
============================

The following code sample illustrates how to get started as quickly as
possible using SQLAlchemy and two factor feature:

::

    from flask import Flask, current_app, render_template

    from flask.ext.sqlalchemy import SQLAlchemy
    from flask.ext.security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required


    # At top of file
    from flask_mail import Mail


    # Convenient references
    from werkzeug.datastructures import MultiDict
    from werkzeug.local import LocalProxy


    _security = LocalProxy(lambda: current_app.extensions['security'])

    _datastore = LocalProxy(lambda: _security.datastore)

    # Create ap
    app = Flask(__name__)
    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = 'super-secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

    app.config['SECURITY_TWO_FACTOR_ENABLED_METHODS'] = ['mail',
     'google_authenticator']  # 'sms' also valid but requires an sms provider
    app.config["SECURITY_TWO_FACTOR"] = True
    app.config['SECURITY_TWO_FACTOR_RESCUE_MAIL'] = 'put_your_mail@gmail.com'
    app.config['SECURITY_TWO_FACTOR_URI_SERVICE_NAME'] = 'put_your_app_name'

    # Example of handling the 'sms' configuration with twilio service
    # app.config['SECURITY_TWO_FACTOR_SMS_SERVICE'] = 'Twilio'
    # app.config['SECURITY_TWO_FACTOR_SMS_SERVICE_CONFIG'] = {
    #     'ACCOUNT_SID': 'ACd1ec6dab1ac13f929d1e58c6a07bf8d2',
    #     'AUTH_TOKEN': '2d206913091314c202a07ab08b7e159b',
    #     'PHONE_NUMBER': '+97223724421',
    # }

    # Create database connection object
    db = SQLAlchemy(app)

    # Define models
    roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

    class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    username = db.Column(db.String(140), unique=True)
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    phone_number = db.Column(db.String(15))
    two_factor_primary_method = db.Column(db.String(140))
    totp_secret = db.Column(db.String(16))

    # Setup Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)

    mail = Mail(app)

    # Create a user to test with


    @app.before_first_request
    def create_user():
    # totp = u'RCTE75AP2GWLZIFR  # example of a valid totp_secret
    db.create_all()
    user_datastore.create_user(email='gal@lp.com', password='123qwe', username='gal'
                               ,totp_secret=None, two_factor_primary_method=None)

    db.session.commit()


    if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
