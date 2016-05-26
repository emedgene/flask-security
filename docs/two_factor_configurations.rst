Two Factor Configurations
=========================

Two factor authentication provides a second layer of security to any type of
login, requiring extra information or a physical device to log in, in addition
to one's password. The added feature includes in scope the ability to add second
factor authentication using user's mail, using Google Authenticator or using an
sms message.

SQLAlchemy Application With Two Factor Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code sample illustrates how to get started as quickly as
possible using SQLAlchemy and two factor feature:

::

    from flask import Flask, render_template
    from flask.ext.sqlalchemy import SQLAlchemy
    from flask.ext.security import Security, SQLAlchemyUserDatastore, \
        UserMixin, RoleMixin, login_required
    from flask_mail import Mail

    # Convenient references
    from werkzueg.local import LocalProxy

    _security = LocalProxy(lambda: current_app.extensions['security'])

    _datastore = LocalProxy(lambda: _security.datastore)


    # Create app
    app = Flask(__name__)
    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = 'super-secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
    app.config['SECURITY_TWO_FACTOR'] = True
    app.config['SECURITY_TWO_FACTOR_ENABLED_METHODS': ['mail',
     'google_authenticator'] # lacking an sms provider we removed that option
    app.config['SECURITY_TWO_FACTOR_URI_SERVICE_NAME'] ='your_app_name'
    app.config['SECURITY_TWO_FACTOR_RESCUE_MAIL'] = 'your_mail@gmail.come'

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
        db.create_all()
        user_datastore.create_user(email='matt@nobien.net', password='password')
        db.session.commit()

    # Views
    @app.route('/')
    @login_required
    def home():
        return render_template('index.html')

    if __name__ == '__main__':
        app.run(host='0.0.0.0', debug=True)
